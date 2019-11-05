<#
.Synopsis
	Hämtar vilka som kan boka ett rum
.Description
	Listar vilka personser som kan skapa bokningar i angivet rum. Om angivet, kontrolleras om det finns personer som inte har blivit synkroniserade från Azure, samt ifall de ska bli synkroniserade. Det går även att exportera de synkroniserade personerna till en Excel-fil som då kommer sparas på H:.
.Parameter RumsNamn
	Namn på rummet som efterfrågas
.Parameter Sync
	Anger att gruppmedlemarna ska synkroniseras till Exchange
.Parameter Osynkade
	Skriv ut vilka som inte har blivit synkroniserade
.Parameter Export
	Ange om användarnas mailadresser ska exporteras till en fil
.Example
	Get-SD_RumBokningsbehörighet -RumsNamn "RumA"
	Ordinarier körning, hämtar vilka som är synkroniserade, samt hur många som inte synkats
.Example
	Get-SD_RumBokningsbehörighet -RumsNamn "RumA" -Synkade
	Lista enbart de personer som har blivit synkroniserade
.Example
	Get-SD_RumBokningsbehörighet -RumsNamn "RumA" -Osynkade
	Lista enbart de personer som inte har blivit synkroniserade
.Example
	Get-SD_RumBokningsbehörighet -RumsNamn "RumA" -Exportera
	Exportera de personer som har behörighet till en Excel-fil
#>

function Get-SD_RumBokningsbehörighet
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $RumsNamn,
		[switch] $Synkade,
		[switch] $Osynkade,
		[switch] $Exportera
	)

	try {
		$RumsNamnAzure = "Res-" + $RumsNamn.Trim() + "-Book"
		$usersAzure = @()
		$usersExchange = @()
		$notSynced = @()

		Write-Verbose "Hämtar Azure-gruppen"
		$AzureGroup = Get-AzureADGroup -SearchString $RumsNamnAzure
		if ($AzureGroup -eq $null)
		{
			Write-Host "Inget rum med namn " -NoNewline
			Write-Host $RumsNamn -ForegroundColor Cyan -NoNewline
			Write-Host " hittades.`nAvslutar"
			return
		}
	} catch [Microsoft.Open.AzureAD16.Client.ApiException] {
		Write-Host "Problem att hitta Azure-gruppen för behörigheter. Kontrollera att den finns och är korrekt kopplad."
	}


	Write-Verbose "Hämtar medlemmar i Azure-gruppen"
	$usersAzure = Get-AzureADGroupMember -ObjectId $AzureGroup.ObjectId -All $true -ErrorAction Stop

	if($usersAzure.Count -gt 0)
	{
		Write-Verbose "Hämtar behöriga till maillådan i Exchange"
		try
		{
			$roomBookInPolicy = (Get-CalendarProcessing -Identity $RumsNamn -ErrorAction Stop).BookInPolicy
			$roomBookInPolicy | % {$usersExchange += (Get-Mailbox -Identity $_ -ErrorAction SilentlyContinue)}
		} catch {
			if ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException" -and $_.CategoryInfo.Activity -eq "Get-MailboxFolderPermission")
			{
				Write-Host "Rummets maillåda gick inte att hitta"
			}
		}

		if ($Synkade)
		{
			Write-Host "Dessa har behörighet att skapa bokning i " -NoNewline
			Write-Host $RumsNamn -ForegroundColor Cyan
			$usersExchange | sort DisplayName | ft DisplayName, PrimarySmtpAddress
		} else {
			Write-Verbose "Jämför personer i Azure-gruppen med behöriga i maillådan"
			foreach ( $uA in $usersAzure ) {
				if ($roomBookInPolicy -notcontains (Get-Mailbox -Identity $uA.UserPrincipalName).LegacyExchangeDN) {
					$notSynced += $uA
				}
			}
			if ($Osynkade) {
				if ($notSynced.Count -gt 0)
				{
					Write-Host "Dessa har inte blivit synkroniserade till Exchange:"
					$notSynced | sort DisplayName | ft DisplayName, UserPrincipalName
				} else {
					Write-Host "Inga osynkade"
				}
			} else {
				Write-Host "Dessa har behörighet att skapa bokning i " -NoNewline
				Write-Host $RumsNamn -ForegroundColor Cyan
				$usersExchange | sort DisplayName | ft DisplayName, PrimarySmtpAddress
				Write-Host "$($notSynced.Count) har inte blivit synkroniserade"
			}
		}


		if($Exportera)
		{
			if($usersExchange.Count -eq 0)
			{
				Write-Host "Inga användare att exportera"
			} else {
				Write-Verbose "Startar Excel"
				$excel = New-Object -ComObject excel.application 
				$excel.visible = $false
				$excelWorkbook = $excel.Workbooks.Add()
				$excelWorksheet = $excelWorkbook.ActiveSheet
				$row = 1
				$excelWorksheet.Cells.Item($row, 1) = "Rumsamn"
				$excelWorksheet.Cells.Item($row, 1).Font.Bold = $true
				$excelWorksheet.Cells.Item($row, 2) = $RumsNamn
				$row = $row + 2
				$excelWorksheet.Cells.Item($row, 1) = "Bokningsbehörighet:"
				$excelWorksheet.Cells.Item($row, 1).Font.Bold = $true
				$row++

				Write-Verbose "Samlar ihop medlemmarna"
				$membersArray = @()
				$membersMailArray = @()
				foreach ($user in $usersExchange) {
					if ($user -notlike "")
					{
						$membersArray += $user.Name
						$membersMailArray += $user.PrimarySmtpAddress
					}
				}

				Set-Clipboard -Value $membersArray
				$excelWorksheet.Cells.Item($row, 2).PasteSpecial() | Out-Null
				Set-Clipboard -Value $membersMailArray
				$excelWorksheet.Cells.Item($row, 3).PasteSpecial() | Out-Null
				$excelRange = $excelWorksheet.UsedRange
				$excelRange.EntireColumn.AutoFit() | Out-Null

				$excelWorkbook.SaveAs("H:\Kan boka i '$RumsNamn'.xlsx")
				$excelWorkbook.Close()
				Write-Host "Användarna exporterade till din H:`n" -NoNewline
				Write-Host "H:\Kan boka i '$RumsNamn'.xlsx" -ForegroundColor Cyan

				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelRange) | Out-Null
				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorksheet) | Out-Null
				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
				[System.GC]::Collect()
				[System.GC]::WaitForPendingFinalizers()
				Remove-Variable excel
			}
		}
	} else {
		Write-Host "`nGruppen för bokningsbehörighet i Azure är tom.`nInga unika behörigheter har skapats, alla kan boka rummet."
	}
}

<#
.Synopsis
	Verifiera om användare har fått EMS-licens.
.Description
	Lista över användare läses in från angiven Excel-fil, varje användare kontrolleras sedan ifall de har blivit tilldelade EMS-licens
.Parameter SökvägTillFil
	Ange sökväg till filen med användarna
.Example
	Confirm-SD_AnvändareEMSLicenserFrånExcelLista -SökvägTillFil H:\fil.xlsx
#>

function Confirm-SD_AnvändareEMSLicenserFrånExcelLista
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $SökvägTillFil
	)

	$donthave = New-Object System.Collections.ArrayList
	$notfound = New-Object System.Collections.ArrayList
	$users = New-Object System.Collections.ArrayList
	$testarrayid = @("hsa","id","id","id")
	$ticker = 0
	$need = 0

	#region Readfile
		Write-Host "Läser Excel-fil..." -Foreground Cyan -nonewline
		$column=1
		$excel = New-Object -ComObject Excel.Application
		$excelWorkbook = $excel.Workbooks.Open($SökvägTillFil)
		$excelWorksheet = $excelWorkbook.Worksheets.Item("Blad1")
		$excel.Visible = $false
		for(;$column -le $($excelWorksheet.UsedRange.Columns).Count-1;$column++)
		{
			if($testarrayid -contains $excelWorksheet.Cells.Item(1, $column).Text)
			{
				break
			}
		}

		for ($i=1; $i -le $($excelWorksheet.UsedRange.Rows).Count-1; $i++)
		{
			$users.Add($excelWorksheet.Cells.Item($i+1, $column).Text) > $null
		}
		#Close Excel-file
		$excelWorkbook.Close()
		$excel.quit()
	#endregion Readfile

	#region CheckUsers
		Write-Host "Startar test av id..." -Foreground Cyan
		foreach($id in $users)
		{
			$user = Get-ADUser -Identity $id
			$name = $user.GivenName + " " + $user.Surname

			try{
				$ticker = $ticker + 1
				$userinfo = Get-MsolUser -SearchString $name | where {$_.ImmutableId -match $id}
				if(-not ($userinfo.Licenses.AccountSku.SkuPartNumber).Contains('EMS'))
				{
					$donthave.Add($userinfo.DisplayName +" - " +$userinfo.UserPrincipalName) > $null
					$need = $need + 1
				}
			}catch{
				$notfound.Add($user.$column) > $null
			}
		}
	#endregion CheckUsers

	Write-Host "Dessa har inte EMS licens" -Foreground Cyan
	$donthave | fl
	Write-Host "`nDessa har inte skapats i Exchange" -Foreground Cyan
	$notfound | fl
	Write-Host "`nAntal kontrollerade:" $ticker "Antal som saknar EMS:" $need

	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorksheet) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
}

<#
.Synopsis
	Hämtar adresser i en distributionslista
.Description
	Hämtar samtliga adresser registrerade i en distributionslista. Ifall angivet, hämtas enbart de adresser som tillhör personer utanför organisationen.
	Adresserna kan, om angivet, exporteras till en Excel-fil, som då sparas på H:.
.Parameter Distlista
	Namn på distributionslistan
.Parameter EndastExterna
	Används för att enbart hämta de externa adresserna i distributionslistan
.Parameter Exportera
	Anger ifall datan ska exporteras till en Excel-fil
.Example
	Get-SD_DistAdresserIListan -Distlista "Distlista"
	Hämtar alla adresser i distributionslistan Distlista, dvs alla som ska ta emot mail som skickas till distributionslistan
.Example
	Get-SD_DistAdresserIListan -Distlista "Distlista" -EndastExterna
	Hämtar alla externa adresser i distributionslistan Distlista, dvs alla adresser utanför organisationen, som ska ta emot mail som skickas till distributionslistan
#>

function Get-SD_DistAdresserIListan
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Distlista,
		[switch] $EndastExterna,
		[switch] $Exportera
	)

	$dl = Get-DistributionGroup -Identity $Distlista -ErrorAction SilentlyContinue
	if($dl -eq $null)
	{
		Write-Host "Ingen distributionslista med namn " -NoNewline
		Write-Host $Distlista -NoNewline -Foreground Cyan
		Write-Host " hittades"
	} else {
		if($EndastExterna)
		{
			$members = Get-DistributionGroupMember -Identity $Distlista.Trim() | Where-Object {$_.RecipientType -like "MailContact"}
		} else {
			$members = Get-DistributionGroupMember -Identity $Distlista.Trim() | sort Name
		}

		if($Exportera)
		{
			if ($members.Count -eq 0)
			{
				Write-Host "Inga användare att exportera"
			} else {
				$excel = New-Object -ComObject Excel.Application
				$excel.Visible = $false
				$excel.DisplayAlerts = $false
				$excelWorkbook = $excel.WorkBooks.Add(1)
				$excelWorksheet = $excelWorkbook.WorkSheets.Item(1)

				$row = 1
				$excelWorksheet.Cells.Item($row, 1) = "Distributionslista"
				$excelWorksheet.Cells.Item($row, 1).Font.Bold = $true
				$excelWorksheet.Cells.Item($row, 2) = $dl.DisplayName
				$row = $row + 2
				$excelWorksheet.Cells.Item($row, 1) = "Namn"
				$excelWorksheet.Cells.Item($row, 2) = "Mailadress"
				$row++

				$memberArray = @()
				$memberMailArray = @()
				foreach($member in $members)
				{
					$memberArray += $member.DisplayName
					$memberMailArray += $member.PrimarySMTPAddress
				}

				Set-Clipboard -Value $memberArray | Out-Null
				$excelWorksheet.Cells.Item($row, 1).PasteSpecial() | Out-Null
				Set-Clipboard -Value $memberMailArray | Out-Null
				$excelWorksheet.Cells.Item($row, 2).PasteSpecial() | Out-Null

				$excelWorksheet.UsedRange.EntireColumn.autofit() | Out-Null

				$excelWorkbook.SaveAs("H:\Medlemmar i distributionslista '$Distlista'.xlsx")
				$excel.WorkBooks.Close()
				$excel.Quit()
				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorksheet) | Out-Null
				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
				[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
				[System.GC]::Collect()
				[System.GC]::WaitForPendingFinalizers()

				Write-Host "$($members.Count) medlemar från distributionslista '$dl', har exporterats till:"
				Write-Host "H:\Medlemmar i distributionslista '$Distlista'.xlsx" -Foreground Green
			}
		} else {
			$members | ft DisplayName, PrimarySMTPAddress
		}
	}
}

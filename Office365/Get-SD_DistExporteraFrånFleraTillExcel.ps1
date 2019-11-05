<#
.Synopsis
	Exporterar medlemmar från flera distributionlistor till en Excel-fil
.Description
	Läser in distributionslistor från en Excel-fil, angiven som parameter, och hämtar alla användare i de distributionlistorna. De läggs sedan in i en ny Excel-fil, en distributionslista per Excel-blad och sparas på H:.
.Parameter InputFile
	CSV-fil med de distributionlistor där medlemmar ska hämtas ifrån
.Description
	Läser in listan med distributionlistor från InputFile, hämtar varje distributionslista och lägger det som ett eget blad i angiven Excel-fil med information om namn, SMTP-adress, ägare och medlemmar
#>

function Get-SD_DistExporteraFrånFleraTillExcel
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $InputFile
	)

	#region Create Excel
	$excel = New-Object -ComObject excel.application 
	$excel.visible = $false
	$excelWorkbook = $excel.Workbooks.Add()
	#endregion
	  
	#Get all Distribution Groups from Office 365  
	if ($InputFile.EndsWith("csv"))
	{
		$objDistributionGroups = Get-Content $InputFile
	} else {
		Write-Host "Filen måste vara av format 'CSV' för att skriptet ska fungera.`nAvslutar"
		return
	}
	$count = 1
	Write-Host "Hittade"$objDistributionGroups.Count"distributionlistor"

	#Iterate through all groups, one at a time
	foreach ($item in $objDistributionGroups)  
	{
		#Get members of this group
		if ( $objDistributionGroup = Get-DistributionGroup -Identity $item )
		{
			$objDGMembers = Get-DistributionGroupMember -Identity $objDistributionGroup.DisplayName -ResultSize Unlimited | sort Name

			Write-Host $count "- $($objDistributionGroup.DisplayName) ($($objDGMembers.Count) medlemmar)"

			#region Create worksheet
			if ($count -eq 1)
			{
				$excelTempsheet = $excelWorkbook.ActiveSheet
			} else {
				$excelTempsheet = $excelWorkbook.Worksheets.Add()
			}
			$tempname = $objDistributionGroup.DisplayName
			$tempname = $tempname.replace("\","_")
			$tempname = $tempname.replace("/","_")
			$tempname = $tempname.replace("*","_")
			$tempname = $tempname.replace("[","_")
			$tempname = $tempname.replace("]","_")
			$tempname = $tempname.replace(":","_")
			$tempname = $tempname.replace("?","_")
			if(($tempname).Length -gt 31)
			{
				try
				{
					$excelTempsheet.Name = ($tempname).SubString(0,31)
				} catch {
					$excelTempsheet.Name = ($objDistributionGroup.PrimarySMTPAddress).SubString(0,31)
				}
			} else {
				$excelTempsheet.Name = $tempname
			}
			#endregion

			#region Add Members
			$row = 1
			$excelTempsheet.Cells.Item($row, 1) = "Namn"
			$excelTempsheet.Cells.Item($row, 1).Font.Bold = $true
			$excelTempsheet.Cells.Item($row, 2) = $objDistributionGroup.DisplayName
			$row = 2
			$excelTempsheet.Cells.Item($row, 1) = "Mailadress"
			$excelTempsheet.Cells.Item($row, 1).Font.Bold = $true
			$excelTempsheet.Cells.Item($row, 2) = $objDistributionGroup.PrimarySMTPAddress
			$row = 3
			$excelTempsheet.Cells.Item($row, 1) = "Ägare"
			$excelTempsheet.Cells.Item($row, 1).Font.Bold = $true
			foreach($owner in ((Get-DistributionGroup -Identity $objDistributionGroup.Name).ManagedBy))
			{
				if ($owner -notlike "*MIG-User*")
				{
					$excelTempsheet.Cells.Item($row, 2) = $owner
					$row = $row + 1
				}
			}

			$row++
			$excelTempsheet.Cells.Item($row, 1) = "Medlemmar"
			$startTableRow = $row
			$excelTempsheet.Cells.Item($row, 2) = "Mailadress"
			$row = $row + 1
			if ($objDGMembers.Count -eq 0)
			{
				$excelTempsheet.Cells.Item($row, 1) = "-"
			} else {
				$memberArray = @()
				$memberMailArray = @()
				foreach ($objMember in $objDGMembers)  
				{  
					$memberArray += $objMember.Name
					$memberMailArray += $objMember.PrimarySMTPAddress
				}
				Set-Clipboard -Value $memberArray
				$excelTempsheet.Cells.Item($row, 1).PasteSpecial() | Out-Null
				Set-Clipboard -Value $memberMailArray
				$excelTempsheet.Cells.Item($row, 2).PasteSpecial() | Out-Null
				$excelRange = $excelTempsheet.UsedRange
				$excelRange.EntireColumn.AutoFit() | Out-Null
				$excelTempsheet.ListObjects.Add(1, $excelTempsheet.Range($excelTempsheet.Cells.Item($startTableRow,1),$excelTempsheet.Cells.Item($excelTempsheet.usedrange.rows.count, 2)), 0, 1) | Out-Null
			}
			#endregion Add Members

			$count = $count+1
		} else {
			Write-Host "Ingen distributionslista med namn" -NoNewline
			Write-Host $item -NoNewline -Foreground Cyan
			Write-Host " hittades"
		}
	}
	$excelWorkbook.SaveAs("H:\Distributionslistor.xlsx")
	$excelWorkbook.Close()
	$excel.Quit()

	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelRange) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelTempsheet) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers()
	Remove-Variable excel
	Write-Host "Distributionslistor, med medlemmar, sparade i H:\Distributionslistor.xlsx"
}

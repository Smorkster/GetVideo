<#
.Synopsis
    Exporterar alla medlemmar i AD-grupp till CSV-fil
.Parameter Grupper
    En lista på grupper som ska exporteras
.Description
    Hämtar alla medlemmar (användare och datorer) för varje given AD-grupp och exporterar dessa till en CSV-fil
.Example
    Get-SD_ExporteraADAnvändare -Grupper "Grupp1","Grupp2"
#>

function Get-SD_ExporteraADAnvändare
{
    param(
	[Parameter(Mandatory=$true)]
        [string[]] $Grupper
    )

    $members = @()
	$ticker = 1
	#region Create Excel
	$excel = New-Object -ComObject excel.application 
	$excel.visible = $false
	$excelWorkbook = $excel.Workbooks.Add()
	#endregion

    foreach ($group in $Grupper) {
		#region Create Excel-worksheet
		Write-Progress "Skapar Excel-blad" -Status "Blad ($ticker av $($Grupper.Count))" -PercentComplete (($ticker/$Grupper.Count)*100)
		if ($ticker -eq 1)
		{
			$excelTempsheet = $excelWorkbook.ActiveSheet
		} else {
			$excelTempsheet = $excelWorkbook.Worksheets.Add()
		}
		#endregion

		#region Add group memberdata
		$row = 1
		$excelTempsheet.Cells.Item($row, 1) = "Namn AD-grupp:"
		$excelTempsheet.Cells.Item($row, 1).Font.Bold = $true
		$excelTempsheet.Cells.Item($row, 2) = (Get-ADGroup -Identity $group).Name
		$row = $row + 2

		$excelTempsheet.Cells.Item($row, 1) = "Gruppmedlemmar"
		$excelTempsheet.Cells.Item($row, 1).Font.Bold = $true
		$excelTempsheet.Cells.Item($row, 2) = "Namn"
		$excelTempsheet.Cells.Item($row, 2).Font.Bold = $true
		$excelTempsheet.Cells.Item($row, 3) = "Medlemstyp"
		$excelTempsheet.Cells.Item($row, 3).Font.Bold = $true
		$row++
		$groupMembers = Get-ADGroupMember -Identity $group | sort name

		$membersArray = @()
		$membersClassArray = @()
		
		Write-Verbose "Skapar data från gruppmedlemmarna"
		foreach ($groupMember in $groupMembers)
		{
			$membersArray += $groupMember.name
			$membersClassArray += $groupMember.objectClass
		}
		Set-Clipboard -Value $membersArray
		$excelTempsheet.Cells.Item($row, 2).PasteSpecial() | Out-Null
		Set-Clipboard -Value $membersClassArray
		$excelTempsheet.Cells.Item($row, 3).PasteSpecial() | Out-Null

		$excelRange = $excelTempsheet.UsedRange
		$excelRange.EntireColumn.AutoFit() | Out-Null
		#endregion Add Members
		$ticker++
    }

	$filename = "H:\Exporterade gruppbehörigheter från AD.xlsx"
	$excelWorkbook.SaveAs($filename)
	$excelWorkbook.Close()
	$excel.Quit()

	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelRange) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelTempsheet) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers()
	Remove-Variable excel
    Write-Host "Användarna exporterade till " -NoNewline
	Write-Host $filename -Foreground Cyan
}

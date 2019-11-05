<#
.Synopsis
	Exporterar alla medlemmar från flera Azure-grupper för rum till en Excel-fil
.Description
	Hämtar medlemmar från Azure-grupper för rum eller resurs för angiven kund med angiven behörighet. Medlemmarna exporteras till en Excel-fil som sparas på H:.
.Parameter GruppTyp
	Typ av Azure-grupp [Admins, Full, Read]
.Parameter RumResurs
	Gäller det rum eller resurs
.Parameter Kund
	Vilken kund gäller exporten för
#>

function Get-SD_RumExporteraFrånFleraTillExcel
{
	param(
	[ValidateSet('Admins', 'Book')]
	[Parameter(Mandatory=$true)]
		[string] $GruppTyp,
	[ValidateSet('Rum', 'Resurs')]
	[Parameter(Mandatory=$true)]
		[string] $RumResurs,
	[ValidateSet('KundA','KundB')]
	[Parameter(Mandatory=$true)]
		[string] $Kund
	)

	$row = 1
	#region Create Excel
	$excel = New-Object -ComObject excel.application 
	$excel.visible = $false
	$excelWorkbook = $excel.Workbooks.Add()
	$excelWorksheet = $excelWorkbook.ActiveSheet
	$excelWorksheet.Cells.Item($row, 1) = "Rumsnamn"
	$excelWorksheet.Cells.Item($row, 2) = "Medlemmar"
	$excelWorksheet.Cells.Item($row, 3) = "Medlems adress"
	$row++
	#endregion
	  
	#Get all Azure-groups
	$sökSträng = "Res-"+$Kund+" "+$RumResurs
	$filter = "*-"+$GruppTyp
	Write-Verbose $sökSträng
	$azureGroups = Get-AzureADGroup -SearchString $sökSträng -All:$true | ? {$_.DisplayName -like $filter}
	$count = 1
	Write-Host "Hittade"$azureGroups.Count"Azure-grupper"

	#Iterate through all groups
	foreach ($roomAzureGroup in $azureGroups)  
	{
		#Get members of this group
		$azureGroupMembers = Get-AzureADGroupMember -ObjectID $roomAzureGroup.ObjectID -All $true | ? {$_.DisplayName -notlike "*-Book*"}
		Write-Host $count "- $($roomAzureGroup.DisplayName) ($($azureGroupMembers.Count) medlemmar)"

		#region Add Members
		$row++
		$excelWorksheet.Cells.Item($row, 1) = $roomAzureGroup.DisplayName -replace "Res-","" -replace "-Admins",""

		$memArray = @()
		$mailArray = @()
		if ($azureGroupMembers.Count -eq 0)
		{
			$memArray += "Inga medlemmar"
			$mailArray += "-"
		} else {
			foreach ($azureGroupMember in $azureGroupMembers)  
			{
				$memArray += $azureGroupMember.DisplayName
				$mailArray += $azureGroupMember.UserPrincipalName
			}
		}
		Set-Clipboard -Value $memArray
		$excelWorksheet.Cells.Item($row, 2).PasteSpecial() | Out-Null
		Set-Clipboard -Value $mailArray
		$excelWorksheet.Cells.Item($row, 3).PasteSpecial() | Out-Null
		#endregion Add Members

		$row = $row + $memArray.Count
		$count = $count + 1
	}

	$excelRange = $excelWorksheet.UsedRange
	$excelRange.EntireColumn.AutoFit() | Out-Null
	$filename = "H:\Alla med '$GruppTyp'-behörighet för $RumResurs hos $Kund.xlsx"
	$excelWorkbook.SaveAs($filename)
	$excelWorkbook.Close()
	$excel.Quit()

	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelRange) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorksheet) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
	[System.GC]::Collect()
	[System.GC]::WaitForPendingFinalizers()
	Remove-Variable excel
	Write-Host "$Typ, med '$GruppTyp' medlemmar hos $Kund, sparade i " -NoNewline
	Write-Host $filename -Foreground Cyan
}

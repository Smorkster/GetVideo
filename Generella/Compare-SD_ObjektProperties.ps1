<#
.Synopsis
	JÃ¤mfÃ¶r tvÃ¥ PowerShell-objekt
.Description
	JÃ¤mfÃ¶r alla parametrar i tvÃ¥ objekt och listar sedan varje parameter som inte Ã¤r lika mellan objekten
.Parameter ReferenceObject
	Ett objekt som ska jÃ¤mfÃ¶ras
.Parameter DifferenceObject
	Ett objekt som ska jÃ¤mfÃ¶ras
.Example
	Compare-SD_ObjektProperties -ReferenceObject $ObjOne -DifferenceObject $ObjTwo
#>
function Compare-SD_ObjektProperties
{
	param(
	[Parameter(Mandatory=$true)]
		[PSObject] $ReferenceObject,
	[Parameter(Mandatory=$true)]
		[PSObject] $DifferenceObject
	)

	$objprops = $ReferenceObject | Get-Member -MemberType Property, NoteProperty | % Name
	$objprops += $DifferenceObject | Get-Member -MemberType Property, NoteProperty | % Name
	$objprops = $objprops | Sort | Select -Unique
	$diffs = @()

	foreach ($objprop in $objprops)
	{
		$diff = Compare-Object $ReferenceObject $DifferenceObject -Property $objprop
		if ($diff)
		{
			$diffprops = @{
				PropertyName=$objprop
				RefValue=($diff | ? {$_.SideIndicator -eq '<='} | % $($objprop))
				DiffValue=($diff | ? {$_.SideIndicator -eq '=>'} | % $($objprop))
			}
			$diffs += New-Object PSObject -Property $diffprops
		}
	}

	if ($diffs)
	{
		return ($diffs | Select PropertyName,RefValue,DiffValue)
	}
}

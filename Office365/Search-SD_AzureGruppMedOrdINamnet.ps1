<#
.Synopsis
	Sök på Office365-grupp genom sökningsord
.Description
	Söker igenom alla Msol-grupper efter de grupper som har sökordet i DisplayName
.Parameter SökOrd
	Ord som kan finnas med i gruppnamnet
.Example
	Search-SD_AzureGruppMedOrdINamnet -SökOrd "Group1"
	Söker igenom alla Azure-grupper efter namn som innehåller Group1 i namnet
#>

function Search-SD_AzureGruppMedOrdINamnet
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $SökOrd
	)

	try {
		$groups = Get-MsolGroup -All -ErrorAction Stop | ? {$_.DisplayName -match $SökOrd}
		if($groups -eq $null)
		{
			Write-Host "Ingen grupp hittades som har $SökOrd i DisplayName"
		} else {
			$groups | sort DisplayName | select DisplayName, Description
		}
	} catch {
		Write-Host "Fel uppstod vid körningen:"
		$_
	}
}

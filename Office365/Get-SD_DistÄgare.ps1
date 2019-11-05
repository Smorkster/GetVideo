<#
.Synopsis
	Hämtar ägare av distributionslista
.Description
	Hämtar registrerad ägare av distributionslista från Exchange
.Parameter Distributionslista
	Namn eller mailadress för distributionslistan
.Example
	Get-SD_DistÄgare -Distributionslista "Distlista"
	Hämtar ägaren av distributionslistan Distlista
#>

function Get-SD_DistÄgare
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Distributionslista
	)

	try {
		$owners = ( Get-DistributionGroup -Identity $Distributionslista -ErrorAction Stop ).ManagedBy | ? {$_ -notlike "*MIG-User-1-Farm-1*"}
		Write-Host "Ägare av " -NoNewline
		Write-Host $Distributionslista -ForegroundColor Cyan
		$owners

		$admins = Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -SearchString "DL-$Distributionslista-Admins").ObjectId | ? {$_.UserPrincipalName -match "@test.com"}
		Write-Host "`nDessa är admins" -ForegroundColor Cyan
		$admins | select DisplayName, UserPrincipalName
	} catch {
		Write-Host "`nIngen distributionslista med namnet " -nonewline
		Write-Host $Distributionslista -ForegroundColor Red -nonewline
		Write-Host " funnen"
	}
}

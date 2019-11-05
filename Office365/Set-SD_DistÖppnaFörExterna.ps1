<#
.Synopsis
	Öppnar distributionslista för extern kontakt
.Description
	Öppnar distributionslista så att externa personer kan skicka mail till distributionslistan.
.Parameter Distributionslista
	Namn på distributionslistan
#>

function Set-SD_DistÖppnaFörExterna
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Distributionslista
	)

	if ($dist = Get-DistributionGroup -Identity $Distributionslista -ErrorAction SilentlyContinue)
	{
		Set-DistributionGroup -Identity $dist.Identity -RequireSenderAuthenticationEnabled $false
	} else {
		Write-Host "Hittade ingen distributionslista med namn " -NoNewline
		Write-Host $Distributionslista -Foreground Cyan
	}
}

<#
.Synopsis
	Hämta distributionslistor användare är ägare för
.Description
	Hämtar alla distributionslistor som en användare är registrerad som ägare för
.Parameter id
	Användarens id
.Example
	Get-SD_AnvändareÄgareDistributionslistor -id "ABCD"
	Hämtar de distributionslistor som användare ABCD är ägare av
#>

function Get-SD_AnvändareÄgareDistributionslistor
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id
	)

	$user = Get-ADUser -Identity $id -Properties *
	$address = "*"+$user.EmailAddress+"*"
	$funkar = Get-DistributionGroup -Filter "CustomAttribute10 -like '$address'"
	
	if($funkar.Count -gt 0)
	{
		Write-Host $user.Name -NoNewline -Foreground Cyan
		Write-host " är ägare av"$funkar.Count"distributionslistor:"
		$funkar | ft DisplayName
	} else {
		Write-Host "Inga distributionslistor funna med"$user.Name"som ägare"
	}
}

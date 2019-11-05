<#
.Synopsis
	Hämtar angiven plats för ett rum
.Description
	Hämtar registrerad plats för ett rum från Exchange
.Parameter Rumsnamn
	Namn på rummet
.Example
	Get-SD_RumPlats -Rumsnamn "RumA"
	Hämtar den plats som angivits för rum RumA
#>

function Get-SD_RumPlats
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Rumsnamn
	)

	try {
		$rum = (Get-Mailbox -Identity $Rumsnamn -ErrorAction Stop).Office
		if($rum -eq $null -or $rum -eq "")
		{
			Write-Host "Ingen plats är specificerad"
		} else {
			Write-Host "$Rumsnamn"$rum"`n"
		}
	} catch {
		if ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException")
		{
			Write-Host "Inget rum med namn $Rumsnamn hittas i Exchange" -Foreground Red
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

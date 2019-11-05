<#
.Synopsis
	Lista alla medlemmar i en distributionslista
.Description
	HÃ¤mtar samtliga medlemmar av en distributionslista och listar dem sorterat i bokstavsordning efter namn
.Parameter Distributionslista
	Namn pÃ¥ distributionslistan
.Example
	Get-SD_DistMedlemmar -Distributionslista "Distlista"
	HÃ¤mtar alla adresser i distributionslistan Distlista, dvs alla som ska ta emot mail som skickas till distributionslistan
#>

function Get-SD_DistMedlemmar
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Distributionslista
	)

	try {
		Get-DistributionGroupMember -Identity $Distributionslista.Trim() -ErrorAction Stop | sort PrimarySMTPAddress | ft PrimarySMTPAddress, DisplayName
	} catch {
		if ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException")
		{
			Write-Host "Ingen distributionslista med namn $Distributionslista hittades."
		} else {
			Write-Host "Fel uppstod i kÃ¶rningen:"
			$_
		}
	}
}

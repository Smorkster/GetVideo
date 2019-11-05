<#
.Synopsis
	Skapa en ny rumslista
.Parameter NamnPåRumslista
	Namnet för rumslistan. Ska följa namnstandarden "<Organisation> <Namn>"
.Parameter PrimarySMTPAddress
	Primär SMTP-adress för distributionslistan. Ska följa namnstandarden för distributionslistor
.Parameter Smtpadress
	Sekundär SMTP-adress
.Example
	New-DistributionGroup -NamnPåRumslista "RumLista" -PrimarySMTPAddress "rumslista@test.com" -Smtpadress "rumslista@test.com"
#>
function New-SD_Rumslista
{
	param(
	[Parameter(Mandatory=$true)]
		[String] $NamnPåRumslista,
	[Parameter(Mandatory=$true)]
		[String] $PrimarySMTPAddress,
	[Parameter(Mandatory=$true)]
		[String] $Smtpadress
	)
	
	New-DistributionGroup -Name $NamnPåRumslista -Roomlist
	Set-DistributionGroup -Identity $NamnPåRumslista -PrimarySMTPAddress $PrimarySMTPAddress
	Set-DistributionGroup -Identity $NamnPåRumslista -EmailAddresses @{Add="smtp:$Smtpadress"}
	Set-DistributionGroup -Identity $NamnPåRumslista -Description "Now"
	
	Write-Host "Rumslista '$NamnPåRumslista' har nu skapats"
}

<#
.Synopsis
	Anslut till tjänsterna
.Description
	Ansluter till alla tre online-tjänsterna för Office365, Exchange, AzureAD samt MSonline. Om anslutningen till Exchange har tappats p.g.a. timeout, kan skriptet användas för att återansluta.
.Parameter reconnectExchange
	Återansluter till Exchange.
	Stänger nuvarande PSSession, skapar en ny och ansluter
#>

function Connect-SD_ToServices
{
	param(
	 	[switch] $reconnectExchange
	)

	$ErrorActionPreference = "SilentlyContinue"
	$WarningPreference = "SilentlyContinue"
	#region Check PSSession
	if (!(Get-PSSession | Where {$_.ConfigurationName -eq "Microsoft.Exchange"}))
	{
		Write-Host "Du är inte ansluten till Exchange."

		Write-Host "Connecting to Exchange" -Foreground Cyan
		$EXOSession = New-ExoPSSession
		Import-PSSession $EXOSession -AllowClobber > $null
	} elseif ($reconnectExchange) {
		Get-Module -Name "*tmp*" | Remove-Module
		Get-PSSession | Remove-PSSession
		$EXOSession = New-ExoPSSession
		Import-PSSession $EXOSession -AllowClobber > $null
		Write-Host "Ansluten till Exchange" -ForegroundColor Green
	}
	#endregion Check PSSession

	#region Check MsolService
	Get-MsolDomain > $null
	if(-not $?)
	{
		Write-Host "Du är inte ansluten till MsolService."
		Write-Host "Ansluter." -Foreground Cyan
		Connect-MsolService
	}
	#endregion Check MsolService

	#region Check AzureAD
	Get-AzureADDomain > $null
	if(-not $?)
	{
		Write-Host "Du är inte ansluten till AzureAD."
		Write-Host "Ansluter." -Foreground Cyan
		Connect-AzureAD > $null
	}
	#endregion Check AzureAD

	$ErrorActionPreference = "Continue"
	$WarningPreference = "Continue"
	Write-Host "Connected to services"
}

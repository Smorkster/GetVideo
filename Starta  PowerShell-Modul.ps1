<#
.Synopsis
	Starta modulen för PowerShell-skript och anslut till online-tjänsterna
.Description
	Detta skript startar sessionen för att använda Servicedesks PowerShell-modul både lokalt och mot online-tjänsterna.
	För att underlätta inloggningen, startas även en AutoHotKey-skript som automatiskt skriver in användarnamn och lösenord i inloggningsrutorna. Uppgifterna hämtas genom att köra Auto-Type via KeePass. Värt att tänka på här är att det måste finnas med en delay i KeePass, för att hantera att rutan för lösenord ska hinna laddas.
	Efter inloggningen i Exchange, MSOnline och AzureAD, läses (importeras) Servicedesks-modul in.
.Parameter loadOnly
	Startar bara PowerShell-modulen. Gör alltså ingen inloggning
.Parameter reconnectExchange
	Läser om modulen för Exchange och gör en ny inloggning
#>

param (
	[switch] $loadOnly,
	[switch] $reconnectExchange
)

& "$PSScriptRoot\AutoLösenord.ahk"
$exchangeModule = $((Get-ChildItem -Path $($env:LOCALAPPDATA+"\Apps\2.0\") -Filter Microsoft.Exchange.Management.ExoPowershellModule.dll -Recurse ).FullName|?{$_ -notmatch "_none_"} | Select -First 1)
[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation") > $null

if(-not (Get-Module | ? {$_.Name -like "*MSOnline*"}))
{
	Write-Host "Läser in MSOnline-modulen" -ForegroundColor Cyan
	Import-Module MSOnline
}

if(-not (Get-Module | ? {$_.Name -like "*ActiveDirectory*"}))
{
	Write-Host "Läser in ActiveDirectory-modulen" -ForegroundColor Cyan
	Import-Module ActiveDirectory
}

if(-not $loadOnly)
{
	if(-not (Get-Module | ? {$_.Name -like "*Exchange*"}))
	{
		Write-Host "Läser in Exchange-modulen" -ForegroundColor Cyan
		Import-Module $exchangeModule
	}
}

if(-not (Get-Module | ? {$_.Name -like "*Servicedesk*"}))
{
	Write-Host "Läser in Servicedesks modul..." -ForegroundColor Cyan
	Import-Module $PSScriptRoot\ServicedeskPowerShell-Modul.psm1
	Write-Host "Om du vill veta vilka kommandon som finns, kör kommando" -NoNewline
	Write-Host " Show-SD_Meny " -NoNewline -ForegroundColor Cyan
	Write-Host "så visas en lista med inlästa kommandon."
}

if($loadOnly)
{
	return
}

if (!(Get-PSSession | Where {$_.ConfigurationName -eq "Microsoft.Exchange"}))
{
	Write-Host "Du är inte ansluten till Exchange"
	Write-Host "Ansluter..." -ForegroundColor Cyan
	if($exchangeModule.Length -eq 0)
	{
		Write-Host "Exchange-modulen är inte installerad." -ForegroundColor Red
	} else {
		$EXOSession = New-ExoPSSession
		$WarningPreference = "SilentlyContinue"
		Import-PSSession $EXOSession -AllowClobber > $null
		$WarningPreference = "Continue"
		Write-Host "Ansluten till Exchange" -ForegroundColor Green
	}
} elseif ($reconnectExchange) {
	Get-Module -Name "*tmp*" | Remove-Module
	Get-PSSession | Remove-PSSession
	$EXOSession = New-ExoPSSession
	$WarningPreference = "SilentlyContinue"
	Import-PSSession $EXOSession -AllowClobber > $null
	$WarningPreference = "Continue"
	Write-Host "Ansluten till Exchange" -ForegroundColor Green
} else {
	Write-Host "Ansluten till Exchange" -ForegroundColor Green
}

try
{
    Get-MsolDomain -ErrorAction Stop > $null
	Write-Host "Ansluten till MsolService" -ForegroundColor Green
} catch {
	Write-Host "Du är inte ansluten till MsolService."
	Write-Host "Ansluter..." -Foreground Cyan
	try {
		Connect-MsolService
		Write-Host "Ansluten till MsolService" -ForegroundColor Green
	} catch [System.Management.Automation.CommandNotFoundException] {
		Write-Host "Modulen MsOnline är inte installerat på datorn." -ForegroundColor Red
	}
}

try
{
    Get-AzureADDomain -ErrorAction Stop > $null
	Write-Host "Ansluten till AzureAD" -ForegroundColor Green
} catch {
	Write-Host "Du är inte ansluten till AzureAD."
	Write-Host "Ansluter..." -ForegroundColor Cyan
	try {
		Connect-AzureAD > $null
		Write-Host "Ansluten till AzureAD" -ForegroundColor Green
	} catch [System.Management.Automation.CommandNotFoundException] {
		Write-Host "Module AzureAD är inte installerat på datorn." -ForegroundColor Red
	}
}

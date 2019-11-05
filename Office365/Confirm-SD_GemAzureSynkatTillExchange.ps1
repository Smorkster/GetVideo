<#
.Synopsis
	Har Azure-objekt synkroniserat till Exchange
.Description
	Kontrollera ifall alla användare i Azure-grupp har synkroniserats till Exchange. Kontrollen görs för alla behörighetsnivåer enligt säkerhetsgrupperna i Azure.
.Parameter Namn
	Namn på Outlook-objektet
.Parameter Typ
	Typ av Outlook-objekt. Måste vara Funk, Dist, Rum eller Resurs
.Example
	Confirm-SD_GemAzureSynkatTillExchange -Namn "Distlista" -Typ Dist
	Kontrollerar att alla medlemmar i Azure-gruppen för distributionslistan Distlista, har synkroniserats till Exchange
#>

function Confirm-SD_GemAzureSynkatTillExchange
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Namn,
	[ValidateSet("Funk","Dist","Rum","Resurs")]
	[Parameter(Mandatory=$true)]
		[string] $Typ
	)

	$notSynced = @()
	if($Typ -eq "Funk")
	{
		$exchangeFunk = $Namn
		$azureFunk = "MB-"+$Namn+"-Full"
		$exchangeGrupper = @()
		$azureGrupper = @()

		Get-MailboxPermission -Identity $exchangeFunk | % {$exchangeGrupper += $_.DisplayName}
		Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -SearchString $azureFunk).ObjectId -All $true | % {$azureGrupper += $_.DisplayName}
		$azureGrupper | % {if($exchangeGrupper -notcontains $_.tostring()) {$notSynced += $_}}
		if($notSynced.Count -gt 0)
		{
			Write-Host $notSynced.Count "personer med full behörighet har inte synkroniserats till Exchange"
		} else {
			Write-Host "Alla användare med full behörighet synkroniserade till Exchange"
		}

		$azureFunk = "mb-"+$Namn+"-read"
		$azureGrupper = @()
		Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -SearchString $azureFunk).ObjectId -All $true | % {$azureGrupper += $_.DisplayName}
		$azureGrupper | % {if($exchangeGrupper -notcontains $_.tostring()) {$notSynced += $_}}
		if($notSynced.Count -gt 0)
		{
			Write-Host $notSynced.Count "personer med läsbehörighet har inte synkroniserats till Exchange"
		} else {
			Write-Host "Alla användare med läsbehörighet synkroniserade till Exchange"
		}
		return
	} elseif($Typ -eq "Dist")
	{
		$exchangeDist = $Namn
		$azureDist = $Namn
		$exchangeGrupper = @()
		$azureGrupper = @()
		Get-DistributionGroupMember -Identity $exchangeDist | % {$exchangeGrupper += $_.DisplayName}
		Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -SearchString $azureDist).ObjectId -All $true | % {$azureGrupper += $_.DisplayName}
	} elseif($Typ -eq "Rum" -or $Typ -eq "Resurs")
	{
		$exchangeRum = $Namn+":\Kalender"
		$azureRum = "res-"+$Namn+"-book"
		$exchangeGrupper = @()
		$azureGrupper = @()
		Get-MailboxFolderPermission -Identity $exchangeRum | ? {$_.user -notlike "Anon*" -and $_.user -notlike "Stand*"} | % {$exchangeGrupper += $_.User.DisplayName}
		Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -SearchString $azureRum).ObjectId -All $true | % {$azureGrupper += $_.DisplayName}
	} else
	{
		Write-Host "Felaktig typ vald"
		return
	}

	$azureGrupper | % {if($exchangeGrupper -notcontains $_.tostring()) {$notSynced += $_}}
	
	if($notSynced.Count -eq 0)
	{
		Write-Host "Alla användare synkroniserade till Exchange"
	} else {
		Write-Host $notSynced.Count "personer har inte synkroniserats till Exchange:"
	}
}

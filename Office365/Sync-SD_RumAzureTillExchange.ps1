<#
.Synopsis
    Synka användares behörigheter till rum från Azure till Exchange
.Description
    Ifall en användare har fått behörighet skapad i en Azure-grupp för rum, men detta inte har blivit översynkat till Exchange, kan den läggas på manuellt
    Parameter Rumslista kan ta ett eller flera rum och loopar då igenom varje rum enskilt
.Parameter Rum
    Namn på rum som ska synkroniseras
#>
function Sync-SD_RumAzureTillExchange
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Rum
	)

	$azureNamn = "Res-"+$Rum+"-Book"
	$usersAzure = Get-AzureADGroupMember -ObjectId (Get-AzureADGroup -SearchString $azureNamn).ObjectId
	$roomPolicy = Get-CalendarProcessing -Identity $Rum
	$exchangeRum = "$Rum`:\Kalender"
	$ticker = 1

	foreach ($user in $usersAzure)
	{
		$roomPolicy += (Get-Mailbox -Identity $user.UserPrincipalName).LegacyExchangeDN
	}
	$roomPolicy = $roomPolicy | select -Unique
	Set-CalendarProcessing -Identity $Rum -AllBookInPolicy:$false -BookInPolicy $roomPolicy -ErrorAction SilentlyContinue

	foreach ($user in $usersAzure) {
        Write-Progress -Activity $r -PercentComplete (($ticker/$usersAzure.Count)*100)
		try {
			Write-Verbose "Skapar behörighet för $($user.DisplayName)"
			Add-MailboxFolderPermission -Identity $exchangeRum -AccessRights LimitedDetails -Confirm:$false -User $user.UserPrincipalName -ErrorAction Stop
		} catch {
			if ($_.CategoryInfo.Reason -like "*UserAlreadyExist*")
			{
				Write-Host "Behörighet finns redan"
			} elseif ($_.CategoryInfo.Reason -eq "ACLTooBigException") {
				Write-Host "För många medlemmar i Azure-gruppen. Kan inte synkronisera $($user.DisplayName) till Exchange.`nAvslutar."
				return
			} elseif ($_.CategoryInfo.Reason -eq "InvalidExternalUserIdException") {
				$address = ($_.Exception -split [char]0x22)[1]
				Write-Host "Adress $address finns inte. Personen har troligen slutat." -ForegroundColor Red
			} else {
				Write-Host "Problem vid skapande av behörighet i kalendern:"
				Write-Host $_.CategoryInfo.Reason
				Write-Host $_.Exception
			}
		}
		$ticker++
	}
}

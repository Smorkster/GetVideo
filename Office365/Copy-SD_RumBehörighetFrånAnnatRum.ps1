<#
.Synopsis
	Kopiera bokningsbehörigheter från ett rum till ett annat
.Description
	Hämtar vilka personer som har behörighet att skapa bokningar för ett rum och skapar ny behörighet för bokning för ett annat rum. Behörigheten sätts både i Azure, med BookInPolicy samt med behörighet 'LimitedDetails' på kalendern
.Parameter RumKopieraFrån
	Visningsnamn på det rum som behörigheter ska kopieras från
.Parameter RumKopieraTill
	Visningsnamn på det rum som behörigheter ska kopieras till
.Example
	Copy-SD_RumBehörighetFrånAnnatRum -RumKopieraFrån "RumA" -RumKopieraTill "RumB"
	Kopierar alla behörighet som kopplats till rum RumA, till att även finnas kopplade till rum RumB
#>

function Copy-SD_RumBehörighetFrånAnnatRum
{
    param(
    [Parameter(Mandatory=$true)]
        [string] $RumKopieraFrån,
    [Parameter(Mandatory=$true)]
        [string] $RumKopieraTill
    )
	#region "Setup"
	$originRoomNameAzure = "Res-$RumKopieraFrån-Book"
	$originRoomAzure = Get-AzureADGroup -SearchString $originRoomNameAzure
	$targetExchange = "$RumKopieraTill`:\Kalender"
	$targetBookInPolicy = (Get-CalendarProcessing -Identity $RumKopieraTill).BookInPolicy
	$targetRoomNameAzure = "Res-$RumKopieraTill-Book"
	$targetRoomAzure = Get-AzureADGroup -SearchString $targetRoomNameAzure
	$ticker = 1
	#endregion

	#region "Get Azure members"
	$membersAzure = Get-AzureADGroupMember -ObjectId $originRoomAzure.ObjectId
	$count = $membersAzure.Count
	#endregion

	#region "Create BookInPolicy-list"
	$membersAzure | foreach {
		$text = $ticker.ToString()+"/"+$count.ToString()
		Write-Progress -Activity "Setting up BookInPolicy" -Status $text -PercentComplete (($ticker/$count)*100)
		$targetBookInPolicy += ( Get-Mailbox -Identity $_.UserPrincipalName ).LegacyExchangeDN
		$ticker += 1
	}
	#endregion

	$ticker = 1
	#region "Set BookInPolicy"
	Set-CalendarProcessing -Identity $rum -BookInPolicy $targetBookInPolicy
	#endregion

	#region "Add members to Azure-group"
	$membersAzure | foreach {
		$text = $ticker.ToString()+"/"+$count.ToString()
		Write-Progress -Activity "Adding to Azure-group" -Status $text -PercentComplete (($ticker/$count)*100)
		Add-MsolGroupMember -GroupObjectId $targetRoomAzure.ObjectId -GroupMemberType User -GroupMemberObjectId $_.ObjectId
		$ticker += 1
	}
	Set-AzureADGroup -ObjectId $targetRoomAzure.ObjectId -Description Now
	#endregion

	$ticker = 1
	#region "Add to Exchange-object"
	$membersAzure | foreach {
		$text = $ticker.ToString()+"/"+$count.ToString()
		Write-Progress -Activity "Adding to Exchange-object" -Status $text -PercentComplete (($ticker/$count)*100)
		Add-MailboxFolderPermission -Identity $targetExchange -AccessRights LimitedDetails -User $_.UserPrincipalName -Confirm:$false > $null
		$ticker += 1
	}
	#endregion
}

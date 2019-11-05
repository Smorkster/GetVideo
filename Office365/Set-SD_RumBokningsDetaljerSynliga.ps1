<#
.Synopsis
	Gör rums kalendarbokningars information synlig
.Description
	Ibland kan ett rums kalendarbokningar visas som enbart "Upptaget". För att korrigera detta behöver inställningen för rummets standardbehörighet korrigeras.
	Ange rummets identitet (namn, mailadress eller annan identifikation).
.Parameter Rum
	Namn eller mailadress för rummet
.Example
	Set-SD_RumBokningsDetaljerSynliga -Rum "RumA"
	Anger att bokningsdetaljerna för rum RumA ska vara synliga för alla användare
#>
function Set-SD_RumBokningsDetaljerSynliga
{
	param(
	[Parameter(Mandatory=$true)]
		$Rum
	)

	if ($room = Get-Mailbox -Identity $Rum)
	{
		$calendar = $Room.DisplayName+":\Kalender"
		Set-MailboxFolderPermission -Identity $calendar -User Standard -AccessRights LimitedDetails
		Write-Host "Bokningsinformation har nu gjorts synlig för $room.DisplayName"
	} else {
		Write-Host "Rum " -NoNewline
		Write-Host $Rum -NoNewline -Foreground Cyan
		Write-Host " finns inte"
	}
}

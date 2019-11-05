<#
.Synopsis
	Ändra texten i rums bokningsbekräftelse
.Description
	Detta ändrar texten i mail får bokningsbekräftelse som skickas ut till användare
	Det ändrar även MailTip, som är vad som visas när objektet laddas in i Till-fältet när bokningen skapas. Texten kommer då visas ovanfår Till-fältet som en notis att det rummet vill informera om något. Fungerar på samma sätt som när autosvarsmeddelande visas innan ett mail skickas.
.Parameter Rum
	Namn eller mailadress får att identifiera rummet
.Parameter Meddelande
	Den text som ska visas i bokningsbekräftelsen
.Example
	Set-SD_RumBekräftelseMeddelande -Rum "RumA" -Meddelande "Rummet är stort"
	Ändrar texten som ska anges när ett rum skickar bekräftelsemail att en bokning har godkänts till "Rummet är stort"
#>
function Set-SD_RumBekräftelseMeddelande
{
	param(
	[Parameter(Mandatory=$true)]
		$Rum,
	[Parameter(Mandatory=$true)]
		$Meddelande
	)
	
	if($room = Get-Mailbox -Identity $Rum)
	{
		Set-CalendarProcessing -Identity $room -AdditionalResponse $Meddelande
		Set-Mailbox -Identity $room -MailTip $Meddelande
		Write-Host "$room.DisplayName har nu uppdaterad bokningsbekräftelse"
	} else {
		Write-Host "Inget rum " -NoNewline
		Write-Host $Rum -NoNewline -Foreground Cyan
		Write-Host " funnet"
	}
}

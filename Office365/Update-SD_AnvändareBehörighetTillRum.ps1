<#
.Synopsis
	Uppdaterar användares behörighet till rum
.Description
	Skapar om behörigheten för en användare till ett rum. Detta kan vara användbart ifall behörigheten inte verkar ha blivit synkroniserad ordentligt, t.ex. att den ligger listad som den ska. Om behörigheten är listad, tas den först bort.
.Parameter Rum
	Namn eller mailadress för rummet
.Parameter id
	id för användare som behöver få behörighet uppdaterad
.Example
	Update-SD_AnvändareBehörighetTillRum -Rum "RumA" -id "ABCD"
	Uppdaterar behörigheten för användare ABCD till rum RumA
#>

function Update-SD_AnvändareBehörighetTillRum
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Rum,
	[Parameter(Mandatory=$true)]
		[string] $id
	)

	Write-Verbose "Hämtar mailbox i Exchange"
	try {
		Write-Verbose "Hämtar AD-objekt för användaren"
		$adUser = Get-ADUser -Identity $id -Properties *
	} catch {
		Write-Host "Användare $id hittades inte i AD"
		return
	}

	try {
		Write-Verbose "Hämtar mailbox för användare"
		$user = Get-Mailbox -Identity $adUser.EmailAddress
	} catch {
		Write-Host "Ingen maillåda hittades för $($adUser.Name)"
		return
	}

	try {
		Write-Verbose "Hämtar mailbox för rummet"
		$room = Get-Mailbox	-Identity $Rum -ErrorAction Stop
	} catch {
		Write-Host "Inget rum hittades med namn $Rum"
		return
	}

	Write-Verbose "Kontrollerar om det redan finns behörighet för användaren i rummet"
	$roomMember = Get-MailboxFolderPermission -Identity $($room.PrimarySmtpAddress)":\Kalender" | ? {$_.User -match $user.DisplayName}
	if($roomMember)
	{
		Write-Verbose "Behörighet fanns redan, tar bort behörigheten"
		Remove-MailboxFolderPermission -Identity $($room.PrimarySmtpAddress)":\Kalender" -User $user.PrimarySmtpAddress -Confirm:$false
	}
	Write-Verbose "Lägger på behörigheten för användaren till rummet"
	Add-MailboxFolderPermission -Identity $($room.PrimarySmtpAddress)":\Kalender" -User $user.PrimarySmtpAddress -AccessRights LimitedDetails > $null
	$bp = (Get-CalendarProcessing -Identity $room.DisplayName).BookInPolicy | select -Unique
	Set-CalendarProcessing -Identity $room.DisplayName -BookInPolicy $bp -AllBookInPolicy:$false
	Write-Host "$adUser.Name har nu bokningsbehörighet för $room.DisplayName"
}

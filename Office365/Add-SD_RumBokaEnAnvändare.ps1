<#
.Synopsis
	Skapa behörighet för användaren att boka rum
.Description
	Lägg in bokningsbehörighet för en användare till ett rum. Skriptet används när synken från ändring i Supportpanelen inte har gått över till Exchange.
.Parameter id
	id för den användare som ska ha behörigheten
.Parameter Rum
	Namn eller identitet på rummet som behörigheten ska skapas på
.Example
	Add-SD_RumBokaEnAnvändare -id "ABCD" -Rum "RumA"
	Skapar behörighet för användare ABCD att skapa bokningar i rum RumA
#>

function Add-SD_RumBokaEnAnvändare
{
	param(
	[Parameter(Mandatory=$true)]
		[String] $id,
	[Parameter(Mandatory=$true)]
		[String] $Rum
	)

	try {
		$RoomObject = Get-Mailbox -Identity $Rum
	} catch [System.Management.Automation.RemoteException] {
		Write-Host "Rum hittades inte"
		return
	}

	try {
		$User = Get-ADUser -Identity $id -Properties *
		if($User.Emailaddress -eq $null) {
			Write-Host "Ingen mailadress registrerad i AD för användaren.`nAvslutar"
			return
		}
	} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
		Write-Host "Användare hittades inte i AD"
		return
	}

	try {
		$UserAccount = Get-Mailbox -Identity $User.Emailaddress
		$BookPolicy = (Get-CalendarProcessing -Identity $RoomObject.Identity).BookInPolicy += $User.Emailaddress | select -Unique
		
		if ($BookPolicy -contains (Get-Mailbox -Identity $User.Emailaddress).LegacyExchangeDN)
		{
			Write-Host $User.Name "är redan behörighet"
		} else {
			Set-CalendarProcessing -Identity $RoomObject.Identity -BookInPolicy $BookPolicy -AllBookInPolicy:$false -WarningAction Stop
			Write-Host $User.Name -NoNewline -Foreground Cyan
			Write-Host " har nu behörighet att boka " -NoNewline
			Write-Host $RoomObject.DisplayName -Foreground Cyan
		}
	} catch [System.Management.Automation.RemoteException] {
		Write-Host "Rum " -NoNewline
		Write-Host $Rum -NoNewline -Foreground Cyan
		Write-Host " hittades inte i Exchange.`nAvslutar"
	}
}

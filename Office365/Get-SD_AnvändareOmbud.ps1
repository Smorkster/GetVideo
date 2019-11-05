<#
.Synopsis
	Hämtar alla ombud för ett konto
.Description
	Hämtar vilka andra användare som har fått behörighet som ombud för angiven användare. De listas sedan per typ av behörighet de har fått, t.ex. för inkorgen eller kalendern.
.Parameter id_Ägare
	id för ägaren av Outlook-kontot
.Example
	Get-SD_Ombud -id_Ägare "ABCD"
	Hämtar alla ombud som skapats till mailkontot för användaren ABCD
#>

function Get-SD_AnvändareOmbud
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id_Ägare
	)
	
	try
	{
		$owner = Get-ADUser -Identity $id_Ägare -Properties *
		$inbox = $owner.EmailAddress+":\Inkorg"
		$calender = $owner.EmailAddress+":\Kalender"

		Write-Host "Behörigheter till Inkorgen:" -Foreground Green
		Get-MailboxFolderPermission -Identity $inbox -ErrorAction Stop | ? { $_.User -notmatch "Standard" -and $_.User -notmatch "Anonymous" } | % { Write-Host $_.User " -> " $_.AccessRights }

		Write-Host "`nBehörigheter till Kalender:" -Foreground Green
		try
		{
			Get-MailboxFolderPermission -Identity $calender -ErrorAction Stop | ? { $_.User -notmatch "Standard" -and $_.User -notmatch "Anonymous" } | % { Write-Host $_.User " -> " $_.AccessRights }
		} catch {
			if ( $_.CategoryInfo -like "*ManagementObjectNotFoundException*" )
			{
				try
				{
					$calender = $owner.EmailAddress+":\Calendar"
					Get-MailboxFolderPermission -Identity $owner.EmailAddress":\Calendar" -ErrorAction Stop | ? { $_.User -notmatch "Standard" -and $_.User -notmatch "Anonymous" } | % { Write-Host $_.User " -> " $_.AccessRights }
				} catch {
					if ( $_.CategoryInfo -like "*ManagementObjectNotFoundException*" )
					{
						Write-Host "Kunde inte hitta kalendern"
					} else {
						$_
					}
				}
			} else {
				$_
			}
		}

		Write-Host "`nDessa har behörighet att skicka mail som ombud:" -Foreground Green
		(Get-Mailbox -Identity $owner.EmailAddress | select GrantSendOnBehalfTo).GrantSendOnBehalfTo

	} catch {
		if ($_.CategoryInfo.Reason -eq "ADIdentityNotFoundException")
		{
			Write-Host "Person med id "$id_Ägare" inte funnen i AD.`nAvslutar" -Foreground Red
			return
		} elseif ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException" -and $_.CategoryInfo.Activity -eq "Get-MailboxFolderPermission") {
			Write-Host "Mailkonto för $($owner.Name) inte funnet" -Foreground Red
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

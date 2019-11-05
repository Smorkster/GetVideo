<#
.Synopsis
	Tar bort en användares profilbild i Office365
.Description
	Tar bort profilbilden från en användares Office365-konto
.Parameter id
	id för användaren
.Example
	Remove-SD_AnvändareIkonfoto -id "ABCD"
	Tar bort profilbild i Office365 för användare ABCD
#>

function Remove-SD_AnvändareIkonfoto
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id
	)
	try {
		$user = Get-ADUser -Identity $id -Properties * -ErrorAction Stop
		$mailbox = Get-Mailbox -Identity $user.EmailAddress -ErrorAction Stop
		Remove-UserPhoto -Identity $id -Confirm -ErrorAction Stop
		Write-Host "Profilbild för $user.Name har nu tagits bort"
	} catch {
		if ($_.CategoryInfo.Reason -eq "ADIdentityNotFoundException")
		{
			Write-Host "Hittade ingen användare med id $id i AD"
		} elseif ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException") {
			if ($_.CategoryInfo.Activity -eq "Get-Mailbox" -xor $_.CategoryInfo.Activity -eq "Remove-UserPhoto")
			{
				Write-Host "Inget mailkonto hittades för $($user.EmailAddress)"
			} else {
				Write-Host "Problem att nå mailkonto"
			}
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

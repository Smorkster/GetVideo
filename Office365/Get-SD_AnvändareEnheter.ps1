<#
.Synopsis
	Hämtar registrerade enheter
.Description
	Hämtar alla enheter registrerade för användaren från Azure
.Parameter id
	id för användaren
.Example
	Get-SD_Ombud -id "ABCD"
#>

function Get-SD_AnvändareEnheter
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id
	)
	
	try
	{
		$user = Get-ADUser -Identity $id -Properties *

		if (($devices = Get-AzureADUserRegisteredDevice -ObjectId (Get-MsolUser -UserPrincipalName $user.Emailaddress).ObjectId).Count -gt 0)
		{
			Write-Host "Följande enheter är kopplade i Azure:"
			foreach ($device in $devices)
			{
				Write-Host "`t $($device.DisplayName)"
			}
		} else {
			Write-Host "Inga enheter registrerade i Azure"
		}
	} catch {
		if ($_.CategoryInfo.Reason -eq "ADIdentityNotFoundException")
		{
			Write-Host "Person med id "$id" inte funnen i AD.`nAvslutar" -Foreground Red
			return
		} elseif ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException" -and $_.CategoryInfo.Activity -eq "Get-MailboxFolderPermission") {
			Write-Host "Mailkonto för $($owner.Name) inte funnet" -Foreground Red
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

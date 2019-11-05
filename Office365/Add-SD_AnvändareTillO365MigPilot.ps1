<#
.Synopsis
	Lägger in en användare i gruppen O365-MigPilots
.Description
	Ifall en användare inte har blivit inlagd i gruppen O365-MigPilots kan det bli problem med att t.ex. logga in.
	Använd då detta skript för att lägga till användaren.
.Parameter id
	id för användaren
.Example
	Add-SD_AnvändareTillO365MigPilot -id "ABCD"
#>

function Add-SD_AnvändareTillO365MigPilot
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id
	)

	try {
		$group = Get-AzureADGroup -SearchString "O365-MigPilots" -ErrorAction Stop
		$User = Get-ADUser -Identity $id -Properties * -ErrorAction Stop

		if($User.EmailAddress -eq $null)
		{
			Write-Host "Ingen mailadress skapad för $id.`nAvslutar"
		} else {
			Write-Verbose "Lägger till användare"
			Add-DistributionGroupMember -Identity $group.ObjectId -Member $User.EmailAddress -BypassSecurityGroupManagerCheck -ErrorAction Stop
			Write-Host "$($User.Name) har nu lagts till i O365-MigPilots" -Foreground Green
		}
	} catch {
		if ($_.CategoryInfo.Reason -eq "ADIdentityNotFoundException")
		{
			Write-Host "Användare hittades inte i AD" -Foreground Red
		} elseif ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException") {
			Write-Host "Användare hittades inte i Azure" -Foreground Red
		} elseif ($_.CategoryInfo.Reason -eq "MemberAlreadyExistsException") {
			Write-Host "Användaren är redan medlem i O365-MigPilots" -Foreground Green
		} else {
			Write-Host "Fel uppstod i körningen:" -Foreground Red
			$_
		}
	}
}

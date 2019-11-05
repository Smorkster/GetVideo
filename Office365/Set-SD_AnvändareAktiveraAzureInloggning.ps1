<#
.Synopsis
	Aktiverar inloggning för Office365-kontot
.Description
	Ändrar status för inloggningsmöjligheten för ett Office365-konto från inaktivt till aktivt
.Parameter id
	id för användaren
.Example
	Set-SD_AnvändareAktiveraAzureInloggning -id "ABCD"
	Aktiverar inloggning i mailen för ABCD
#>

function Set-SD_AnvändareAktiveraAzureInloggning
{
	param(
		[string] $id
	)

	try {
		$adUser = Get-ADUser -Identity $id -Properties * -ErrorAction Stop
		Set-MsolUser -UserPrincipalName $adUser.Emailaddress -BlockCredential $false -ErrorAction Stop
		Write-Host "Office365-konto för $($adUser.Name) har nu öppnats för inloggning"
	} catch {
		if ($_.CategoryInfo.Reason -eq "ADIdentityNotFoundException")
		{
			Write-Host "Hittades inte i AD"
		} elseif ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException") {
			Write-Host "Användare hittades inte i Exchange"
		} elseif ($_.FullyQualifiedErrorId -like "*UserNotFoundException*") {
			Write-Host "Användare hittades inte i Azure"
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

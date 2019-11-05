<#
.Synopsis
	Anger att lösenordet för kontot inte går ut
.Description
	Sätter att lösenordet för konto i Azure inte går ut.
.Parameter id
	id för kontot
.Example
	Set-SD_AnvändarePasswordNeverExpires -id "ABCD"
	Anger att konto för ABCD inte ska gå ut, och lösenordet därför kommer fortsätta gälla tills det byts
#>

function Set-SD_AnvändarePasswordNeverExpires
{
	param(
		[string] $id,
		[string] $Mailadress
	)

	try {
		if ($Mailadress -eq $null)
		{
			$adUser = Get-ADUser -Identity $id -Properties * -ErrorAction Stop
			$Mailadress = Get-Mailbox -Identity $adUser.EmailAddress -ErrorAction Stop
		}
		Set-MsolUser -UserPrincipalName $Mailadress -PasswordNeverExpires $true -ErrorAction Stop
		Write-Host "Lösenordsåterställning har nu inaktiverats för $Mailadress"
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

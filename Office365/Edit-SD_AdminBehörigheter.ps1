<#
.Synopsis
	Lägger till/tar bort full behörighet till ett konto
.Description
	Skapar FullAccess-behörighet för administratör att få tillgång till användares brevlådor.
	När behörighet skapats, sparas användarens mailadress i en fil för att underlätta rensning av behörigheter.
.Parameter Mailadress
	Mailadress för användaren vars konto behörigheten ska kopplas till
.Parameter id
	id för användare vars konto behörigheten ska kopplas till
.Parameter Rensa
	Tar bort behörighet till alla konton där full access har lagts till. Läsning görs från fil.
.Example
	Edit-SD_AdminBehörigheter -Mailadress "test@test.com"
	Lägger till FullAccess-behörighet till konto med mailadress test@test.com
.Example
	Edit-SD_AdminBehörigheter -Rensa
	Läser igenom fil med lista för alla konton där behörighet lagts, och tar bort behörigheten
#>
function Edit-SD_AdminBehörigheter
{
	param(
		[String] $Mailadress,
		[String] $id,
		[switch] $Rensa
	)
	$file = "H:\O365Admin.txt"
	$adminName = Get-ADUser -Identity $env:USERNAME
	$adminUser = $adminName.GivenName  + " " + $adminName.Surname + " (Admin)"
	try
	{
		Write-Verbose "Hämtar ditt adminkonto"
		$adminAccount = Get-Mailbox -Anr $adminUser
	} catch {
		Write-Host "Hittar inget adminkonto. Avslutar" -Foreground Red
		return
	}

	if($Rensa)
	{
		Write-Verbose "Läser fil med konton behörighet har skapats på"
		$konton = Get-Content $file
		if ($konton -ne "")
		{
			$konton | % {
				if ($_ -ne "")
				{
					Remove-MailboxPermission -Identity $_ -User $adminAccount.UserPrincipalName -AccessRights FullAccess -Confirm:$false -WarningAction SilentlyContinue
					Write-Host "Behörighet till $_ borttagen"
				}
			}
			"" > $file
		} else {
			Write-Host "Filen är tom, inga behörigheter att ta bort" -Foreground Cyan
		}
	} else {
		if($id)
		{
			$Mailadress = (Get-ADUser -Identity $id -Properties *).Emailaddress
			if($Mailadress -eq "")
			{
				Write-Host "Ingen mailadress finns för " -NoNewline
				Write-Host $id -NoNewline -Foreground Cyan
				Write-Host " i AD. Avslutar."
				return
			}
		}
		while($Mailadress -eq "")
		{
			$Mailadress = Read-Host "Ange mailadress för kontot du vill få behörighet till"
		}

		if ($konto = Get-Mailbox -Identity $Mailadress -ErrorAction SilentlyContinue)
		{
			try
			{
				Write-Verbose "Lägger till full behörighet på $konto"
				Add-MailboxPermission -Identity $konto.UserPrincipalName -User $adminAccount.UserPrincipalName -AccessRights FullAccess -WarningAction SilentlyContinue > $null
				Add-Content $file $konto.UserPrincipalName
				Write-Host "Lagt till behörighet till konto " -NoNewline
				Write-Host $konto.DisplayName -Foreground Cyan
			} catch {
				Write-Host "Error vid tillägg av behörighet"
			}
		} else {
			Write-Host "Konto med adress "$Mailadress" finns inte i Exchange"
			return
		}
	}
}

<#
.Synopsis
	Lägger till ett autosvarsmeddelande
.Description
	Lägger in ett autosvarsmeddelande på avsedd användare mellan start- och slutdatum. Datum är inte krav. Skulle datum saknas vid körning, är meddelandet aktivt tills det manuellt inaktiveras.
	För att kunna lägga in meddelandet, krävs fullständig behörighet på mailkontot. Detta läggs på i början av skriptet och tas bort när meddelandet är inlagt.
.Parameter id
	id för användaren
.Parameter Meddelande
	Text som ska stå i autosvarsmeddelandet
.Parameter Startdatum
	Startdatum för när autosvarsmeddelande ska börja gälla
.Parameter Slutdatum
	Slutdatum för när autosvarsmeddelande ska sluta gälla
.Example
	Add-SD_AnvändareAutosvar -id "ABCD" -Meddelande "Test" -Startdatum 1970-01-01 -Slutdatum 1970-01-02
	Sätter meddelande "Test" på konto "ABCD" att vara aktivt mellan 1970-01-01 och 1970-01-02
#>

function Add-SD_AnvändareAutosvar
{
    [CmdletBinding()]
	param(
	[Parameter(Mandatory=$true)]
		[string] $id,
	[Parameter(Mandatory=$true)]
		[string] $Meddelande,
	[ValidatePattern("\d{4}[-]\d{2}[-]\d{2}")]
		[string] $Startdatum,
	[ValidatePattern("\d{4}[-]\d{2}[-]\d{2}")]
		[string] $Slutdatum
	)
	Write-Progress -Activity "Skapar autosvar" -Status "Hämtar admin från AD" -PercentComplete ((1/6)*100)
    $adminName = Get-ADUser -Identity $env:USERNAME
	$adminUser = $adminName.GivenName  + " " + $adminName.Surname + " (Admin)"
	try
	{
		Write-Verbose "Hämtar ditt adminkonto"
		Write-Progress -Activity "Skapar autosvar" -Status "Hämtar adminkonto i Exchange" -PercentComplete ((2/6)*100)
		$adminAccount = Get-Mailbox -Anr $adminUser
	} catch {
		Write-Host "Hittar inget adminkonto. Avslutar" -Foreground Red
		return
	}

	try
	{
		Write-Verbose "Hämtar användarkontot"
		Write-Progress -Activity "Skapar autosvar" -Status "Hämtar användares konto i Exchange" -PercentComplete ((3/6)*100)
		$userAccount = Get-Mailbox -Identity (Get-ADUser -Identity $id -Properties *).Emailaddress
	} catch [System.Management.Automation.RemoteException]{
		Write-Host "Inget konto för " -NoNewline
		Write-Host $id -Foreground Cyan
		Write-Host " hittades. Avslutar"
		return
	}

	try {
		Write-Verbose "Skapar tillfällig behörighet till användarkontot"
		Write-Progress -Activity "Skapar autosvar" -Status "Skapar behörighet till användares konto" -PercentComplete ((4/6)*100)
		Add-MailboxPermission -Identity $userAccount.PrimarySmtpAddress -User $adminAccount.PrimarySmtpAddress -AccessRights FullAccess -WarningAction SilentlyContinue > $null
	} catch {
		Write-Host "Kunde inte lägga på full behörighet för adminkonto. Avslutar"
		return
	}
	
	Write-Progress -Activity "Skapar autosvar" -Status "Lägger in autosvarsmeddelande" -PercentComplete ((5/6)*100)
	if(-not $Startdatum)
	{
		$Startdatum = (Get-Date -UFormat "%Y-%m-%d")+" 00:00:00"
		if(-not $Slutdatum)
		{
			Write-Verbose "Lägger in autosvarsmeddelande, från nu och tills det manuellt stängs av."
			Set-MailboxAutoReplyConfiguration -Identity $userAccount.PrimarySmtpAddress -AutoReplyState Enabled -InternalMessage $Meddelande -ExternalMessage $Meddelande -Confirm:$false
		} else {
			$Slutdatum = $Slutdatum+" 22:59:59"
			Write-Verbose "Lägger in autosvarsmeddelande, från nu till $Slutdatum"
			Set-MailboxAutoReplyConfiguration -Identity $userAccount.PrimarySmtpAddress -AutoReplyState Scheduled -StartTime $Startdatum -EndTime $Slutdatum -InternalMessage $Meddelande -ExternalMessage $Meddelande -Confirm:$false
		}
	} else {
		if($Slutdatum)
		{
			$Startdatum = $Startdatum+" 00:00:00"
			$Slutdatum = $Slutdatum+" 22:59:59"
			Write-Verbose "Lägger in autosvarsmeddelande mellan $Startdatum och $Slutdatum"
			Set-MailboxAutoReplyConfiguration -Identity $userAccount.PrimarySmtpAddress -AutoReplyState Scheduled -InternalMessage $Meddelande -ExternalMessage $Meddelande -StartTime $Startdatum -EndTime $Slutdatum -Confirm:$false
		} else {
			Write-Verbose "Lägger in autosvarsmeddelande, från $Startdatum och tills det aktivt stängs av."
			Set-MailboxAutoReplyConfiguration -Identity $userAccount.PrimarySmtpAddress -AutoReplyState Enabled -InternalMessage $Meddelande -ExternalMessage $Meddelande -StartTime $Startdatum -Confirm:$false
		}
	}
	Write-Verbose "Tar bort behörighet från användarkontot"
	Write-Progress -Activity "Skapar autosvar" -Status "Tar bort behörighet från användarkonto" -PercentComplete ((6/6)*100)
	Remove-MailboxPermission -Identity $userAccount.PrimarySmtpAddress -User $adminAccount.PrimarySmtpAddress -AccessRights FullAccess -Confirm:$false
}

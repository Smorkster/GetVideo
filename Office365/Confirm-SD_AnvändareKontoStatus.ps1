<#
.Synopsis
	Kontrollera status på olika delar av ett mailkonto
.Description
	Kontrollerar alla steg för synkronisering och skapande av ett O365-konto. För varje kontroll skrivs en rapport i kommandofönstret.
	Ifall något steg fallerar, kommer skriptet stoppas.
.Parameter id
	id för användaren
	.Parameter AllTests
	Switch för att köra alla kontroller
.Example
	Confirm-SD_AnvändareKontoStatus -id "ABCD"
	Utför tester för att kontollera att mailkonto skapats för användare ABCD. Om något test fallerar, avbryts testningen
.Example
	Confirm-SD_AnvändareKontoStatus -id "ABCD" -AllTests
	Utför alla tester för att kontollera att mailkonto skapats för användare ABCD. Har det inte skapats någon msoluser, kommer dock testningen avbrytas
#>

function Confirm-SD_AnvändareKontoStatus
{
	param(
	[Parameter(Mandatory=$true)]
		[String] $id,
		[switch] $AllTests
		)

	try
	{
		$user = Get-ADUser -Identity $id -Properties *
	} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
		Write-Host "AD-konto har inte skapats`nAlla tester avslutas."
		return
	} catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
		Write-Host "Kan inte ansluta till AD-server. Läs om ActiveDirectory modulen."
		return
	}
	$fail = $false

	if($user.EmailAddress -eq $null)
	{
		Write-Host "Mailattributet ej synkroniserat till AD" -Foreground Red
		$fail = $true
		if(-not $AllTests)
		{
			return
		}
	} else {
		Write-Host "Mailattribut finns i AD" -Foreground Green
	}

	if(-not $user.Enabled)
	{
		Write-Host "AD-konto ej aktivt (Disabled)" -Foreground Red
		$fail = $true
		if(-not $AllTests)
		{
			return
		}
	} else {
		Write-Host "AD-konto är aktivt" -Foreground Green
	}

	if($user.LockedOut)
	{
		Write-Host "AD-konto är låst" -Foreground Red
		$fail = $true
		if(-not $AllTests)
		{
			return
		}
	} else {
		Write-Host "AD-konto är inte låst" -Foreground Green
	}

	if ($user.DistinguishedName -like "*OU=KundC*")
	{
		Write-Host "Anställd på annan plats, ignorerar msExchMailboxGuid" -Foreground Green
		$
	} else {
		if($user.msExchMailboxGuid -ne $null)
		{
			Write-Host "msExchMailboxGuid är inte tomt i AD" -Foreground Red
			$fail = $true
			if(-not $AllTests)
			{
				return
			}
		} else {
			Write-Host "msExchMailboxGuid är tomt i AD" -Foreground Green
		}
	}

	try
	{
		$userAzure = Get-MsolUser -UserPrincipalName $user.EmailAddress -ErrorAction Stop
	} catch {
		Write-Host "O365-konto har inte skapats. Avbryter resten av testerna." -Foreground Red
		return
	}

	try
	{
		#region Azure-login
		if ($userAzure.BlockCredential)
		{
			Write-Host "Inloggning med O365-konto inaktiverat" -Foreground Red
			$fail = $true
		} else {
			Write-Host "Inloggning med O365-konto aktiverat" -Foreground Green
		}
		#endregion

		$haveLicens = $false
		$licenses = $userAzure.Licenses | select accountskuid | % {$_ -match "pack"}
		$userGroups = Get-AzureADUser -Filter "UserPrincipalName eq '$($user.EmailAddress)'" | Get-AzureADUserMembership

		#region MigPilot
		if(($userGroups | ? {$_.DisplayName -like "O365-MigPilots"}) -eq $null)
		{
			Write-Host "Är inte medlem i O365-MigPilots" -Foreground Red
			$fail = $true
			if(-not $AllTests)
			{
				return
			}
		} else {Write-Host "Är medlem i O365-MigPilots" -Foreground Green}
		#endregion

		#region Tnf-user
		if(($userGroups | ? {$_.DisplayName -like "KundC"}) -eq $null)
		{
			foreach($l in $licenses)
			{
				if($l -eq $true)
				{
					$haveLicens = $true
				}
			}
			if(-not $haveLicens)
			{
				Write-Host "E3-licens saknas" -Foreground Red
				$fail = $true
				if(-not $AllTests)
				{
					return
				}
			} else {Write-Host "E3-licens finns" -Foreground Green}
		} else {
			Write-Host "Anställd på annan plats, tilldelas ingen licens." -Foreground Green
		}
		#endregion

		#region Exchange
		$userExchange = Get-Mailbox -Identity $user.EmailAddress -ErrorAction SilentlyContinue
		if($userExchange -eq $null)
		{
			Write-Host "Mailbox inte skapad i Exchange" -Foreground Red
			$fail = $true
			if(-not $AllTests)
			{
				return
			}
		} else {
			Write-Host "Mailbox skapad i Exchange" -Foreground Green
		}
		#endregion

		#region Logins
		Search-UnifiedAuditLog -StartDate ([DateTime]::Today.AddDays(-10)) -EndDate ([DateTime]::Now) -UserIds $user.EmailAddress -Operations "UserLoggedIn" -AsJob | Out-Null
		Write-Host "Senast lyckade inloggning: " -NoNewline
		$successfullLoggins = Get-Job | Receive-Job
		if ($successfullLoggins.Count -gt 0)
		{
			$lastlogon = ($successfullLoggins[0].AuditData | ConvertFrom-Json).CreationTime

			foreach($logon in $successfullLoggins) {
				if (($logon.AuditData | ConvertFrom-Json).CreationTime -gt $lastlogon)
				{
					$lastlogon = ($logon.AuditData | ConvertFrom-Json).CreationTime
				}
			}

			$lastlogon = [datetime]::Parse($lastlogon).ToUniversalTime()
			if ($lastlogon.Date -eq [datetime]::Today.AddDays(-1)) {
				if (($lastlogon.Hour + 1) -lt 10)
				{
					$hour = "0"+($lastlogon.Hour + 1)
				} else {$hour = $lastlogon.Hour}
				if ($lastlogon.Minute -lt 10)
				{
					$minute = "0"+($lastlogon + 1)
				} else {$minute = $lastlogon.Minute}
				Write-Host "Igår"$hour":"$minute -Foreground Green
			}
			elseif ($lastlogon.Date -eq [datetime]::Today) {
				if (($lastlogon.Hour + 1) -lt 10)
				{
					$hour = "0"+($lastlogon.Hour + 1)
				} else {$hour = $lastlogon.Hour}
				if ($lastlogon.Minute -lt 10)
				{
					$minute = "0"+($lastlogon.Minute + 1)
				} else {$minute = $lastlogon.Minute}
				Write-Host "Idag"$hour":"$minute -Foreground Green
			}
			else {Write-Host $lastlogon.DateTime -Foreground Green}
		} else {
			Write-Host "Inga inloggningar registrerade"
		}
		#endregion
		
		#region Devices
		if (($devices = Get-AzureADUserRegisteredDevice -ObjectId $userAzure.ObjectId).Count -gt 0)
		{
			Write-Host "Följande enheter är kopplade i Azure:"
			foreach ($device in $devices)
			{
				Write-Host "`t $($device.DisplayName)"
			}
		} else {
			Write-Host "Inga enheter registrerade i Azure"
		}
		#endregion

	} catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
		Write-Host "O365-konto har inte skapats. Avbryter resten av testerna." -Foreground Red
		$fail = $true
		if(-not $AllTests)
		{
			return
		}
	}

	if(-not $fail)
	{
		Write-Host "Allt ska fungera"
	}
}

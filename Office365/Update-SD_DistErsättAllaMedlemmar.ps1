<#
.Synopsis
	Ersätter alla medlemmar i distributionslista
.Description
	Tar först bort alla medlemmar i en distributionslista, läser sedan in adresser från Excel-fil och lägger in dessa som nya medlemmar.
	När skriptet startar, öppnas filen i Excel så att den kan editeras. När filen är sparad, fortsätter skriptet efter användaren har tryck på Enter.
	Om en extern mailadress inte finns i Exchange, skapas ett kontakt-objekt med adressen. Adressen läggs sedan till i distributionslistan. Om det är en intern mailadress som inte finns, hoppas adressen över.

	Varje rad i filen ska innehålla en mailadress.
.Example
	Update-SD_DistErsättAllaMedlemmar -DistLista "Dist Lista"
	Raderar alla existerande medlemmar i distributionslista 'Dist Lista' och lägger in alla personer i Excel-filen som nya medlemmar
#>

function Update-SD_DistErsättAllaMedlemmar
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $DistLista
	)

	#Variables
	Write-Host "Öppnar Excel-fil. Editera adresser som ska läggas till/tas bort. Stäng sedan Excel för att fortsätta." -Foreground Cyan
	$fil = "G:\\\Epost & Skype\Powershell\FilerTillSkripten\Ersättare distributionslista.csv"
	$Excel = New-Object -ComObject Excel.Application
	$Excel.Visible = $true
	$temp = $Excel.Workbooks.Open($fil)
	$ticker = 1
	Read-Host "Fortsätt genom att trycka Enter..."

	$newMembers = Get-Content -Path $fil

	try {
		$distList = Get-DistributionGroup -Identity $DistLista -ErrorAction Stop
	} catch {
		Write-Host "Ingen distributionslista med namn $DistLista hittades.`nAvslutar"
		return
	}

	$currentMembers = Get-DistributionGroupMember -Identity $distList.Identity
	foreach ($member in $currentMembers)
	{
		Write-Progress -Activity "Tar bort medlem $ticker av $($currentMembers.Count)" -PercentComplete (($ticker/$currentMembers.Count)*100)
		Remove-DistributionGroupMember -Identity $distList.Identity -Member $member.PrimarySMTPAddress -Confirm:$false
		$ticker++
	}
	Write-Progress -Activity "Tar bort medlem" -Completed

	$ticker = 1
	$newMembers | foreach {
		$ticker = $ticker + 1
		$emailToAdd = $_.Trim()
		Write-Progress -Activity "Lägger till medlemmar $ticker av $($currentMembers.Count)" -PercentComplete (($ticker/$currentMembers.Count)*100)
		Write-Host "Lägger in $emailToAdd"

		#region Create contact object
		if((Get-Mailbox -Identity $emailToAdd -ErrorAction SilentlyContinue) -or (Get-Contact -Identity $emailToAdd -ErrorAction SilentlyContinue))
		{
			Write-Host "`tAdress finns i Exchange." -Foreground Green
		} else {
			Write-Host "`tInget kontaktobjekt hittades i Exchange, skapar" -Foreground Cyan
			New-MailContact -Name $emailToAdd -ExternalEmailAddress $emailToAdd | Out-Null
			Set-MailContact -Identity $emailToAdd -HiddenFromAddressListsEnabled $true | Out-Null
			Write-Host "`tKontaktobjekt skapat." -Foreground Green
		}
		#endregion Create contact object

		try { Add-DistributionGroupMember -Identity $distList.Identity -Member $emailToAdd -ErrorAction Stop }
		catch {
			if( $_.CategoryInfo.Reason -eq "MemberAlreadyExistsException") {
				Write-Host "Finns redan i distributionslistan"-Foreground Red
			}
		}

		Write-Host "Klar`n" -Foreground Green
	}

	$Excel.Workbooks.Close()
	$Excel.Quit()
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($temp) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null
}

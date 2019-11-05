<#
.Synopsis
	Lägger till/tar bort användare för behörighet att boka i ett eller flera rum.
.Description
	En batch-körning för att lägga in eller ta bort flera användare i flera rum. Användarna och rummen läses in från två filer som öppnas i början av skriptet.
	Varje användare från filen AddUserToRoomBookUsers.txt läggs in i varje rum från filen AddUserToRoomBookGroups.txt
.Parameter Remove
	Parameter för att ange ifall användarna ska tas bort.
.Example
	Add-SD_RumBokaFleraAnvändare
	Lägger in varje användare i varje rum
.Example
	Add-SD_RumBokaFleraAnvändare -Remove
	Tar bort varje användare från varje rum
#>

function Add-SD_RumBokaFleraAnvändare
{
	param(
		[switch] $Remove
	)

	#Variables
	$User = 0
	$Target = 0
	$Failed = @()
	$tickerTotal = 1
	$tickerUser = 1

	$fileUsers = "G:\\\Epost & Skype\Powershell\FilerTillSkripten\AddUserToRoomBookUsers.csv"
	$Excel = New-Object -ComObject Excel.Application
	$Excel.Visible = $true
	$temp = $Excel.Workbooks.Open($fileUsers)
	Read-Host "Editera filen för användare och tryck sedan Enter"
	$fileGroups = "G:\\\Epost & Skype\Powershell\FilerTillSkripten\AddUserToRoomBookGroups.csv"
	$Excel.Visible = $true
	$temp2 = $Excel.Workbooks.Open($fileGroups)
	Read-Host "Editera filen för grupper/rum och tryck sedan Enter"

	$InputUsers = Get-Content -Path $fileUsers
	$InputGroups = Get-Content -Path $fileGroups
	$numGroups = $InputGroups.Count
	$numUsers = $InputUsers.Count
	$numberOfEntries = $numGroups * $numUsers
	$Excel.Workbooks.Close()
	$Excel.Quit()
	$WarningPreference = "SilentlyContinue"

	$InputUsers | foreach {
		if ($User = Get-Mailbox -Identity $_.Trim() -ErrorAction SilentlyContinue)
		{
			Write-Host "($($tickerUser)/$($numUsers)) User - " -Foreground Yellow -NoNewline
			Write-Host $_ -Foreground Cyan

			$InputGroups | foreach {
				$room = $_.Trim()
				$name = "Res-"+$room+"-Book"
				$eRoom = $room+":\Kalender"
				$policy = (Get-CalendarProcessing -Identity $room).BookInPolicy
				$MsolUser = Get-MsolUser -UserPrincipalName $User.PrimarySMTPAddress
				if ($Target = (Get-MsolGroup -MaxResults 100000 -SearchString $name -ErrorAction Stop).ObjectID){

					if ($Remove)
					{
					#region Remove user
						Write-Host "($($tickerTotal)/$($numberOfEntries)) `tRemoving from..." -Foreground Yellow -NoNewline
						Write-Host $room -Foreground Cyan -NoNewline
						try {
							Remove-MsolGroupMember -GroupObjectID $Target -GroupMemberType 'User' -GroupMemberObjectId $MsolUser.ObjectId -ErrorAction SilentlyContinue
							Write-Host " ." -NoNewline -Foreground Green
							if($policy -contains $User.LegacyExchangeDN)
							{
								$policy = $policy | ? {$_ -ne $User.LegacyExchangeDN}
								Set-CalendarProcessing -Identity $room -AllBookInPolicy:$false -BookInPolicy $policy -ErrorAction SilentlyContinue
								Write-Host "." -NoNewline -Foreground Green
							}
							Remove-MailboxFolderPermission -Identity $eRoom -User $User.PrimarySMTPAddress | Out-Null
							Write-Host "." -NoNewline -Foreground Green
						} catch {
							if($_ -like "*Åtkomst nekad.*") {
								Write-Host "Anslutning till Exchange har tappats. Återanslut.`nAvslutar skriptet"
								exit
							}
						}
					#endregion
					} else {
					#region Add user
						Write-Host "($($tickerTotal)/$($numberOfEntries)) `tAdding to " -Foreground Yellow -NoNewline
						Write-Host $_ -Foreground Cyan -NoNewline
						try {
							Add-MsolGroupMember -GroupObjectID $Target -GroupMemberType 'User' -GroupMemberObjectId $MsolUser.ObjectId -ErrorAction SilentlyContinue
							Write-Host "." -NoNewline -Foreground Green
							if($policy -notcontains $User.LegacyExchangeDN)
							{
								$policy += $User.LegacyExchangeDN
								Set-CalendarProcessing -Identity $room -AllBookInPolicy:$false -BookInPolicy $policy -ErrorAction SilentlyContinue
								Write-Host "." -NoNewline -Foreground Green
							}
							Add-MailboxFolderPermission -Identity $eRoom -AccessRights LimitedDetails -Confirm:$false -User $User.PrimarySMTPAddress -ErrorAction SilentlyContinue | Out-Null
							Write-Host "." -NoNewline -Foreground Green
						} catch {
							if ($_ -like "*Åtkomst nekad.*") {
								Write-Host "Anslutning till Exchange har tappats. Återanslut.`nAvslutar skriptet"
								exit
							}
						}
					#endregion
					}

					Set-MsolGroup -ObjectID $Target -Description "Now"
					Write-Host "." -NoNewline -Foreground Green
					Write-Host " Done" -Foreground Green
				} else {
					Write-Host "Group" $_ "not found..." -Foreground Red
				}
			$tickerTotal = $tickerTotal + 1
			}
		} else {
			$Failed += $_
			Write-Host "User $_ not found. Skipping." -Foreground Red
		}
		$tickerUser = $tickerUser + 1
		Write-Host "`n"
		try {$Error[0] = ""} catch {}
	}
	if($Failed.Count -gt 0)
	{
		Write-Host "Dessa kunde inte " -NoNewline
		if($Remove)
		{
			Write-Host "tas bort"
		} else {
			Write-Host "läggas till i någon grupp:"
		}
		$Failed
	}
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($temp2) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($temp) | Out-Null
	[System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null
}

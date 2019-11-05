<#
.Synopsis
	Lägg in en/flera resurser eller rum i en administrations-/Azuregrupp
.Description
	Skriptet används för att lägga in Azure-objekt till en administrationsgrupp i Azure.
	Använder ingen logik för att särskilja grupper, så om flera objekt har samma början i namnet, t.ex. samma organisation och lokalitet, kommer samtliga objekt placeras i administrationsgruppen.
.Parameter ResursNamn
	Namn/mailadress för resursen/rummet
.Parameter GruppNamn
	Namn på gruppen som resurserna/rummen ska läggas in i
.Example
	Add-SD_ResursTillGrupp -ResursNamn "RumA" -GruppNamn "GruppA"
	Rum och resurser flyttas till en grupp genom att söka på "RumA" och ange gruppnamn "GruppA"
#>

function Add-SD_ResursTillGrupp
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $ResursNamn,
	[Parameter(Mandatory=$true)]
		[string] $GruppNamn
	)

	try {
		$rooms = Get-Mailbox -Identity "$ResursNamn*" -Filter {ResourceType -eq "Room"}
		$equipments = Get-Mailbox -Identity "$ResursNamn*" -Filter {ResourceType -eq "Equipment"}
		$groupObjectID = Get-MsolGroup -SearchString $GruppNamn

		if($groupObjectID -eq $null)
		{
			Write-Host "Ingen grupp med namn $GruppNamn hittades.`nAvslutar"
		} else {
			$rooms | % {Get-MsolGroup -SearchString "res-$_-admins" -ErrorAction Stop} | % { Add-MsolGroupMember -GroupObjectId $groupObjectID.ID -GroupMemberType Group -GroupMemberObjectId $_.ObjectID -ErrorAction Stop }
			$equipments | % {Get-MsolGroup -SearchString "res-$_-admins" -ErrorAction Stop} | % { Add-MsolGroupMember -GroupObjectId $groupObjectID.ID -GroupMemberType Group -GroupMemberObjectId $_.ObjectID -ErrorAction Stop }
		}
	} catch {
		if ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException")
		{
			Write-Host "Rum $ResursNamn hittades inte"
		} elseif ($_.CategoryInfo.Reason -eq "MicrosoftOnlineException") {
			Write-Host "Grupp hittades inte i Azure"
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

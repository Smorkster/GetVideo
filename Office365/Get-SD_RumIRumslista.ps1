<#
.Synopsis
	Hämtar alla rum i en rumslista
.Description
	Hämtar alla rum i angiven rumslista. Om det hittas flera rumslistor med namn som liknar vad som angivits, lista de och användaren får ange vilken rumslista som ska användas
.Parameter Rumslista
	Namn på rumslista att visa
.Example
	Get-SD_RumIRumslista -Rumslista "ListA"
	Hämtar alla rum som kopplats till rumslistan ListA
#>

function Get-SD_RumIRumslista
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Rumslista
	)

	try {
		$searchstring = "*" + $Rumslista + "*"
		$groups = Get-DistributionGroup -Filter {RecipientTypeDetails -eq "RoomList"} | ? {$_.DisplayName -like $searchstring}
		if($groups.Count -gt 1)
		{
			Write-Host "Hittade ingen rumslista med namnet $Rumslista.`nAvslutar"
		} elseif ($groups.Count -gt 1) {
			$ticker = 1
			Write-Host "Olika rumslistor hittades, välj vilken från listan:"
			foreach($i in $groups)
			{
				Write-Host $ticker $i.DisplayName $i.DistiguishedName
				$ticker = $ticker + 1
			}
			$index = Read-Host "Nummer"
			$group = $groups[$index-1]
		} else {
			$group = $groups
		}

		Write-Host "Visar för " $group
		Get-DistributionGroupMember -Identity $group.DisplayName -ErrorAction Stop | sort DisplayName | ft DisplayName
	} catch {
		if ($_.CategoryInfo.Reason -eq "ManagementObjectNotFoundException") {
			Write-Host "Ingen rumslista med namn $Rumslista hittades"
		} else {
			Write-Host "Fel uppstod i körningen:"
			$_
		}
	}
}

<#
.Synopsis
	Sök efter Azure-grupper för angiven organisation som inte är medlemmar i grupp för Supportpanelen.
.Description
	Hittar alla grupper i Azure, inom angiven organisation, som inte har lagts in som medlem i relaterad grupp för Supportpanelen. Val av grupp görs i början av skriptet genom en numrerad lista.
#>

function Get-SD_GrupperEjBundnaTillSupportpanelen
{
	$ticker = 1
	$groups = Get-AzureADGroup -SearchString "secgroup-supportpanel" | ? {$_.DisplayName -ne "secgroup-supportpanel" -and $_.DisplayName -ne "secgroup-supportpanel-group1"}
	foreach($i in $groups)
	{
		Write-Host $ticker $i.DisplayName
		$ticker = $ticker + 1
	}
	$index = Read-Host "Nummer för grupp"
	$id = $groups[$index-1].ObjectId

	# Hämta alla medlemmar i gruppen
	Write-Host "`nHämtar information..." -ForegroundColor Cyan
	$sgGruppen = Get-MsolGroupMember -GroupObjectId $id -All | ? {$_.GroupMemberType -ne "User"}
	Write-Host $sgGruppen.Count "Medlemsobjekt i" $groups[$index-1].DisplayName

	$organisation = (Get-MsolGroup -ObjectId $id).displayname -split "-" | select -Last 1

	# Hämta alla skapade funktionsbrevlådor för organisationen
	$funkar = Get-AzureADGroup -SearchString "mb-$organisation" -All 1 | ? {$_.DisplayName -match "-admins"}
	Write-Host $funkar.Count "Funktionsbrevlådor"

	# Hämta alla skapade distributionslistor för organisationen
	$distor = Get-AzureADGroup -SearchString "dl-$organisation" -All 1 | ? {$_.DisplayName -match "-admins"}
	Write-Host $distor.Count "Distributionslistor"

	# Hämta alla skapade rum och resurser för organisationen
	$resar = Get-AzureADGroup -SearchString "res-$organisation" -All 1 | ? {$_.DisplayName -match "-admins"}
	Write-Host $resar.Count "Rum / resurser"

	$notmember = @()

	Write-Host "Kontrollerar funktionsbrevlådor" -ForegroundColor Cyan
	foreach ($f in $funkar) {
		if ( ($sgGruppen | ? {$_.DisplayName -match $f.DisplayName}).Count -eq 0 )
		{
			$notmember += $f
		}
	}
	Write-Host "Kontrollerar distributionslistor" -ForegroundColor Cyan
	foreach ($d in $distor) {
		if ( ($sgGruppen | ? {$_.DisplayName -match $d.DisplayName}).Count -eq 0 )
		{
			$notmember += $d
		}
	}
	Write-Host "Kontrollerar rum och resurser" -ForegroundColor Cyan
	foreach ($r in $resar) {
		if ( ($sgGruppen | ? {$_.DisplayName -match (($r.DisplayName).split("(") | select -First 1)}).Count -eq 0 )
		{
			$notmember += $r
		}
	}

	Write-Host $notmember.Count "grupper funna som inte är medlemmar i Supportpanelen för"$groups[$index-1].DisplayName":"
	$notmember | ft DisplayName
	
	if($notmember.Count -gt 0)
	{
		$a = Read-Host "Lägga till grupperna i Supportpanelen? (Y/N)"
		if ($a -eq "Y")
		{
			$ticker = 1
			$tot = $notmember.Count
			foreach ($g in $notmember)
			{
				Write-Host $ticker "/" $tot
				try {
					Add-AzureADGroupMember -ObjectId $id -RefObjectId $g.ObjectId
				} catch {
					if($Error[0] -match "already exist for the following modified properties")
					{
						Write-Host "Redan medlem" -ForegroundColor Red
					} else {
						$Error[0]
					}
				}
				$ticker = $ticker + 1
			}
			Set-AzureADGroup -ObjectId $id -Description Now
		}
	}
}

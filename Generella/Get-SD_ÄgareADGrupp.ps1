<#
.Synopsis
	Hämta ägare av AD-grupp
.Description
	Hämtar ägare av en AD-grupp från AD
.Parameter GruppNamn
	Namn på AD-grupp
.Example
	Get-SD_ÄgareADGrupp -GruppNamn "gruppnamn"
#>

function Get-SD_ÄgareADGrupp
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $GruppNamn
	)

	try {
		$group = Get-ADGroup -Filter "Name -like '*$GruppNamn*' -and Name -like '*User*'"
	} catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
		Write-Host "Ingen AD-grupp funnen med namn " -NoNewline
		Write-Host $GruppNamn -Foreground Cyan -NoNewline
		Write-Host " funnen"
		return
	}
	Write-Verbose $group.Count
	if($group.Count -gt 1)
	{
		Write-Host "Flera grupper med liknande namn hittades. Ange vilken i listan nedan."
		$index=1
		foreach($item in $list)
		{
			Write-Host $index " " $item.Name
			$index = $index + 1
		}
		$number = Read-Host "Ange nummer för avsett gruppnamn"
		$s = $group[$number].Name
	} elseif($group.Count -eq 0) {
		Write-Host "Ingen AD-grupp funnen med namn " -NoNewline
		Write-Host $GruppNamn -Foreground Cyan -NoNewline
		Write-Host " funnen"
		return
	} else {
		$s = $group.Name
	}
	Get-ADGroup -Identity $s -Properties ManagedBy | ft @{Name='Ägare'; Expression={(Get-ADUser $_.managedBy).Name}}
}

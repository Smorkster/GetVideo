<#
.Synopsis
	Döp om en funktionsbrevlåda
.Description
	Döper om en funktionsbrevlåda och byter mailadress. Namn och adress måste följa namnstandarden. Ingen kontroll av detta görs dock.
.Parameter OldName
	Det nuvarande namnet på funktionsbrevlådan
.Parameter NewName
	Det nya namnet på funktionsbrevlådan. Måste följa nuvarande namnstandard.
.Parameter OldEmail
	Den gamla mailadressen för funktionsbrevlådan
.Parameter NewEmail
	Den nya mailadressen för funktionsbrevlådan. Måste följa nuvarande namnstandard.
.Example
	Rename-SD_Funk -OldName "OldName" -NewName "NewName" -OldEmail "oldname@test.com" -NewEmail "newname@test.com"
	Döper om funktionsbrevlådan OldName och ger den det nya namnet NewName samt byter mailadress från oldname@test.com till newname@test.com
#>

function Rename-SD_Funk
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $OldName,
	[Parameter(Mandatory=$true)]
		[string] $NewName,
	[Parameter(Mandatory=$true)]
		[string] $OldEmail,
		[Parameter(Mandatory=$true)]
		[string] $NewEmail
	)

	#region Get objects
	$OldName = "*"+$OldName+"*"
	$foundBoxes = Get-Mailbox $OldName
	if ($foundBoxes.Count -gt 1)
	{
		Write-Host "`nFler än en funktionsbrevlåda hittades. Välj i listan:"
		$listTicker = 1
		foreach ($mail in $foundBoxes)
		{
			Write-Host $listTicker "-" $mail.DisplayName
			$listTicker += 1
		}
		$answer = Read-Host "Vilken funktionsbrevlåda ska ändras?"
		while ($answer -lt 1 -or $answer -gt $foundBoxes.Count)
		{
			$answer = Read-Host "Vilken funktionsbrevlåda ska ändras?"
		}
		$Mailbox = $foundBoxes[$answer-1]
	} elseif ($foundBoxes.Count -lt 1) {
		Write-Host "Ingen funktionsbrevlåda hittades.`nAvslutar"
		return
	} else {
		$Mailbox = $foundBoxes
	}
	$azureName1 = "MB-"+$Mailbox.DisplayName+"-Admins"
	$azureName2 = "MB-"+$Mailbox.DisplayName+"-Full"
	$azureName3 = "MB-"+$Mailbox.DisplayName+"-Read"

	#endregion Get objects

	Write-Host "Changing email from $OldEmail to $NewEmail" -Foreground Yellow

	#region Exchange
	Set-Mailbox -Identity $Mailbox.PrimarySMTPAddress -WindowsEmailAddress $NewEmail -Name $NewName -DisplayName $NewName -EmailAddresses @{add="smtp:$oldemail"}
	#endregion Exchange

	#region Azure
	$azureGroupAdmins = Get-MsolGroup -SearchString $azureGroupAdmins
	$newAzureGroupNameAdmins = "MB-"+$newname+"-Admins"
	$azureGroupFull = Get-MsolGroup -SearchString $azureGroupFull
	$newAzureGroupNameFull = "MB-"+$newname+"-Full"
	$azureGroupRead = Get-MsolGroup -SearchString $azureGroupRead
	$newAzureGroupNameRead = "MB-"+$newname+"-Read"

	Set-MsolGroup -ObjectId $azureGroupAdmins.ObjectId -DisplayName $newAzureGroupNameAdmins -Description Now
	Set-MsolGroup -ObjectId $azureGroupRead.ObjectId -DisplayName $newAzureGroupNameRead -Description Now
	Set-MsolGroup -ObjectId $azureGroupFull.ObjectId -DisplayName $newAzureGroupNameFull -Description Now
	#endregion Azure
}

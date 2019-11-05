<#
.Synopsis
	DÃ¶p om en distributionslista
.Description
	DÃ¶per om en distributionslista och byter mailadress. Namn och adress mÃ¥ste fÃ¶lja namnstandarden. Ingen kontroll av detta gÃ¶rs dock.
.Parameter OldName
	Det nuvarande namnet pÃ¥ distributionslistan
.Parameter NewName
	Det nya namnet pÃ¥ distributionslistan. MÃ¥ste fÃ¶lja nuvarande namnstandard.
.Parameter OldEmail
	Den gamla mailadressen fÃ¶r distributionslistan
.Parameter NewEmail
	Den nya mailadressen fÃ¶r distributionslistan. MÃ¥ste fÃ¶lja nuvarande namnstandard.
.Example
	Rename-SD_Dist -OldName "OldName" -NewName "NewName" -OldEmail "oldname@test.com" -NewEmail "newname@test.com"
	DÃ¶per om distributionslistan OldName och ger den det nya namnet NewName samt byter mailadress frÃ¥n oldname@test.com till newname@test.com
#>

function Rename-SD_Dist
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

	$Groups = Get-MsolGroup -SearchString DL-$OldName
	$Mailbox = Get-DistributionGroup $OldName

	Write-Host "Changing email from $OldEmail to $NewEmail" -Foreground Yellow
	Set-DistributionGroup -Identity $OldEmail -WindowsEmailAddress $NewEmail -DisplayName $NewName #-Name $NewName

	$Groups | foreach {
		$OldGroup = $_
		$NewGroup = $OldGroup.DisplayName -replace ($OldName, $NewName)

		Write-Host "Renaming $OldGroup.DisplayName to $NewGroup..." -Foreground Yellow
		Set-MsolGroup -ObjectId $OldGroup.ObjectId -DisplayName $NewGroup -Description Now
	}
}

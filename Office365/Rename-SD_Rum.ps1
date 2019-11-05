<#
.Synopsis
	Döp om ett rum
.Description
	Döper om ett rum och byter mailadress. Namn och adress måste följa namnstandarden. Ingen kontroll av detta görs dock.
.Parameter OldName
	Det nuvarande namnet på rummet
.Parameter NewName
	Det nya namnet på rummet. Måste följa nuvarande namnstandard.
.Parameter OldEmail
	Den gamla mailadressen för rummet
.Parameter NewEmail
	Den nya mailadressen för rummet. Måste följa nuvarande namnstandard.
.Example
	Rename-SD_Rum -OldName "OldName" -NewName "NewName" -OldEmail "oldname@test.com" -NewEmail "newname@test.com"
	Döper om rummet OldName och ger den det nya namnet NewName samt byter mailadress från oldname@test.com till newname@test.com
#>

function Rename-SD_Rum
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

	$Groups = Get-MsolGroup -SearchString RES-$OldName
	$Mailbox = Get-Mailbox $OldName

	Write-Host "Byter mailadress " -NoNewline
	Write-Host $OldEmail -NoNewline -Foreground Cyan
	Write-Host " till " -NoNewline
	Write-Host $NewEmail -Foreground Cyan
	Set-Mailbox -Identity $OldEmail -WindowsEmailAddress $NewEmail -Name $NewName -DisplayName $NewName

	$Groups | foreach {
		$OldGroup = $_
		$NewGroup = $OldGroup.DisplayName -replace ($OldName, $NewName)

		Write-Host "Byter namn " -NoNewline
		Write-Host $OldGroup.DisplayName -NoNewline -Foreground Cyan
		Write-Host " till " -NoNewline
		Write-Host $NewGroup -Foreground Cyan
		Set-MsolGroup -ObjectId $OldGroup.ObjectId -DisplayName $NewGroup -Description Now
	}
}

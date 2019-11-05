<#
.Synopsis
	Vilken property innehåller givet värde
.Description
	Söker igenom ett objekt efter en property som innehåller givet sökord och returnerar namnet på den/de propertyn.
.Parameter Objekt
	Det objekt som ska genomsökas
.Parameter SökOrd
	Det värde som ska sökas efter
.Example
	Get-PropertyNamnFrånVärde -Objekt $a -SökOrd "Test"
#>
function Get-SD_PropertyNamnFrånVärde
{
	param(
	[Parameter(Mandatory=$true)]
		[PSCustomObject] $Objekt,
	[Parameter(Mandatory=$true)]
		[string] $SökOrd
	)

	$SökOrd = "*"+$SökOrd+"*"
	$Objekt.PSObject.Properties | % { if ($_.Value -like $SökOrd) {$_.Name}}
}

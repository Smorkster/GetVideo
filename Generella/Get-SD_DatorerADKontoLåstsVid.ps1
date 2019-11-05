<#
.Synopsis
	Hitta vilken dator ett konto har blivit låst vid
.Description
	Söker igenom låsningsloggarna och listar alla datorer som ett konto har blivit låst vid och listar dem
.Parameter id
	ID för den användare som har fått sitt konto låst
.Example
	Get-SD_DatorerADKontoLåstsVid -id "ABCD"
#>

function Get-SD_DatorerADKontoLåstsVid
{
	param(
	[Parameter(Mandatory=$true)]
		[String] $id
	)

	$result = Get-ChildItem G:\\LockedOut_Log -Filter '*.txt' | cat | ? {($_ -split '\s+')[2] -like "*$id*"} | % {($_ -split '\s+')[0] + " " + ($_ -split '\s+')[1] + " " + ($_ -split '\s+')[3]} | sort
	
	if($result.Count -eq 0)
	{
		Write-Host "Ingen information om låsning för $id hittades"
	} else {
		Write-Host "$id blev låst på följande datorer:"
		$result
	}
}

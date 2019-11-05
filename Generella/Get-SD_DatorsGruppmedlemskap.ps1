<#
.Synopsis
	Lista AD-grupper fÃ¶r en dator
.Description
	HÃ¤mtar AD-objektet fÃ¶r dator och lista de grupper som dator Ã¤r medlem i
.Parameter DatorNamn
	Namn pÃ¥ dator att undersÃ¶ka
.Example
	Get-SD_DatorsGruppmedlemskap -DatorNamn "Dat1"
#>

function Get-SD_DatorsGruppmedlemskap
{
	param(
	[Parameter(Mandatory=$true)]
		[String] $DatorNamn
	)

	try
	{
		Write-Host "Datorn " -NoNewline
		Write-Host $DatorNamn -Foreground Cyan
		Write-Host " Ã¤r medlem i fÃ¶ljande AD-grupper:"
		(Get-ADComputer -Identity $DatorNamn -Properties *).MemberOf | % {($_ -split ',')[0]} | % {$_.Substring(3)}
	} catch {
		Write-Host "Dator med namn $DatorNamn finns inte i AD"
	}
}

<#
.Synopsis
	Hämta ägare av funktionsbrevlåda
.Description
	Hämtar ägaren av funktionsbrevlåda angiven som parameter
.Parameter Funktionsbrevlåda
	Namn eller mailadress för funktionsbrevlådan
.Example
	Get-SD_FunkÄgare -Funktionsbrevlåda "Funklåda"
	Hämtar ägare av funktionsbrevlåda Funklåda
#>

function Get-SD_FunkÄgare
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Funktionsbrevlåda
	)

	try {
		$owner = ( Get-Mailbox -Identity $Funktionsbrevlåda.Trim() -ErrorAction Stop ).CustomAttribute10
	} catch {
		Write-Host "Ingen funktionsbrevlåda med namnet " -nonewline
		Write-Host $Funktionsbrevlåda -ForegroundColor Magenta -nonewline
		Write-Host " funnen"
	}

	Write-Host "Ägare av" $Funktionsbrevlåda.Trim() "är:"
	try {
		$user = Get-Mailbox -Identity $owner.Substring(7) -ErrorAction Stop | select DisplayName, UserPrincipalName
		Write-Host $user.EmailAddress
	} catch {
		Write-Host $owner.Substring(7)
		Write-Host "`nIngen maillåda hittades. Har personen slutat?"
	}
}

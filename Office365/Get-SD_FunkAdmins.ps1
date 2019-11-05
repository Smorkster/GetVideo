<#
.Synopsis
	Lista administratörer för en funktionsbrevlåda
.Description
	Hämtar alla administratörer för en funktionsbrevlåda
.Parameter Funktionsbrevlåda
	Namn/mailadress för funktionsbrevlådan
.Example
	Get-SD_FunkAdmins -Funktionsbrevlåda "Funk 1"
#>

function Get-SD_FunkAdmins
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $Funktionsbrevlåda
	)

	$funk = Get-Mailbox -Identity $Funktionsbrevlåda.Trim() -ErrorAction SilentlyContinue
	if($funk -eq $null)
	{
		Write-Host "Funktionsbrevlåda " -NoNewline
		Write-Host $Funktionsbrevlåda -ForegroundColor Magenta -NoNewline
		Write-Host " finns inte"
	} else {
		Get-MailboxPermission -Identity $funk.Identity -ErrorAction Stop | ? {($_.AccessRights -match "FullAccess") -and ($_.User -match "@test.com")} | ft User
	}
}

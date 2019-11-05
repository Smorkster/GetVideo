<#
.Synopsis
	Verifiera ifall användare är medlem i en funktionsbrevlåda
.Description
	Söker funktionsbrevlåda och kontrollerar sedan om användaren finns listad med behörighet
.Parameter id
	id för användaren
.Parameter Funktionsbrevlåda
	Namn/mailadress för funktionsbrevlådan
.Example
	Confirm-SD_AnvändareMedlemIFunktionsbrevlåda -id "ABCD" -Funktionsbrevlåda "Funk 1"
#>

function Confirm-SD_AnvändareMedlemIFunktionsbrevlåda
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id,
	[Parameter(Mandatory=$true)]
		[string] $Funktionsbrevlåda
	)

	$user = Get-ADUser -Identity $id -Properties *
	$member = Get-Mailbox -Identity $Funktionsbrevlåda | Get-MailboxPermission | ? {$_.User -eq $user.Emailaddress}

	Write-Host $MailAnvändare -ForegroundColor Cyan -NoNewline
	Write-Host " har " -NoNewline
	if($member)
	{
		Write-Host $member.AccessRights -NoNewline -ForegroundColor Cyan
	} else {
		Write-Host " ingen behörighet till " -nonewline
	}
	Write-Host $Funktionsbrevlåda -ForegroundColor Cyan
}

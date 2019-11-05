<#
.Synopsis
	Kontrollera ifall msExchMailboxGuid är tomt
.Description
	Kontrollera värdet på msExchMailboxGuid hos användaren.
	Detta används om det inte skapas någon låda för användaren, trots att synkronisering har utförts
.Parameter id
	id för användaren
.Example
	Confirm-SD_AnvändaremsExchMailboxGuid -id "ABCD"
#>

function Confirm-SD_AnvändaremsExchMailboxGuid
{
	param(
	[Parameter(Mandatory=$true)]
		[string] $id
	)

	try {
		$value = (Get-ADUser -Identity $id -Properties * -ErrorAction Stop).msExchMailboxGuid
		if($value -eq $null)
		{
			Write-Host "msExchMailboxGuid är tom"
		} else {
			Write-Host "msExchMailboxGuid är inte tom"
		}
	} catch {
		Write-Host "Ingen användare för $id hittades i AD"
	}
}

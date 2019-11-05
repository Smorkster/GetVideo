<#
.Synopsis
	Listar samtliga skapade rumslistor
.Description
	Listar alla registrerade rumslistor sorterade pÃ¥ namn
#>

function Get-SD_Rumslistor
{
	Get-DistributionGroup -Filter {RecipientTypeDetails -eq "RoomList"} | sort DisplayName | ft DisplayName
}

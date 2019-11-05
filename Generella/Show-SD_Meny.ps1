<#
.Synopsis
	Visar en meny över tillgängliga kommandon/skript skapade för Servicedesk
.Description
	Listar samtliga inläsa kommandon/skript i modulen. Listan kan med hjälp av dynamiska parametrar, filtreras per typ och mål.
	Om inga parametrar används, listas samtliga inlästa kommandon, kategoriserade per kommandotyp, t.ex. 'Add', 'Get' eller 'Remove'.
.Parameter KommandoMål
	Filtrera listan att bara visa kommandon som har ett specifikt mål
.Parameter Kommandotyp
	Filtrera listan att bara visa kommandon som är av samma typ
#>

function Show-SD_Meny
{
	[CmdletBinding()]
	param (
		[ValidateSet('Användare','Funk','Dist','Gem','Resurs','Rum')]
		[string] $KommandoMål
	)

	DynamicParam
	{
		$ParamAttrib = New-Object System.Management.Automation.ParameterAttribute
		$AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
		$AttribColl.Add($ParamAttrib)
		$AttribColl.Add((New-Object  System.Management.Automation.ValidateSetAttribute($script:commandTypes)))
		$RuntimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('KommandoTyp',  [string], $AttribColl)

		$RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
		$RuntimeParamDic.Add('KommandoTyp',  $RuntimeParam)

		return  $RuntimeParamDic
	}

	process
	{
		$ticker = 0
		$CommandKeys = (Get-Module "ServicedeskPowerShell-Modul").ExportedCommands.Keys

		if ($($PSBoundParameters.KommandoTyp)) {
			$name = $($PSBoundParameters.KommandoTyp)+"-*"
			$CommandKeys = $CommandKeys | ? {$_ -like $name}
		}
		if ($KommandoMål -eq "Användare")
		{
			$CommandKeys = $CommandKeys | ? {$_ -like "*_Användare*"}
		} elseif ($KommandoMål -eq "Funk") {
			$CommandKeys = $CommandKeys | ? {$_ -like "*Funk*"}
		} elseif ($KommandoMål -eq "Dist") {
			$CommandKeys = $CommandKeys | ? {$_ -like "*Dist*"}
		} elseif ($KommandoMål -eq "Gem") {
			$CommandKeys = $CommandKeys | ? {$_ -like "*Gem*"}
		} elseif ($KommandoMål -eq "Resurs") {
			$CommandKeys = $CommandKeys | ? {$_ -like "*Resurs*"}
		} elseif ($KommandoMål -eq "Rum") {
			$CommandKeys = $CommandKeys | ? {$_ -like "*Rum*"}
		}

		$items = $CommandKeys | % {$_ -split ("-") | select -First 1} | select -Unique
		$length = $CommandKeys | % {$_.Length} | sort | select -Last 1

		foreach ($i in $items){
			if (-not $($PSBoundParameters.KommandoTyp))
			{
				Write-Host $i -ForegroundColor DarkBlue -BackgroundColor White
			}
			foreach ( $name in $CommandKeys | ? { $_ -match $i } ){
				if ($PSBoundParameters.KommandoMål -or $PSBoundParameters.KommandoTyp)
				{
					Write-Host $name " " -ForegroundColor Cyan -NoNewLine
					Write-Host (Get-Help $name).Synopsis
				} else {
					if ( $ticker -lt 3 )
					{
						Write-Host $name -NoNewLine
						1..( $length - $name.length ) | % { Write-Host " " -NoNewLine }
						$ticker += 1
					} else {
						Write-Host $name
						$ticker = 0
					}
				}
			}
			Write-Host "`n"
			$ticker = 0
		}
	}
}

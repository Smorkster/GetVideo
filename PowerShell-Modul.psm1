function FillChangelog
{
	$global:changeloghash = @{} #Hashtable
	$global:changelog = @() #Array
	$change = $null
	$changeText = @()
	$changeSummary = ""
	foreach($changeTextRow in (Get-Content $PSScriptRoot\Changelog.txt))
	{
		if ($changeTextRow -match "\d{4}[-]\d{2}[-]\d{2}")
		{
			if ($change -eq $null)
			{
				$change = New-Object PSObject
				$change | Add-Member -MemberType NoteProperty -Name ChangeDatum -Value $changeTextRow
			}
		} elseif ($changeTextRow -eq "") {
			$change | Add-Member -MemberType NoteProperty -Name ChangeText -Value $changeText
			$change | Add-Member -MemberType NoteProperty -Name ChangeSummary -Value $changeSummary
			$global:changelog += $change
			$changeText = @()
			$changeSummary = ""
			$change = $null
		} else {
			if ($changeTextRow -notmatch "\*\*\*\*\*\*\*\*")
			{
                $split = $changeTextRow -split " - "
                $one = $split[0]
                $rest = $split[1..$split.Count]
				if ($one -match "-")
				{
					$changeSummary += "$one`n"
                    if($global:changeloghash.ContainsKey($one))
                    {
                        $global:changeloghash.$one += @($change.ChangeDatum; $rest)
                    } else {
                        $global:changeloghash.Add($one, @($change.ChangeDatum; $rest))
                    }
				}
			}
			if ($changeTextRow -notmatch "\*\*\*\*\*\*\*\*")
			{
				if (($changeTextRow -split " - ")[0] -match "-")
				{
					if ($changeSummary -eq "")
					{
						$changeSummary += "$(($changeTextRow -split " - ")[0])`n"
					} else {
						$changeSummary += "$(($changeTextRow -split " - ")[0])`n"
					}
				}
				$changeText += $changeTextRow
			}
		}
	}
}

function FillTypes
{
	$script:commandTypes = @()
	$script:commandTypes = $ToExport | % {$_ -split ("-") | select -First 1} | sort | select -Unique
}

$ModuleFunctions = Get-ChildItem -Path "$PSScriptRoot\Servicedesk*" | ? { $_.Mode -match "d" } | % { Get-ChildItem $_ } | ? { $_.Name -like "*.ps1" }
$ToExport = $ModuleFunctions | Select-Object -ExpandProperty BaseName

foreach ($import in $ModuleFunctions)
{
	try
	{
		. $import.FullName
	} catch {
		Write-Error "Import misslyckad: $($import.FullName): $_"
	}
}

Export-ModuleMember -Function $ToExport
FillChangelog
FillTypes
Write-Host "Version $(($Global:changelog | select -First 1).ChangeDatum) är klar att användas" -ForegroundColor Green

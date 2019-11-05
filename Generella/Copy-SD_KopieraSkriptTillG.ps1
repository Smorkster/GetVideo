<#
.Synopsis
	Kopierar PowerShell-script till centrala mappen på G:
.Description
	Skapar en lista av alla PowerShell-script från lokal samt centrala mappen. Gör sedan en jämförelse om någon fil är nyare i lokal mapp, i så fall uppdateras fil i central mapp.
	Gör utskrift om fil uppdateras, skriver sedan ut en summering av uppdateringen
.Example
	Copy-SD_KopieraTillG
#>

function Copy-SD_KopieraSkriptTillG
{
	$localDir = "H:\Dokument\Programmering\Powershell"
	$centralDir = "G:\\\Epost & Skype\Powershell\"
	$local = Get-ChildItem $localDir -File -Recurse
	$central = Get-ChildItem $centralDir -File -Recurse
	$MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
	$oförändrade = 0
	$ticker = 1

	foreach ($fileA in $local) {
		Write-Progress -Activity "Kopierar till G" -PercentComplete (($ticker/$local.Count)*100) -Status "Hanterar fil ($ticker / $($local.Count))" -CurrentOperation $fileA.Name
		$fileB = $central | ? {$_.Name -eq $fileA.Name}
		if ($fileB -eq $null)
		{
			Write-Host "Ny fil: " -NoNewline
			Write-Host $fileA.Name -ForegroundColor Cyan
			if ( ($fileA.DirectoryName -split "\\" | select -Last 1) -eq "Powershell" )
			{
				$newFile = $centralDir + "\" + $fileA.Name
			} else {
				$newFile = $centralDir + ($fileA.DirectoryName -split "\\" | select -Last 1) + "\" + $fileA.Name
			}
			Copy-Item $fileA.FullName -Destination $newFile
		} else {
			$fileAHash = [System.BitConverter]::ToString($MD5.ComputeHash([System.IO.File]::ReadAllBytes($fileA.FullName)))
			$fileBHash = [System.BitConverter]::ToString($MD5.ComputeHash([System.IO.File]::ReadAllBytes($fileB.FullName)))
			if ($fileAHash -ne $fileBHash)
			{
				Write-Host "Uppdaterar " -NoNewline
				Write-Host $fileA.Name -ForegroundColor Cyan
				Copy-Item $fileA.FullName -Destination $fileB.FullName
			} else {
				$oförändrade += 1
			}
		}
		$fileB = $null
		$ticker++
	}
	Write-Progress -Activity "Kopierar till G" -Completed
	Write-Host "$oförändrade filer oförändrade"
}

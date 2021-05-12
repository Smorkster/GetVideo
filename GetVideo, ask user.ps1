<#
.SYNOPSIS
	Same as GetVideo, but this version checks with the user if the video is to be downloaded
#>

param
(
	[int]$start = 0,
	[int]$length = 10
)
function GetVideoInfo
{
	param ( $url )
	$video = New-Object -TypeName PSObject
	$request = ( Invoke-WebRequest -uri $url )
	$user = ( $request.Links | Where-Object { $_.class -match "yt-uix-sessionlink       spf-link" } ).innerText
	$title = ( $request.ParsedHtml.title ).TrimEnd( " - YouTube" )
	$published = ( ( $request.ToString() -split '\n' | Select-String 'Published' ) -split "content=""" )[1].Substring( 0, 10 )
	Add-Member -InputObject $video -MemberType NoteProperty -Name User -Value $user
	Add-Member -InputObject $video -MemberType NoteProperty -Name Title -Value $title
	Add-Member -InputObject $video -MemberType NoteProperty -Name Published -Value $published
	return $video
}

Add-Type -AssemblyName System.Web
if ( $start -gt 0 ) { $start = $start -1 }

$failedDownloads = New-Object System.Collections.Arraylist( $null )
$youtubeUser = Get-Credential
$links = Get-Content links.txt
$ticker = 1

for ( ; $start -lt $links.Count; $start++ )
{
	$comp = Get-WmiObject -Filter "DeviceID='C:'" -Class Win32_LogicalDisk
	$limit = 1.5
	if ( ( $comp.FreeSpace / 1GB ) -gt ( 1.5 ) )
	{
		$video = $links[$start]
		$videoinfo = GetVideoInfo( $links[$start] )
		$index = ( $links.Count - [System.Web.HttpUtility]::ParseQueryString( $links[$start] )["index"] ) + 1
		$ans = Read-Host $ticker "/" $length "- Download" $index "? ($video)`n`t" $videoinfo.title

		if ( $ans -match "y" )
		{
			$videoname = "Bellular " +$index+ " %(title)s.%(ext)s"
			$ErrorActionPreference = "SilentlyContinue"
			& .\youtube-dl.exe $video -o $videoname -u $youtubeUser.UserName -p $youtubeUser.GetNetworkCredential().Password --mark-watched --no-playlist -q
			$ErrorActionPreference = "Continue"
			if ( $Error[0] -ne "" )
			{
				Write-Host "Error while downloading" -Foreground Red
				if ( ( Get-ChildItem | Where-Object { $_.Name -match "Bellular "+$index } ).Length -eq 0 )
				{
					Write-Host "Couldn't download " -nonewline -Foreground Red
					Write-Host $videoinfo.title
					$failedDownloads.Add($videoinfo.title +"`n`t"+ $video) > $null
				}
				else
				{
					Write-Host "Download finished " -nonewline -Foreground Green
					Write-Host $videoinfo.title
				}
			}
			else
			{
				Write-Host "Download finished " -nonewline -Foreground Green
				Write-Host $videoinfo.title
			}
		}
		if ( $ticker -eq $length )
		{
			$comp = Get-WmiObject -Filter "DeviceID='C:'" -Class Win32_LogicalDisk
			Write-Host "Done processing $length" -nonewline
            if ( $failedDownloads.Count -gt 0 )
            {
               Write-Host ". The following failed:"
               $failedDownloads
               $failedDownloads.Clear()
            }
			else { Write-Host "." }

			Write-Host ( [Math]::Round( ( $comp.FreeSpace / 1GB ), 2 ) )"free space."
			Write-Host "Enter " -nonewline -Foreground Green
			Write-Host "to continue, " -nonewline
			Write-Host "Q " -nonewline -Foreground Green
			$input = Read-Host "to quit"
			if ( $input -eq "Q" ) { break }
			$ticker = 0
		}
		$ticker = $ticker + 1
		$Error[0] = ""
		$videoinfo = $null
	}
	else
	{
		Write-Host "To little free disc space."
		Write-Host "Aborting" -Foreground Red
		break
	}
}

<#
.SYNOPSIS
	Reads a file of YouTube-links and downloads the videos
.DESCRIPTION
	Version 3
	This script reads a file containing a list of addresses with videos that wants to be downloaded. It is mainly created for YouTube, but the application YouTube-dl can also handle other sites.
	Before downloading, the script checks of there are (persumed) enough free space on the disc. It then continues with fetching information about the video then starts downloading.
	If the video is located on YouTube the video will be marked as watched if the user have provided login credentials.
	The videos will be named as such:
		YouTube: <YouTube-username> <date of publication> <videoname>
		Other sites: <Domain-name> <videoname>
#>

param
(
	[int]$start = 0
)
function GetVideoInfo
{
	param ( $url )
	$video = New-Object -TypeName PSObject
	$request = (Invoke-WebRequest -Uri $url )
	if ( $videolink -match "www.youtube.com" )
	{
		$user = ( $request.Links | Where-Object { $_.href -like "*/channel/*" } ).innerText[0]
		$title = ( $request.ParsedHtml.title ).TrimEnd( " - YouTube" )
		$published = ( ( $request.ToString() -split '\n' | Select-String 'Published' ) -split "content=""" )[1].Substring( 0, 10 )
	}
	else
	{
		$title = $request.ParsedHtml.title
		$user = ( [System.Uri] $url ).Host -replace '^www\.'
		$published = ""
	}
	Add-Member -InputObject $video -MemberType NoteProperty -Name User -Value $user
	Add-Member -InputObject $video -MemberType NoteProperty -Name Published -Value $published
	Add-Member -InputObject $video -MemberType NoteProperty -Name Title -Value $title
	return $video
}

Add-Type -AssemblyName System.Web
if ( $start -gt 0 ) { $start = $start -1 }
$ErrorActionPreference = "SilentlyContinue"
$youtubeUser = Get-Credential
$ErrorActionPreference = "Continue"
$Error.Clear()
$failedDownloads = New-Object System.Collections.Arraylist($null)
$filename = Read-Host "Filename"
$links = Get-Content $filename
$lowerRemaindingDiscLimit = 1.5
$ticker = 1
if ( $null -eq $links )
{
	Write-Host "File empty. Quiting" -ForegroundColor Cyan
	return
}

for ( ; $start -lt $links.Count ; $start++ )
{
	$comp = Get-WmiObject -Filter "DeviceID='C:'" -Class Win32_LogicalDisk
	if ( ( $comp.FreeSpace / 1GB ) -gt ( $lowerRemaindingDiscLimit ) )
	{
		if ( $links.Count -eq 1 ) { $videolink = $links }
		else { $videolink = $links[$start] }

		$videoinfo = GetVideoInfo $videolink
		Write-Host $ticker "/" $links.Count "- Downloading " -NoNewline
		Write-Host $videoinfo.title -ForegroundColor Cyan

		$ErrorActionPreference = "SilentlyContinue"
		if ( $videolink -match "www.youtube.com" )
		{
			$videoname = $videoinfo.user+ " " +$videoinfo.published+ " %(title)s.%(ext)s"
			if ( $null -eq $youtubeUser ) { & .\youtube-dl.exe $videolink -o $videoname --no-playlist -q }
			else { & .\youtube-dl.exe $videolink -o $videoname -u $youtubeUser.UserName -p $youtubeUser.GetNetworkCredential().Password --mark-watched --no-playlist -q }
		}
		else
		{
			$videoname = $videoinfo.user+ " %(title)s.%(ext)s"
			& .\youtube-dl.exe $videolink -o $videoname -q
		}

		if ( $? )
		{
			Write-Host "Error while downloading" -ForegroundColor Red
			if ( ( Get-ChildItem | Where-Object { $_.Name -match $index } ).Length -eq 0 )
			{
				Write-Host "Couldn't download " -NoNewline -ForegroundColor Red
				Write-Host $videolink
                $failedDownloads.Add( $videoinfo.title +"`n`t"+ $videolink ) > $null
			}
			else { Write-Host "Download finished " -ForegroundColor Green }
		}
		else { Write-Host "Download finished "-ForegroundColor Green }

		$ErrorActionPreference = "Continue"

		$videoinfo = $null
	}
	else
	{
		Write-Host "To little free disc space."
		Write-Host "Aborting" -ForegroundColor Red
		break
	}
	$ticker = $ticker + 1
}
Write-Host "Done downloading" $links.Count
Write-Host "Free space" ( $comp.FreeSpace / 1GB ) -NoNewline
if ( $failedDownloads.Count -gt 0 )
{
   Write-Host ". The following failed:"
   $failedDownloads
   $failedDownloads.Clear()
}
else { Write-Host "." }
$null > $filename
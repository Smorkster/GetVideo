<#
.SYNOPSIS
	Reads a file of YouTube-links and downloads the videos
.DESCRIPTION
	Version 2
	This script reads a file containing a list of addresses with videos that wants to be downloaded. It is mainly created for YouTube, but the application YouTube-dl can also handle other sites.
	Before downloading, the script checks of there are (persumed) enough free space on the disc. It then continues with fetching information about the video then starts downloading.
	If the video is located on YouTube the video will be marked as watched if the user have provided login credentials.
	The videos will be named as such:
		YouTube: <YouTube-username> <date of publication> <videoname>
		Othersites: <Domain-name> <videoname>
#>

param
(
	[int]$start = 0
)
function GetVideoInfo($url){
	$video = New-Object -TypeName PSObject
	$request = (Invoke-WebRequest -uri $url)
	if($videolink -match "www.youtube.com")
	{
		$user = ($request.Links | ? {$_.class -match "yt-uix-sessionlink       spf-link"}).innerText
		$title = ($request.ParsedHtml.title).TrimEnd(" - YouTube")
		$published = (($request.ToString() -split '\n' | Select-String 'Published') -split "content=""")[1].Substring(0,10)
	} else {
		$title = $request.ParsedHtml.title
		$user = ([System.Uri] $url).Host -replace '^www\.'
		$published = ""
	}
	Add-Member -InputObject $video -MemberType NoteProperty -Name User -Value $user
	Add-Member -InputObject $video -MemberType NoteProperty -Name Published -Value $published
	Add-Member -InputObject $video -MemberType NoteProperty -Name Title -Value $title
	return $video
}

Add-Type -AssemblyName System.Web
if($start -gt 0)
{
	$start = $start -1
}
$Error[0] = $null
$ErrorActionPreference = "SilentlyContinue"
$youtubeCredentials = $null
$youtubeCredentials = Get-Credentials
$ErrorActionPreference = "Continue"
$failedDownloads = New-Object System.Collections.Arraylist($null)
$filename = "links.txt"
$links = Get-Content $filename
if($links -eq $null)
{
	Write-Host "File empty. Quiting" -Foreground Cyan
	return
}$ticker = 1

for(; $start -lt $links.Count; $start++)
{
	$comp = Get-WmiObject -Filter "DeviceID='C:'" -Class Win32_LogicalDisk
	$limit = 1.5
	if(($comp.FreeSpace / 1GB) -gt (1.5))
	{
		if($links.Count -eq 1)
		{
			$videolink = $links
		} else {
			$videolink = $links[$start]
		}
		$videoinfo = GetVideoInfo($videolink)
		Write-Host $ticker "/" $links.Count "- Downloading " -nonewline
		Write-Host $videoinfo.title -Foreground Cyan

		$ErrorActionPreference = "SilentlyContinue"
		if($videolink -match "www.youtube.com")
		{
			$videoname = $videoinfo.user+ " " +$videoinfo.published+ " %(title)s.%(ext)s"
			if($youtubeCredentials -eq $null)
			{
				& youtube-dl.exe $videolink -o $videoname --no-playlist -q
			} else {
				& youtube-dl.exe $videolink -o $videoname -u $youtubeCredentials.UserName -p $youtubeCredentials.Password --mark-watched --no-playlist -q
			}
		} else {
			$videoname = $videoinfo.user+ " %(title)s.%(ext)s"
			& youtube-dl.exe $videolink -o $videoname -q
		}
			
		$ErrorActionPreference = "Continue"

		if($Error[0] -ne "")
		{
			Write-Host "Error while downloading" -Foreground Red
			if((get-childitem | ? {$_.Name -match $index}).Length -eq 0)
			{
				Write-Host "Couldn't download " -nonewline -Foreground Red
				Write-Host $videolink
                $failedDownloads.Add($videoinfo.title +"`n`t"+ $videolink) > $null
			} else {
				Write-Host "Download finished " -Foreground Green
			}
		} else {
			Write-Host "Download finished "-Foreground Green
		}

		$Error[0] = ""
		$videoinfo = $null
	} else {
		Write-Host "To little free disc space."
		Write-Host "Aborting" -Foreground Red
		break
	}
	$ticker = $ticker + 1
}
Write-Host "Done downloading" $links.Count -nonewline
if($failedDownloads.Count -gt 0)
{
   Write-Host ". The following failed:"
   $failedDownloads
   $failedDownloads.Clear()
} else {
	Write-Host "."
}
$null > $filename
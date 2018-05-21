<#
.SYNOPSIS
	Reads a file of YouTube-links and downloads the videos
.DESCRIPTION
	Version 4
	This script reads a file containing a list of addresses with videos that wants to be downloaded. It is mainly created for YouTube, but the application YouTube-dl can also handle other sites.
	Before downloading, the script checks of there are (persumed) enough free space on the disc. It then continues with fetching information about the video then starts downloading.
	If the video is located on YouTube the video will be marked as watched if the user have provided login credentials.
	The videos will be named as such:
		YouTube: <date of publication> <YouTube-username> <videoname>
		Other sites: <Domain-name> <videoname>
#>

param
(
	[int]$start = 0
)
function GetVideoInfo($url){
	$video = New-Object -TypeName PSObject
	$request = (Invoke-WebRequest -Uri $url)
	if($videolink -match "www.youtube.com")
	{
		$user = ($request.Links | ? {$_.href -like "*/channel/*"}).innerText[0]
		$title = ($request.ParsedHtml.title).TrimEnd(" - YouTube")
		$published = (($request.ToString() -split '\n' | Select-String 'Published') -split "content=""")[1].Substring(0,10)
	} else {
		$title = $request.ParsedHtml.title
		$user = ([System.Uri] $url).Host -replace '^www\.'
		$published = ""
	}
	$title = $title -replace "<" , ""
    $title = $title -replace ">" , ""
    $title = $title -replace ":" , " -"
    $title = $title -replace [char]0x22 , ""
    $title = $title -replace "/" , "_"
    $title = $title -replace "\\" , ""
    $title = $title -replace "\|" , "_"
    $title = $title -replace "\?" , ""
    $title = $title -replace "\*" , ""

	Add-Member -InputObject $video -MemberType NoteProperty -Name User -Value $user
	Add-Member -InputObject $video -MemberType NoteProperty -Name Published -Value $published
	Add-Member -InputObject $video -MemberType NoteProperty -Name Title -Value $title
	return $video
}

$errorHandling =# ($videoname, $videolink, $youtubeName, $youtubePassword)
{
# args[0] = videolink
# args{1] = videoname
	if(-not $?)
	{
		throw = $args[1] +"`n`t"+ $args[0]
	} else {
		if((Get-ChildItem c:\users\6g1w\w -filter $args[1]).count -eq 0)
		{
			throw = $args[1] +"`n`t"+ $args[0]
		}
	}
}
Add-Type -AssemblyName System.Web
if($start -gt 0)
{
	$start = $start -1
}
$ErrorActionPreference = "SilentlyContinue"
$youtubeUser = Get-Credential
$ErrorActionPreference = "Continue"
$filename = Read-Host "Filename"
$links = Get-Content $filename
$lowerRemaindingDiscLimit = 1.5
$ticker = 1

if($links -eq $null)
{
	Write-Host "File with links empty. Quiting" -ForegroundColor Cyan
	return
}

for(; $start -lt $links.Count; $start++)
{
	$comp = Get-WmiObject -Filter "DeviceID='C:'" -Class Win32_LogicalDisk
	if(($comp.FreeSpace / 1GB) -gt ($lowerRemaindingDiscLimit))
	{
		if($links.Count -eq 1)
		{
			$videolink = $links
		} else {
			$videolink = $links[$start]
		}
		$videoinfo = GetVideoInfo($videolink)

		if($videolink -match "www.youtube.com")
		{
			$videoname = "c:\users\6g1w\appdata\w\"+$videoinfo.published+" " +$videoinfo.user+" %(title)s.%(ext)s"
		
			if($youtubeUser -eq $null)
			{
				Start-Job -ScriptBlock {param($videolink,$videoname,$videotitle) c:\users\6g1w\appdata\w\youtube-dl.exe $videolink -o $videoname --no-playlist -q; if((Get-ChildItem c:\users\6g1w\appdata\w -filter *$videoTitle*).count -eq 0) { throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ [int[]][char[]]$videoTitle } } -ArgumentList $videolink,$videoname,$videoinfo.Title > $null
			} else {
				Start-Job -ScriptBlock {param($videolink,$videoname,$youtubeUserName,$youtubeUserPassword,$videoTitle) c:\users\6g1w\appdata\w\youtube-dl.exe $videolink -o $videoname -u $youtubeUserName -p $youtubeUserPassword --mark-watched --no-playlist -q; if((Get-ChildItem c:\users\6g1w\appdata\w -filter *$videoTitle*).count -eq 0) { throw $videoTitle +"`n`t"+ $videolinkv } } -ArgumentList $videolink, $videoname,$youtubeUser.UserName,$youtubeUser.GetNetworkCredential().Password,$videoinfo.Title > $null
			}
		} else {
			$videoname = "c:\users\6g1w\appdata\w\"+$videoinfo.user+ " %(title)s.%(ext)s"
			Start-Job -ScriptBlock {param($videolink,$videoname,$videoTitle) c:\users\6g1w\appdata\w\youtube-dl.exe $videolink -o $videoname -q;if((Get-ChildItem c:\users\6g1w\appdata\w -filter *$videoTitle*).count -eq 0) { throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ [int[]][char[]]$videoTitle } } -ArgumentList $videolink,$videoname,$videoinfo.Title > $null
		}
		Write-Host "Downloading" $videoinfo.Title
		$videoinfo = $null
	} else {
		Write-Host "To little free disc space."
		Write-Host "Aborting" -ForegroundColor Red
		break
	}
	$ticker = $ticker + 1
}
Write-Host "Waiting for downloads `n"

$fails = Get-Job | Wait-Job

Write-Host "Done downloading" $links.Count
Write-Host "Free space" ($comp.FreeSpace / 1GB)
$null > $filename

$fails = Get-Job | ? {$_.State -eq 'Failed'}
$addresses = New-Object -ComObject System.Collections.ArrayList
if($fails.count -gt 0)
{
	Write-Host "These failed to download"
	foreach($j in $fails)
	{
		Write-Host $j.ChildJobs[0].JobStateInfo.Reason.Message -ForegroundColor Red
		$addresses.Add($j.ChildJobs[0].JobStateInfo.Reason.Message.Split("`t")[1]) > $null
	}
}
$addresses > $filename
Get-Job | Remove-Job
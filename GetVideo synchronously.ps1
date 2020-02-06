<#
.Synopsis
    Reads a file of weblinks and downloads videos from the site
.Description
	Version 10
	This script reads a file containing a list of addresses with videos that wants to be downloaded. It is mainly created for YouTube, but the application YouTube-dl can also handle other sites.
	Before downloading, the script extracts YouTube- and Google-cookies checks of there are (persumed) enough free space on the disc, the lower limit is 2 GB of free space. It then continues with fetching information about the video and then starts downloading.
	If the webaddress is located on YouTube, and there is a cookiefile, the video will be marked as watched credentials.
	
	The links.txt file must be located in the same folder as YouTube-dl and contain one webaddress per row
	The videos will be named as such:
		YouTube: <date of publication> <YouTube-username> <videoname>
		SVT Play: <date of publication> <Domain-name> <videoname>
		Other sites: <Domain-name> <videoname>
.Parameter WorkingDirectory
	Directory where youtube-dl and links.txt is located. This is also where cookies.txt will be saved and where the videos will be downloaded.
.Parameter ExtractCookiesFrom
	Choase which webbrowser to extract the cookies from.
.Parameter WatchLater
	Use this switch to download the videos in your "Watch Later"-list on YouTube. If used, the parameter 'ExtractCookiesFrom' must also be used, or else youtube-dl can't read your account.
.Parameter File
	Use this switch to download videos from links in the "links.txt"-file.
.Parameter Start
	Chaose to start at position in the list of links other that at the first.
.Parameter ExitAfter
	Use this switch to tell the script to close the PowerShell-window when done. If there are errors, the window will stay open.
#>

param(
[Parameter(Mandatory=$true)]
	[string] $WorkingDirectory,
[ValidateSet("Firefox","Google Chrome")]
	[string] $ExtractCookiesFrom,
	[switch] $WatchLater,
	[switch] $File,
[ValidatePattern('\d')]
	[int] $MaxDownloads,
	[int] $Start = 0,
	[switch] $ExitAfter
)

function GetVideoInfo
{
	param(
		[string] $url
	)

	$video = New-Object -TypeName PSObject
	$request = (Invoke-WebRequest -Uri $url)
	if($url -match "www.youtube.com")
	{
		try
		{
			$user = (($request.Links | ? {$_.href -like "*/channel/*"} | ? {$_.innertext -eq $_.innerhtml})[0]).innerhtml
			$title = ($request.ParsedHtml.title -split " - YouTube")[0]
			$published = ($request.RawContent | Select-String -Pattern '(meta itemprop="datePublished".+")' -AllMatches | select -ExpandProperty matches | select -ExpandProperty value).SubString(39,10)
		} catch {
			$user = "Parse Error"
			$title = $url
		}
	} elseif ($url -match "www.svtplay.se") {
		$user = "SVT Play"
		$title = ($request.ParsedHtml.title -split " \| SVT Play")[0]
		$date = (($request.ParsedHtml.all | ? {$_.className -like "*play_video-page__meta-data-item*"})[0]).textContent.Trim()
        if ($date -like "*ig*r*") {
            $published = ([datetime]::Today.AddDays(-1)).ToShortDateString()
        } else {
    		$y = [datetime]::Now.Year
	    	$m = ($date -split ' ')[2] -replace "jan","01" -replace "feb","02" -replace "mar","03" -replace "apr","04" -replace "maj","05" -replace "jun","06" -replace "jul","07" -replace "aug","08" -replace "sep","09" -replace "okt","10" -replace "nov","11" -replace "dec","12"
		    if (($d = ($date -split ' ')[1]).length -lt 2)
			{
				$d = "0"+$d
			}
    		$published = [string]::Concat($y, "-", $m, "-", $d)
        }
	} else {
		$title = $request.ParsedHtml.title
		$user = ([System.Uri] $url).Host -replace '^www\.'
		$published = ""
	}
	$title = $title -replace "<" , ""			# Char <
    $title = $title -replace ">" , ""			# Char >
    $title = $title -replace ":" , " -"			# Char :
    $title = $title -replace [char]0x22 , "'"	# Char "
    $title = $title -replace "/" , "_"			# Char /
    $title = $title -replace "\\" , ""			# Char \
    $title = $title -replace "\|" , "_"			# Char |
    $title = $title -replace "\?" , ""			# Char ?
    $title = $title -replace "\*" , "_"			# Char *

	Add-Member -InputObject $video -MemberType NoteProperty -Name User -Value $user
	Add-Member -InputObject $video -MemberType NoteProperty -Name Published -Value $published
	Add-Member -InputObject $video -MemberType NoteProperty -Name Title -Value $title

	return $video
}

function ExtractCookies
{
	param(
		[string] $Browser,
		[string] $WorkingDirectory,
		[switch] $Session
	)

	$where = "('.youtube.com','.svtplay.se')"
	$targetFileCookies = "$workingDirectory\cookies.txt"
	$cookieString = ""
	Remove-Item $targetFileCookies -ErrorAction SilentlyContinue

	$user = $env:USERNAME
	if ($browser -eq "Firefox")
	{
		$ffFolder = Get-ChildItem -Path "c:\users\$user\appdata\roaming\mozilla\firefox\profiles" -Name "*default*"
		$cookiesSQLite = "C:\Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\$ffFolder\cookies.sqlite"
		$query = "SELECT * FROM moz_cookies WHERE host IN $where"
	} else {
		$cookiesSQLite = Join-Path -Path $([System.Environment]::GetFolderPath("LocalApplicationData")) -ChildPath 'Google\Chrome\User Data\Default\Cookies'
		$query = "SELECT * FROM cookies WHERE host_key IN $where"
	}
	$cookieData = @()
	$cookieData += Invoke-SqliteQuery -DataSource $cookiesSQLite -Query $query

	foreach ($cookie in $cookieData)
	{
		if ($browser -eq "Firefox")
		{
			$cookieHost = $cookie.host
			if($cookie.sameSite) { $cookieSameSite = "TRUE" } else {$cookieSameSite = "FALSE"}
			$cookiePath = $cookie.path
			if($cookie.isSecure) { $cookieIsSecure = "TRUE" } else {$cookieIsSecure = "FALSE"}
			$cookieExpiry = $cookie.expiry
			$cookieName = $cookie.name
			$cookieValue = $cookie.value
		} elseif ($browser -eq "Google Chrome") {
			$cookieHost = $cookie.host_key
			if($cookie.firstpartyonly) { $cookieSameSite = "TRUE" } else {$cookieSameSite = "FALSE"}
			$cookiePath = $cookie.path
			if ($cookie.is_secure) { $cookieIsSecure = "TRUE" } else { $cookieIsSecure = "FALSE"}
			$cookieExpiry = [math]::Floor(($cookie.expires_utc / 1000000) - 11644473600)
			$cookieName = $cookie.name
			$ByteArr = [System.Security.Cryptography.ProtectedData]::Unprotect(
				$cookie.encrypted_value,
				$null,
				[System.Security.Cryptography.DataProtectionScope]::CurrentUser
			)
			$cookieValue = [System.Text.Encoding]::ASCII.GetString($ByteArr)
		}
		$cookieString += $cookieHost+"`t"+$cookieSameSite+"`t"+$cookiePath+"`t"+$cookieIsSecure+"`t"+$cookieExpiry+"`t"+$cookieName+"`t"+$cookieValue+"`r`n"
	}
	Add-Content -Value "# Netscape HTTP Cookie File`r`n" -Path $targetFileCookies
	Add-Content -Value $cookieString -Path $targetFileCookies
	if ($Session)
	{
		Write-Verbose "Skapar session fÃ¶r YouTube"
		$newSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
		foreach ($cookie in $cookieData)
		{
			$newCookie = New-Object System.Net.Cookie
			$newCookie.Domain = $cookie.Host
			$newCookie.Name = $cookie.name
			$newCookie.Value = $cookie.value
			$newCookie.Expires = [datetime]::Parse([timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($cookie.expiry)))
			$newSession.Cookies.Add($newCookie)
		}
		return $newSession
	} else { return }
}

function ClearWatchedVideos
{
	param(
		$session
	)
	$ie = New-Object -ComObject internetexplorer.application
	$ie.Visible = $false
	$ie.Navigate("https://www.youtube.com/playlist?list=WL")
	while ($ie.Busy -eq $true) { Start-Sleep -Seconds 1; } # Wait for page to load
	($ie.Document.all | ? {$_.className -eq "yt-uix-button yt-uix-button-size-default yt-uix-button-default remove-watched-button"}).click()
}

Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web
$lowerRemaindingDiscLimit = 2
$ticker = 1

if ($workingDirectory -eq "h")
{
	$workingDirectory = $PSScriptRoot
	Write-Verbose "Setting directory to $workingDirectory"
}

if ($extractCookiesFrom)
{
	try {
		Import-Module PSSQLite -ErrorAction Stop
		$moduleLoaded = $true
	} catch {
		Write-Host "Can't import the module PSSQLite. Will not be able to extract cookies"
		$moduleLoaded = $false
	}
	if ($WatchLater) {
		$session = ExtractCookies -Browser $extractCookiesFrom -WorkingDirectory $workingDirectory -Session
	} else {
		ExtractCookies -Browser $extractCookiesFrom -WorkingDirectory $workingDirectory
	}
	Write-Verbose "Cookies extracted from $extractCookiesFrom"
}

if ($WatchLater)
{
	Write-Verbose "Starting download from YouTubes 'Watch Later'"
	cd $workingDirectory
	if (Get-ChildItem "cookies.txt" -ErrorAction SilentlyContinue)
	{
		[System.Collections.ArrayList] $parameters = @('https://www.youtube.com/playlist?list=WL', '--cookies', 'cookies.txt', '--no-progress', '-o', '%(upload_date)s %(uploader)s %(title)s.%(ext)s', '--mark-watched', '--no-warning')
		if ($start)
		{
			$parameters.AddRange(@('--playlist-start', $start))
			Write-Verbose "Starting download from position $start"
		}
		if ($MaxDownloads) {
			$parameters.AddRange(@('--max-downloads', $MaxDownloads))
			Write-Verbose "Settings maximum number of downloads to $MaxDownloads"
		}
		Write-Verbose "Starting download process"
		.\youtube-dl.exe $parameters | % {
			if ($_ -match "Downloading 0 videos")
			{
				Write-Host "WatchLater-list is empty. Exiting."
				return
			} elseif ($_ -match "Downloading video \d of \d") {
				$text = ($_ -split " ")[3..5]
			} elseif ($_ -match "Destination:") {
				$text += ($_ -split ": ")[1]
				Write-Host $text -ForegroundColor Cyan
				$text = ""
			} elseif ($_ -match "Download completed") {
				Write-Host "`tFinished downloading"
				$text = ""
			} elseif ($_ -match "ERROR: ") {
				$fails += ($_ -split ":")[1]+"`n"
				Write-Host "`tDownload failed" -ForegroundColor Red
				$text = ""
			}
		}
		Write-Verbose "Downloading finished"

		Write-Verbose "Finding and renaming videofiles"
		Get-ChildItem | ? {$_.Name -match "\d\d\d\d\d\d\d\d"} | % { Rename-Item -Path $_ -NewName $_.Name.Insert(4,'-').Insert(7,'-') }
		ClearWatchedVideos
	} else {
		Write-Host "Cookie-file not present. It is needed for youtube-dl to work with WatchLater-list.`nAborting"
		return
	}
}

if ($File)
{
	Write-Verbose "Starting download of files by links in file"
	if($start -gt 0)
	{
		$start = $start -1
	}

	if (Test-Path ($workingDirectory + "\links.txt"))
	{
		Write-Verbose "Fetching links from file"
		$links = Get-Content ($workingDirectory + "\links.txt")
		if($links -eq $null)
		{
			Write-Host "The links.txt file is empty. Exiting script." -ForegroundColor Red
			return
		}
	} else {
		Write-Host "The links.txt file is not found. Exiting script." -ForegroundColor Red
		return
	}
	Write-Verbose "Starting download process"
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
			$videoinfo = GetVideoInfo -url $videolink

			if($videolink -match "www.youtube.com")
			{
				if ($videoinfo.user -eq "Parse Error")
				{
					$videoname = "%(upload_date)s %(uploader)s %(title)s.%(ext)s"
				} else {
					$videoname = $videoinfo.published+" " +$videoinfo.user+" "+$videoinfo.Title+".%(ext)s"
				}
			
				if(-not $moduleLoaded)
				{
					Start-Job -ScriptBlock {
						param($videolink, $videoname, $videotitle, $dir)
						cd $dir
						.\youtube-dl.exe $videolink -o $videoname --no-playlist -q
						if ($Error[0] -ne $null)
						{
							throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName
						}
						if ((Get-ChildItem -filter *$videoTitle*).count -eq 0)
						{
							throw $videoTitle +"`n`t"+ $videolink
						}
					} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
				} else {
					Start-Job -ScriptBlock {
						param($videolink, $videoname, $videoTitle, $dir)
						cd $dir
						.\youtube-dl.exe $videolink -o $videoname --cookies "cookies.txt" --mark-watched --no-playlist -q
						if ($Error[0] -ne $null)
						{
							throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName
						}
						if((Get-ChildItem -filter *$videoTitle*).Count -eq 0)
						{
							throw $videoTitle +"`n`t"+ $videolink
						}
					} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
				}
			} elseif ($videolink -match "www.svtplay.se") {
				$videoname = $videoinfo.Published +" "+ $videoinfo.User+" "+ $videoinfo.Title+".%(ext)s"
				Start-Job -ScriptBlock {
					param($videolink, $videoname, $videoTitle, $dir)
					cd $dir
					.\youtube-dl.exe $videolink -o $videoname -q --ffmpeg-location .\ffmpeg\bin
					if ($Error[0] -ne $null)
					{
						throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName
					}
					if ((Get-ChildItem -filter *$videoTitle*).count -eq 0)
					{
						throw $videoTitle +"`n`t"+ $videolink +"`n`t" + $videoTitle
					}
				} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
			} else {
				$videoname = $videoinfo.user+" "+ $videoinfo.Title+".%(ext)s"
				Start-Job -ScriptBlock {
					param($videolink, $videoname, $videoTitle, $dir)
					cd $dir
					.\youtube-dl.exe $videolink -o $videoname -q
					if ($Error[0] -ne $null)
					{
						throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName
					}
					if ((Get-ChildItem -filter *$videoTitle*).count -eq 0)
					{
						throw $videoTitle +"`n`t"+ $videolink +"`n`t" + $videoTitle
					}
				} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
			}
			Write-Host "Downloading" $ticker "of" $links.Count " " -NoNewline
			Write-Host $videoinfo.Title -ForegroundColor Cyan
			$videoinfo = $null
		} else {
			Write-Host "To little free disc space."
			Write-Host "Aborting" -ForegroundColor Red
			break
		}
		$ticker = $ticker + 1
	}
	Write-Host "Waiting for downloads `n"

	Get-Job | Wait-Job > $null

	Write-Host "Done downloading" $links.Count "videos"
	Write-Host "Free space:" ([math]::Round($comp.FreeSpace / 1GB,2)) "GB"
	$null > ($workingDirectory + "\links.txt")

	Write-Verbose "Some videos could not be downloaded"
	$fails = Get-Job | ? {$_.State -eq 'Failed'}
	if($fails.Count -gt 0)
	{
		Write-Host "These failed to download"
		foreach($failed in $fails)
		{
			Write-Host $failed.ChildJobs[0].JobStateInfo.Reason.Message -ForegroundColor Red
			Add-Content ($workingDirectory + "\links.txt") $failed.ChildJobs[0].JobStateInfo.Reason.Message.Split("`t")[1].Trim()
		}
		Write-Host "Visit https://ytmp3.cc/"
	}
	Get-Job | Remove-Job
}

if ($ExitAfter -and ($fails.Count -eq 0))
{
	Stop-Process -Id $PID
}


<#
.Synopsis
    Reads a file of weblinks and downloads videos from the site
.Description
	Version 9
	This script reads a file containing a list of addresses with videos that wants to be downloaded. It is mainly created for YouTube, but the application YouTube-dl can also handle other sites.
	Before downloading, the script extracts YouTube- and Google-cookies checks of there are (persumed) enough free space on the disc, the lower limit is 2 GB of free space. It then continues with fetching information about the video and then starts downloading.
	If the webaddress is located on YouTube, and there is a cookiefile, the video will be marked as watched credentials.
	
	The links.txt file must be located in the same folder as YouTube-dl and contain one webaddress per row
	The videos will be named as such:
		YouTube: <date of publication> <YouTube-username> <videoname>
		SVT Play: <date of publication> <Domain-name> <videoname>
		Other sites: <Domain-name> <videoname>
.Parameter workingDirectory
	Directory where youtube-dl and links.txt is located. This is also where cookies.txt will be saved and where the videos will be downloaded.
.Parameter extractCookiesFrom
	Chose which webbrowser to extract the cookies from.
.Parameter start
	Chose to start at position in the list of links other that at the first.
#>

param (
[Parameter( Mandatory = $true )]
	[string] $WorkingDirectory,
[ValidateSet( "Firefox", "Google Chrome" )]
	[string] $ExtractCookiesFrom,
	[int] $Start = 0,
	[switch] $ExitAfter
)

function GetVideoInfo
{
	param (
		[string] $url
	)

	$video = New-Object -TypeName PSObject
	$request = ( Invoke-WebRequest -Uri $url )
	if ( $url -match "www.youtube.com" )
	{
		$user =  ( ( $request.Links | Where-Object { $_.href -like "*/channel/*" } | Where-Object { $_.innertext -eq $_.innerhtml } )[0] ).innerhtml
		$title = ( $request.ParsedHtml.title -split " - YouTube" )[0]
		$published = ( $request.RawContent | Select-String -Pattern '(meta itemprop="datePublished".+")' -AllMatches | Select-Object -ExpandProperty matches | Select-Object -ExpandProperty value ).SubString( 39, 10 )
	}
	elseif
	( $url -match "www.svtplay.se" ) {
		$user = "SVT Play"
		$title = ( $request.ParsedHtml.title -split " \| SVT Play" )[0]
		$date = ( ( $request.ParsedHtml.all | Where-Object { $_.className -like "*play_video-page__meta-data-item*" } )[0] ).textContent.Trim()

		if ( $date -like "*ig*r*" ) { $published = ([datetime]::Today.AddDays(-1)).ToShortDateString() }
		else
		{
    		$y = [datetime]::Now.Year
	    	$m = $date.Substring( 7, 3 ) -replace "jan", "01" -replace "feb", "02" -replace "mar", "03" -replace "apr", "04" -replace "maj", "05" -replace "jun", "06" -replace "jul", "07" -replace "aug", "08" -replace "sep", "09" -replace "okt", "10" -replace "nov", "11" -replace "dec", "12"
		    $d = $date.Substring( 4, 2 )
    		$published = [string]$y + "-" + [string]$m +"-" + [string]$d
        }
	}
	else
	{
		$title = $request.ParsedHtml.title
		$user = ( [System.Uri] $url ).Host -replace '^www\.'
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
	param (
		[string] $browser,
		[string] $workingDirectory
	)

	$where = "('.youtube.com','.svtplay.se')"
	$user = $env:USERNAME
	$cookieData = @()
	if ( $browser -eq "Firefox" )
	{
		$ffFolder = Get-ChildItem -Path "C:\Users\$user\AppData\Roaming\Mozilla\Firefox\profiles" -Name "*default*"
		$cookiesSQLite = "C:\Users\$user\AppData\Roaming\Mozilla\Firefox\Profiles\$ffFolder\cookies.sqlite"
		$cookieData += Invoke-SqliteQuery -DataSource $cookiesSQLite -Query "SELECT * FROM moz_cookies WHERE host IN $where"
	}
	else
	{
		$cookiesSQLite = Join-Path -Path $( [System.Environment]::GetFolderPath( "LocalApplicationData" ) ) -ChildPath 'Google\Chrome\User Data\Default\Cookies'
		$cookieData += Invoke-SqliteQuery -DataSource $cookiesSQLite -Query "SELECT * FROM cookies WHERE host_key IN $where"
	}

	$targetFileCookies = "$workingDirectory\cookies.txt"
	$cookieString = ""

	Remove-Item $targetFileCookies -ErrorAction SilentlyContinue
	foreach ( $cookie in $cookieData )
	{
		if ( $browser -eq "Firefox" )
		{
			$cookieHost = $cookie.host
			if ( $cookie.sameSite ) { $cookieSameSite = "TRUE" } else { $cookieSameSite = "FALSE" }
			$cookiePath = $cookie.path
			if ( $cookie.isSecure ) { $cookieIsSecure = "TRUE" } else { $cookieIsSecure = "FALSE"}
			$cookieExpiry = $cookie.expiry
			$cookieName = $cookie.name
			$cookieValue = $cookie.value
		}
		elseif ( $browser -eq "Google Chrome" )
		{
			$cookieHost = $cookie.host_key
			if ( $cookie.firstpartyonly ) { $cookieSameSite = "TRUE" } else { $cookieSameSite = "FALSE" }
			$cookiePath = $cookie.path
			if ( $cookie.is_secure ) { $cookieIsSecure = "TRUE" } else { $cookieIsSecure = "FALSE" }
			$cookieExpiry = [math]::Floor( ( $cookie.expires_utc / 1000000 ) - 11644473600 )
			$cookieName = $cookie.name
			$ByteArr = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $cookie.encrypted_value,
                $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
			$cookieValue = [System.Text.Encoding]::ASCII.GetString( $ByteArr )
		}

		$cookieString += $cookieHost+"`t"+$cookieSameSite+"`t"+$cookiePath+"`t"+$cookieIsSecure+"`t"+$cookieExpiry+"`t"+$cookieName+"`t"+$cookieValue+"`r`n"
	}

	Add-Content -Value "# Netscape HTTP Cookie File`r`n" -Path $targetFileCookies
	Add-Content -Value $cookieString -Path $targetFileCookies
}

Add-Type -AssemblyName System.Security
Add-Type -AssemblyName System.Web
if ( $workingDirectory -eq "h" ) { $workingDirectory = $PSScriptRoot }

if ( Test-Path ( $workingDirectory + "\links.txt" ) )
{
	$links = Get-Content ( $workingDirectory + "\links.txt" )
	if ( $null -eq $links )
	{
		Write-Host "The links.txt file is empty. Exiting script." -ForegroundColor Red
		return
	}
}
else
{
	Write-Host "The links.txt file is not found. Exiting script." -ForegroundColor Red
	return
}

$moduleLoaded = $false
if ( $extractCookiesFrom )
{
	try { Import-Module PSSQLite -ErrorAction Stop; $moduleLoaded = $true } catch { Write-Host "Can't import the module PSSQLite. Will not be able to extract cookies" }
}

if ( $start -gt 0 ) { $start = $start -1 }

if ( $moduleLoaded ) { ExtractCookies -browser $extractCookiesFrom -workingDirectory $workingDirectory }
$lowerRemaindingDiscLimit = 2
$ticker = 1

for ( ; $start -lt $links.Count; $start++ )
{
	$comp = Get-WmiObject -Filter "DeviceID='C:'" -Class Win32_LogicalDisk
	if ( ( $comp.FreeSpace / 1GB ) -gt ( $lowerRemaindingDiscLimit ) )
	{
		if ( $links.Count -eq 1 ) { $videolink = $links }
		else { $videolink = $links[$start] }
		$videoinfo = GetVideoInfo -url $videolink

		if ( $videolink -match "www.youtube.com" )
		{
			$videoname = $videoinfo.published+" " +$videoinfo.user+" "+$videoinfo.Title+".%(ext)s"
		
			if ( -not $moduleLoaded )
			{
				Start-Job -ScriptBlock {
					param ( $videolink, $videoname, $videotitle, $dir )
					Set-Location $dir
					.\youtube-dl.exe $videolink -o $videoname --no-playlist -q
					if ( $Error[0] -ne $null ) { throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName }
					if ( ( Get-ChildItem -filter *$videoTitle* ).count -eq 0 ) { throw $videoTitle +"`n`t"+ $videolink }
				} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
			}
			else
			{
				Start-Job -ScriptBlock {
					param ( $videolink, $videoname, $videoTitle, $dir )
					Set-Location $dir
					.\youtube-dl.exe $videolink -o $videoname --cookies "cookies.txt" --mark-watched --no-playlist -q
					if ( $Error[0] -ne $null ) { throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName }
					if ( ( Get-ChildItem -filter *$videoTitle* ).Count -eq 0 ) { throw $videoTitle +"`n`t"+ $videolink }
				} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
			}
		}
		elseif ( $videolink -match "www.svtplay.se" )
		{
			$videoname = $videoinfo.Published +" "+ $videoinfo.User+" "+ $videoinfo.Title+".%(ext)s"
			Start-Job -ScriptBlock {
				param ( $videolink, $videoname, $videoTitle, $dir )
				Set-Location $dir
				.\youtube-dl.exe $videolink -o $videoname -q --ffmpeg-location .\ffmpeg\bin
				if ( $Error[0] -ne $null ) { throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName }
				if ( ( Get-ChildItem -filter *$videoTitle* ).count -eq 0 ) { throw $videoTitle +"`n`t"+ $videolink +"`n`t" + $videoTitle }
			} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
		}
		else
		{
			$videoname = $videoinfo.user+" "+ $videoinfo.Title+".%(ext)s"
			Start-Job -ScriptBlock {
				param ( $videolink, $videoname, $videoTitle, $dir )
				Set-Location $dir
				.\youtube-dl.exe $videolink -o $videoname -q
				if ( $Error[0] -ne $null ) { throw $videoTitle +"`n`t"+ $videolink +"`n`t"+ $Error[0].CategoryInfo.TargetName }
				if ( ( Get-ChildItem -filter *$videoTitle* ).count -eq 0 ) { throw $videoTitle +"`n`t"+ $videolink +"`n`t" + $videoTitle }
			} -ArgumentList $videolink, $videoname, $videoinfo.Title, $workingDirectory > $null
		}
		Write-Host "Downloading" $ticker "of" $links.Count " " -NoNewline
		Write-Host $videoinfo.Title -ForegroundColor Cyan
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
Write-Host "Waiting for downloads `n"

Get-Job | Wait-Job > $null

Write-Host "Done downloading" $links.Count "videos"
Write-Host "Free space:" ( [math]::Round( $comp.FreeSpace / 1GB, 2 ) ) "GB"
$null > ( $workingDirectory + "\links.txt" )

$fails = Get-Job | Where-Object { $_.State -eq 'Failed' }
if ( $fails.Count -gt 0 )
{
	Write-Host "These failed to download"
	foreach ( $failed in $fails )
	{
		Write-Host $failed.ChildJobs[0].JobStateInfo.Reason.Message -ForegroundColor Red
        Add-Content ( $workingDirectory + "\links.txt" ) $failed.ChildJobs[0].JobStateInfo.Reason.Message.Split( "`t" )[1].Trim()
	}
	Write-Host "Visit https://ytmp3.cc/"
}
Get-Job | Remove-Job

if ( $ExitAfter -and ( $fails.Count -eq 0 ) ) { Stop-Process -Id $PID }

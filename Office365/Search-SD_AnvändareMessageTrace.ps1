<#
.Synopsis
	Sök messagetrace till eller från angiven användare
.Description
	Gör en messagetrace för angiven mottagare eller avsändare mellan angivna datum
.Parameter AdressAvsändare
	Adress för avsändaren
.Parameter AdressMottagare
	Adress för mottagaren
.Parameter Startdatum
	Startdatum för hur långt tillbaka messagetrace ska söka. Maxgräns är 10 dagar. Om startdatum utesluts, görs sökningen automatiskt för de två senaste dagarna.
.Parameter Slutdatum
	Slutdatum för sökningen. Om slutdatum utesluts, används dagens datum
.Parameter Exportera
	Används för att exportera messagetrace till Excel-fil
.Example
	Search-SD_AnvändareMessageTrace -AdressAvsändare "test@test.com" -AdressMottagare "testare@test.com" -Startdatum 1970-01-01 -Slutdatum 1970-01-02
	Söker efter alla mail som skickats från test@test till testare@test mellan datum 1970-01-01 och 1970-01-02
.Example
	Search-SD_AnvändareMessageTrace -AdressAvsändare "test@test.com" -Startdatum 1970-01-01 -Slutdatum 1970-01-02
	Söker efter alla mail som skickats från test@test mellan datum 1970-01-01 och 1970-01-02
.Example
	Search-SD_AnvändareMessageTrace -AdressMottagare "testare@test.com" -Startdatum 1970-01-01 -Slutdatum 1970-01-02
	Söker efter alla mail som skickats till testare@test mellan datum 1970-01-01 och 1970-01-02
.Example
	Search-SD_AnvändareMessageTrace -AdressMottagare "testare@test.com" -Startdatum 1970-01-01 -Exportera
	Söker och exporterar alla mail som skickats till testare@test från datum 1970-01-01 till idag
#>

function Search-SD_AnvändareMessageTrace
{
	[cmdletbinding()]
	param(
		[string] $AdressAvsändare,
		[string] $AdressMottagare,
	[ValidatePattern("\d{4}[-]\d{2}[-]\d{2}")]
		[string] $Startdatum,
	[ValidatePattern("\d{4}[-]\d{2}[-]\d{2}")]
		[string] $Slutdatum,
		[switch] $Exportera
	)

	if ($Startdatum)
	{
		if ([datetime]::Parse($Startdatum) -lt ([datetime]::Now.AddDays(-29)))
		{
			Write-Host "Startdatum är för lång tillbaka i tiden. Maxgräns är 10 dagar"
			return
		} else {
			if ($Slutdatum -eq "")
			{
				$Slutdatum = [datetime]::Now.ToString()
			} elseif ($Slutdatum -lt $Startdatum) {
				Write-Host "Slutdatum infaller före startdatum."
				return
			}
		}
	}

	if ($AdressAvsändare -and $AdressMottagare)
	{
		if ($Startdatum)
		{
			Write-Verbose "1"
			$mails = Get-MessageTrace -StartDate $Startdatum -EndDate $Slutdatum -SenderAddress $AdressAvsändare -RecipientAddress $AdressMottagare
			$fileName = "H:\Mail från $AdressAvsändare till $AdressMottagare ($Startdatum - $Slutdatum).xlsx"
		} else {
			Write-Verbose "2"
			$mails = Get-MessageTrace -SenderAddress $AdressAvsändare -RecipientAddress $AdressMottagare
			$fileName = "H:\Mail från $AdressAvsändare till $AdressMottagare.xlsx"
		}
	} elseif ($AdressAvsändare) {
		if ($Startdatum)
		{
			Write-Verbose "3"
			$mails = Get-MessageTrace -StartDate $Startdatum -EndDate $Slutdatum -SenderAddress $AdressAvsändare
			$fileName = "H:\Mail från $AdressAvsändare ($Startdatum - $Slutdatum).xlsx"
		} else {
			Write-Verbose "4"
			$mails = Get-MessageTrace -SenderAddress $AdressAvsändare
			$fileName = "H:\Mail från $AdressAvsändare.xlsx"
		}
	} elseif ($AdressMottagare) {
		if ($Startdatum)
		{
			Write-Verbose "5"
			$mails = Get-MessageTrace -StartDate $Startdatum -EndDate $Slutdatum -RecipientAddress $AdressMottagare
			$fileName = "H:\Mail till $AdressMottagare ($Startdatum - $Slutdatum).xlsx"
		} else {
			Write-Verbose "6"
			$mails = Get-MessageTrace -RecipientAddress $AdressMottagare
			$fileName = "H:\Mail till $AdressMottagare.xlsx"
		}
	} else {
		Write-Host "Varken avsändare eller mottagare angavs.`nAvbryter."
		return
	}

	if ($Exportera)
	{
		if ($mails.Count -eq 0)
		{
			Write-Host "Inga mail att exportera"
		} else {
			Write-Host "Påbörjar export"
			$excel = New-Object -ComObject excel.application 
			$excel.visible = $false
			$excelWorkbook = $excel.Workbooks.Add()
			$excelWorksheet = $excelWorkbook.ActiveSheet
			$excelWorksheet.Cells.Item(1, 1) = "Receivedate"
			$excelWorksheet.Cells.Item(1, 2) = "SenderAddress"
			$excelWorksheet.Cells.Item(1, 3) = "RecipientAddress"
			$excelWorksheet.Cells.Item(1, 4) = "Subject"
			$row = 2

			$mailDateArray = @()
			$mailSenderArray = @()
			$mailRecipientArray = @()
			$mailSubjectArray = @()
			foreach ($mail in $mails)
			{
				$mailDateArray += $mail.Received.ToShortDateString() + " " + $mail.Received.ToLongTimeString()
				$mailSenderArray += $mail.SenderAddress
				$mailRecipientArray += $mail.RecipientAddress
				$mailSubjectArray += $mail.Subject
			}

			Set-Clipboard -Value $mailDateArray
			$excelWorksheet.Cells.Item($row, 1).PasteSpecial() | Out-Null
			Set-Clipboard -Value $mailSenderArray
			$excelWorksheet.Cells.Item($row, 2).PasteSpecial() | Out-Null
			Set-Clipboard -Value $mailRecipientArray
			$excelWorksheet.Cells.Item($row, 3).PasteSpecial() | Out-Null
			Set-Clipboard -Value $mailSubjectArray
			$excelWorksheet.Cells.Item($row, 4).PasteSpecial() | Out-Null

			$range = $excelWorksheet.Range($excelWorksheet.Cells.Item(2, 1), $excelWorksheet.Cells.Item($mails.Count+1,1))
			$range.NumberFormat = "ÅÅÅÅ-MM-DD tt:mm:ss"

			$excelRange = $excelWorksheet.UsedRange
			$excelRange.EntireColumn.AutoFit() | Out-Null
			$excelWorksheet.ListObjects.Add(1, $excelWorksheet.Range($excelWorksheet.Cells.Item(1, 1),$excelWorksheet.Cells.Item($excelWorksheet.usedrange.rows.count, 4)), 0, 1) | Out-Null
			$excelWorkbook.SaveAs($fileName)
			$excelWorkbook.Close()
			$excel.Quit()

			[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelRange) | Out-Null
			[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorksheet) | Out-Null
			[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excelWorkbook) | Out-Null
			[System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
			[System.GC]::Collect()
			[System.GC]::WaitForPendingFinalizers()
			Remove-Variable excel
			
			Write-Host "MessageTrace har nu blivit exporterad till " -NoNewline
			Write-Host $fileName -Foreground Cyan
		}
	} else {
		$mails
	}
}

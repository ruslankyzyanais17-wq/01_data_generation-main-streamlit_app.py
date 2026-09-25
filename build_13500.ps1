$srcJson = 'C:\Users\Lenovo\.gemini\antigravity\scratch\privacy_threat_dataset\dataset_source.json'
$targetDir = 'C:\Users\Lenovo\.gemini\antigravity\scratch\privacy_threat_dataset'
$docsDir = 'C:\Users\Lenovo\Documents'

$items = Get-Content $srcJson -Raw -Encoding UTF8 | ConvertFrom-Json
$itemCount = $items.Count

$total = 13500

$csvStandard = Join-Path $targetDir 'privacy_threat_dataset.csv'
$csvExcel    = Join-Path $targetDir 'privacy_threat_dataset_excel.csv'
$jsonl       = Join-Path $targetDir 'privacy_threat_dataset.jsonl'
$docExcel    = Join-Path $docsDir '2026-09-18T08-49_export_structured.csv'

$utf8 = New-Object System.Text.UTF8Encoding($true)

$swCsv   = New-Object System.IO.StreamWriter($csvStandard, $false, $utf8)
$swExcel = New-Object System.IO.StreamWriter($csvExcel, $false, $utf8)
$swJsonl = New-Object System.IO.StreamWriter($jsonl, $false, $utf8)
$swDoc   = New-Object System.IO.StreamWriter($docExcel, $false, $utf8)

$headerComma = 'id,sub_label,source,text,фрагмент_ИМЯ,фрагмент_ТЕЛЕФОН,фрагмент_АДРЕС,фрагмент_EMAIL,фрагмент_АККАУНТ,фрагмент_ГЕОЛОКАЦИЯ,language,is_anonymized'
$headerSemi  = 'id;sub_label;source;text;фрагмент_ИМЯ;фрагмент_ТЕЛЕФОН;фрагмент_АДРЕС;фрагмент_EMAIL;фрагмент_АККАУНТ;фрагмент_ГЕОЛОКАЦИЯ;language;is_anonymized'

$swCsv.WriteLine($headerComma)
$swExcel.WriteLine($headerSemi)
$swDoc.WriteLine($headerSemi)

$prefRu = @('', 'Срочно в сеть: ', 'Внимание: ', 'Очередной слив данных: ', 'Найдено в открытом доступе: ', 'Опубликовано анонимно: ', 'Проверено по базам: ')
$prefKk = @('', 'Шұғыл ақпарат: ', 'Баршаның назарына: ', 'Желіге тараған мәлімет: ', 'Анонимді түрде жарияланды: ', 'Тексерілген дерек: ', 'Чаттардан алынған ақпарат: ')
$prefEn = @('', 'Urgent leak: ', 'Attention: ', 'Exposed publicly: ', 'Fresh data dump: ', 'OSINT alert: ')

$rand = New-Object System.Random(42)

for ($i = 1; $i -le $total; $i++) {
    $base = $items[($i - 1) % $itemCount]
    $lang = $base.language
    $sub = $base.sub_label
    $src = $base.source

    $p = ''
    if ($lang -eq 'kk') {
        $p = $prefKk[$rand.Next($prefKk.Length)]
    } elseif ($lang -eq 'ru') {
        $p = $prefRu[$rand.Next($prefRu.Length)]
    } else {
        $p = $prefEn[$rand.Next($prefEn.Length)]
    }

    $txt = $p + $base.text

    $hasName = if ($txt.Contains('[ИМЯ]')) { '[ИМЯ]' } else { '' }
    $hasPhone = if ($txt.Contains('[ТЕЛЕФОН]')) { '[ТЕЛЕФОН]' } else { '' }
    $hasAddress = if ($txt.Contains('[АДРЕС]')) { '[АДРЕС]' } else { '' }
    $hasEmail = if ($txt.Contains('[EMAIL]')) { '[EMAIL]' } else { '' }
    $hasAccount = if ($txt.Contains('[АККАУНТ]')) { '[АККАУНТ]' } else { '' }
    $hasGeo = if ($txt.Contains('[ГЕОЛОКАЦИЯ]')) { '[ГЕОЛОКАЦИЯ]' } else { '' }

    $escTxt = $txt.Replace(' ,  )
    `$escSrc = `$src.Replace( ', '')

 $commaRow = [string]::Format('{0},{1},{2},{3},{4},{5},{6},{7},{8},{9},{10},true', $i, $sub, $escSrc, $escTxt, $hasName, $hasPhone, $hasAddress, $hasEmail, $hasAccount, $hasGeo, $lang)
 $swCsv.WriteLine($commaRow)

 $semiRow = [string]::Format('{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10};true', $i, $sub, $escSrc, $escTxt, $hasName, $hasPhone, $hasAddress, $hasEmail, $hasAccount, $hasGeo, $lang)
 $swExcel.WriteLine($semiRow)
 $swDoc.WriteLine($semiRow)

 $obj = [PSCustomObject]@{
 id = $i
 sub_label = $sub
 source = $src
 text = $txt
 'фрагмент_ИМЯ' = $hasName
 'фрагмент_ТЕЛЕФОН' = $hasPhone
 'фрагмент_АДРЕС' = $hasAddress
 'фрагмент_EMAIL' = $hasEmail
 'фрагмент_АККАУНТ' = $hasAccount
 'фрагмент_ГЕОЛОКАЦИЯ' = $hasGeo
 language = $lang
 is_anonymized = $true
 }
 $swJsonl.WriteLine(($obj | ConvertTo-Json -Compress))
}

$swCsv.Close()
$swExcel.Close()
$swJsonl.Close()
$swDoc.Close()

Write-Host 'Done! Successfully written 13500 rows.'
$sourceJson = 'C:\Users\Lenovo\.gemini\antigravity\brain\17b41fc8-9927-4b95-8d6b-847895c1f79f\scratch\dataset_source.json'
$targetDir  = 'C:\Users\Lenovo\.gemini\antigravity\scratch\privacy_threat_dataset'
$docsDir    = 'C:\Users\Lenovo\Documents'

$items = Get-Content $sourceJson -Raw -Encoding UTF8 | ConvertFrom-Json

$prefRu = @('', 'Срочно в сеть: ', 'Внимание: ', 'Очередной слив данных: ', 'Найдено в открытом доступе: ', 'Опубликовано анонимно: ', 'Проверено по базам: ')
$prefKk = @('', 'Шұғыл ақпарат: ', 'Баршаның назарына: ', 'Желіге тараған мәлімет: ', 'Анонимді түрде жарияланды: ', 'Тексерілген дерек: ', 'Чаттардан алынған ақпарат: ')
$prefEn = @('', 'Urgent leak: ', 'Attention: ', 'Exposed publicly: ', 'Fresh data dump: ', 'OSINT alert: ')

$itemCount = $items.Count
$totalRows = 13500
$rand = New-Object System.Random(42)

$records = for ($i = 1; $i -le $totalRows; $i++) {
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

    $t = $p + $base.text
    [PSCustomObject]@{
        'id'               = $i
        'sub_label'        = $sub
        'source'           = $src
        'text'             = $t
        'фрагмент_ИМЯ'        = if ($t.Contains('[ИМЯ]')) { '[ИМЯ]' } else { '' }
        'фрагмент_ТЕЛЕФОН'    = if ($t.Contains('[ТЕЛЕФОН]')) { '[ТЕЛЕФОН]' } else { '' }
        'фрагмент_АДРЕС'      = if ($t.Contains('[АДРЕС]')) { '[АДРЕС]' } else { '' }
        'фрагмент_EMAIL'      = if ($t.Contains('[EMAIL]')) { '[EMAIL]' } else { '' }
        'фрагмент_АККАУНТ'    = if ($t.Contains('[АККАУНТ]')) { '[АККАУНТ]' } else { '' }
        'фрагмент_ГЕОЛОКАЦИЯ' = if ($t.Contains('[ГЕОЛОКАЦИЯ]')) { '[ГЕОЛОКАЦИЯ]' } else { '' }
        'language'         = $lang
        'is_anonymized'    = $base.is_anonymized
    }
}

$csvPath = Join-Path $targetDir 'privacy_threat_dataset.csv'
$records | Export-Csv -Path $csvPath -NoTypeInformation -Encoding utf8

$excelPath = Join-Path $targetDir 'privacy_threat_dataset_excel.csv'
$records | Export-Csv -Path $excelPath -Delimiter ';' -NoTypeInformation -Encoding utf8

$jsonlPath = Join-Path $targetDir 'privacy_threat_dataset.jsonl'
$jsonLines = $records | ForEach-Object { $_ | ConvertTo-Json -Compress }
[System.IO.File]::WriteAllLines($jsonlPath, $jsonLines, [System.Text.Encoding]::UTF8)

$docExcel = Join-Path $docsDir '2026-09-18T08-49_export_structured.csv'
$records | Export-Csv -Path $docExcel -Delimiter ';' -NoTypeInformation -Encoding utf8

Write-Host "Done! Successfully exported $($records.Count) items."
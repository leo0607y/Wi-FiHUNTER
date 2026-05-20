<#
.SYNOPSIS
Wi-Fiデバイス可視化ツールの環境自動構築および起動スクリプト。
管理者権限の自動要求、Npcap/Pythonの検知、venv環境構築、実行を行います。
#>

# 1. 管理者権限（Administrator）のチェックと自動昇格

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] パケット送受信を行うため、管理者権限への昇格が必要です。" -ForegroundColor Yellow
    Write-Host "[*] ユーザーアカウント制御 (UAC) 画面が表示されたら 'はい' を選択してください..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1

    # 自身を管理者権限かつ実行ポリシーBypassで再起動
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# 管理者として実行中

Clear-Host
Write-Host "==========================================================" -ForegroundColor Green
Write-Host "    Wi-Fi接続デバイス可視化ツール 自動ランチャー (管理者)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

# 2. Pythonの存在チェック

try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] Python が検出されました: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[エラー] Python がインストールされていないか、PATHが通っていません。" -ForegroundColor Red
    Write-Host "公式サイト (https://www.python.org/) から Python をインストールし、" -ForegroundColor Yellow
    Write-Host "インストール時に必ず 'Add Python to PATH' にチェックを入れてください。" -ForegroundColor Yellow
    Write-Host "プログラムを終了するには何かキーを押してください..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}

# 3. Npcap / WinPcap ドライバの存在チェック (WindowsのScapy動作に必須)

$npcapPath1 = "$env:SystemRoot\System32\Npcap"
$npcapPath2 = "$env:SystemRoot\System32\wpcap.dll"
if (-not (Test-Path $npcapPath1) -and -not (Test-Path $npcapPath2)) {
    Write-Host "`n[警告] Windowsでネットワークパケットを制御するための 'Npcap' ドライバが見つかりません。" -ForegroundColor Yellow
    Write-Host "Scapyを動かすには Npcap のインストールが必須です。" -ForegroundColor Yellow
    Write-Host "1. https://npcap.com/ から最新の 'Npcap Installer' をダウンロードしてインストールしてください。" -ForegroundColor Cyan
    Write-Host "2. インストール完了後、このスクリプトを再度実行してください。" -ForegroundColor Cyan
    Write-Host "Npcapダウンロードサイトを開きますか？ (Y/N): " -NoNewline
    $ans = Read-Host
    if ($ans -eq "Y" -or $ans -eq "y") {
        Start-Process "https://npcap.com/#download"
    }
    Exit
}

# 4. スクリプトの実行カレントディレクトリをこのファイルの場所に合わせる

Set-Location $PSScriptRoot

# 5. Python 仮想環境 (.venv) のセットアップ

if (-not (Test-Path ".venv")) {
    Write-Host "`n[*] 仮想環境 (.venv) を作成しています..." -ForegroundColor Cyan
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[エラー] 仮想環境の作成に失敗しました。" -ForegroundColor Red
        Exit
    }
    Write-Host "[OK] 仮想環境を作成しました。" -ForegroundColor Green
}

# 6. 仮想環境のアクティベート

Write-Host "[*] 仮想環境を有効化しています..." -ForegroundColor Cyan
& ".\.venv\Scripts\Activate.ps1"

# 7. 依存パッケージのインストール/同期

Write-Host "[*] 依存ライブラリ (scapy, mac-vendor-lookup) のインストール状況を確認中..." -ForegroundColor Cyan
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host "[エラー] ライブラリのインストールに失敗しました。" -ForegroundColor Red
    Exit
}
Write-Host "[OK] ライブラリのセットアップが完了しました。" -ForegroundColor Green

# 8. スキャナーの実行

Write-Host "`n[*] リアルタイム接続スキャナーを起動します..." -ForegroundColor Cyan
Start-Sleep -Seconds 1
Clear-Host

python app/scanner.py

# 実行完了後に一時停止

Write-Host "`n処理が完了しました。Enterキーを押すと終了します..." -ForegroundColor Gray
$null = Read-Host

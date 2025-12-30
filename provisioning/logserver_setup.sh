#!/bin/bash
# ============================================
# BlackDomain - Log Server Setup Script
# ============================================
# Este script configura o servidor Ubuntu com
# Wazuh SIEM para monitoramento centralizado
# ============================================

echo "========================================"
echo "  BlackDomain - Log Server Setup"
echo "========================================"
echo ""

# Atualizar sistema
echo "[*] Atualizando sistema..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# Instalar dependências
echo "[*] Instalando dependências..."
apt-get install -y -qq \
    curl \
    wget \
    git \
    net-tools \
    vim \
    htop

# Instalar Docker
echo "[*] Instalando Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    rm get-docker.sh
    systemctl enable docker
    systemctl start docker
fi

# Instalar Docker Compose
echo "[*] Instalando Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    curl -L "https://github.com/docker/compose/releases/download/v2.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
fi

# Criar diretório para Wazuh
echo "[*] Configurando Wazuh..."
mkdir -p /opt/wazuh
cd /opt/wazuh

# Baixar docker-compose do Wazuh
echo "[*] Baixando configuração do Wazuh..."
curl -so docker-compose.yml https://raw.githubusercontent.com/wazuh/wazuh-docker/v4.8.0/single-node/docker-compose.yml

# Criar configuração customizada
cat > /opt/wazuh/custom_ossec.conf << 'EOF'
<!-- Configuração customizada para BlackDomain -->
<ossec_config>
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
</ossec_config>
EOF

# Iniciar Wazuh
echo "[*] Iniciando containers do Wazuh..."
docker-compose up -d

# Aguardar Wazuh iniciar
echo "[*] Aguardando Wazuh inicializar (isso pode levar alguns minutos)..."
sleep 60

# Verificar status
echo "[*] Verificando status dos containers..."
docker-compose ps

# Criar diretório de flags
mkdir -p /opt/wazuh/flags

# FLAG 6: Acesso ao servidor de logs - XACK{1679091c5a880faf6fb5e6087eb1b2dc} (md5 de "6")
cat > /opt/wazuh/flags/flag6.txt << 'EOF'
╔════════════════════════════════════════╗
║     BlackDomain - Log Server Flag     ║
╚════════════════════════════════════════╝

Parabéns! Você conseguiu acessar o servidor de logs.

FLAG: XACK{1679091c5a880faf6fb5e6087eb1b2dc}

Dica: Explore os logs do Wazuh para encontrar evidências
de ataques e atividades suspeitas no domínio.

Dashboard: https://10.10.10.20
Usuário padrão: admin
Senha padrão: SecretPassword (verifique docker-compose.yml)
EOF

# FLAG 7: Root no servidor Linux - XACK{8f14e45fceea167a5a36dedd4bea2543} (md5 de "7")
cat > /root/flag7.txt << 'EOF'
XACK{8f14e45fceea167a5a36dedd4bea2543}

Você obteve acesso root ao servidor de logs!
EOF

# Configurar mensagem de boas-vindas
cat > /etc/motd << 'EOF'
╔════════════════════════════════════════════════════════╗
║                                                        ║
║           BlackDomain - Log Server (Wazuh)            ║
║                                                        ║
║  Este servidor coleta e analisa logs de segurança     ║
║  de todo o domínio BlackDomain.local                  ║
║                                                        ║
║  Wazuh Dashboard: https://10.10.10.20                 ║
║                                                        ║
╚════════════════════════════════════════════════════════╝
EOF

# Criar script de informações
cat > /usr/local/bin/blackdomain-info << 'EOF'
#!/bin/bash
echo "========================================="
echo "  BlackDomain - Informações do Sistema"
echo "========================================="
echo ""
echo "Hostname: $(hostname)"
echo "IP: 10.10.10.20"
echo "Função: Servidor de Logs (Wazuh SIEM)"
echo ""
echo "Serviços:"
docker-compose -f /opt/wazuh/docker-compose.yml ps
echo ""
echo "Acesso ao Dashboard:"
echo "  URL: https://10.10.10.20"
echo "  Usuário: admin"
echo "  Senha: Verifique /opt/wazuh/docker-compose.yml"
echo ""
echo "Flags disponíveis:"
echo "  - /opt/wazuh/flags/flag6.txt"
echo "  - /root/flag7.txt (requer root)"
echo ""
EOF
chmod +x /usr/local/bin/blackdomain-info

# Configurar firewall básico
echo "[*] Configurando firewall..."
ufw --force enable
ufw allow 22/tcp    # SSH
ufw allow 443/tcp   # Wazuh Dashboard
ufw allow 1514/tcp  # Wazuh Agent Communication
ufw allow 1515/tcp  # Wazuh Agent Enrollment
ufw allow 55000/tcp # Wazuh API

# Criar script de reset
cat > /opt/wazuh/reset.sh << 'EOF'
#!/bin/bash
echo "[*] Resetando ambiente Wazuh..."
cd /opt/wazuh
docker-compose down
docker-compose up -d
echo "[+] Ambiente resetado!"
EOF
chmod +x /opt/wazuh/reset.sh

# Informações finais
echo ""
echo "========================================"
echo "  Configuração Concluída!"
echo "========================================"
echo ""
echo "Servidor de Logs configurado com sucesso!"
echo ""
echo "Informações:"
echo "  - IP: 10.10.10.20"
echo "  - Dashboard: https://10.10.10.20"
echo "  - Flags: 2 flags inseridas"
echo ""
echo "Execute 'blackdomain-info' para mais detalhes"
echo ""

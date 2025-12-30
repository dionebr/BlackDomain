# -*- mode: ruby -*-
# vi: set ft=ruby :

# BlackDomain - Ambiente Active Directory para CTF
# Baseado em: christophetd/Adaz
# Melhorado com: Wazuh SIEM, múltiplas vulnerabilidades e flags XACK

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box_check_update = false
  
  # Configuração global de rede removida para evitar conflitos DHCP
  # As redes serão definidas por máquina individualmente

  ### === CONTROLADOR DE DOMÍNIO (DC01) === ###
  config.vm.define "dc01" do |dc|
    dc.vm.box = "gusztavvargadr/windows-server-2019-standard"
    dc.vm.hostname = "dc01"
    dc.vm.network "private_network", ip: "10.10.10.10", netmask: "255.255.255.0"
    
    dc.vm.provider "virtualbox" do |vb|
      vb.name = "BlackDomain-DC01"
      vb.memory = 2048
      vb.cpus = 2
      vb.gui = false
      vb.customize ["modifyvm", :id, "--vram", "128"]
      vb.customize ["modifyvm", :id, "--clipboard", "bidirectional"]
    end
    
    dc.vm.provision "shell", path: "provisioning/dc_setup.ps1", privileged: true
  end

  ### === WORKSTATION 1 (WS01) === ###
  config.vm.define "ws01" do |ws1|
    ws1.vm.box = "gusztavvargadr/windows-10-21h2-enterprise"
    ws1.vm.hostname = "ws01"
    ws1.vm.network "private_network", ip: "10.10.20.11", netmask: "255.255.255.0"
    
    ws1.vm.provider "virtualbox" do |vb|
      vb.name = "BlackDomain-WS01"
      vb.memory = 2048
      vb.cpus = 2
      vb.gui = false
      vb.customize ["modifyvm", :id, "--vram", "128"]
    end
    
    ws1.vm.provision "shell", path: "provisioning/ws_setup.ps1", privileged: true
  end

  ### === WORKSTATION 2 (WS02) === ###
  config.vm.define "ws02" do |ws2|
    ws2.vm.box = "gusztavvargadr/windows-10-21h2-enterprise"
    ws2.vm.hostname = "ws02"
    ws2.vm.network "private_network", ip: "10.10.20.12", netmask: "255.255.255.0"
    
    ws2.vm.provider "virtualbox" do |vb|
      vb.name = "BlackDomain-WS02"
      vb.memory = 2048
      vb.cpus = 2
      vb.gui = false
      vb.customize ["modifyvm", :id, "--vram", "128"]
    end
    
    ws2.vm.provision "shell", path: "provisioning/ws_setup.ps1", privileged: true
  end

  ### === SERVIDOR DE LOGS (LOGSRV) === ###
  config.vm.define "logsrv" do |log|
    log.vm.box = "ubuntu/jammy64"
    log.vm.hostname = "logsrv"
    log.vm.network "private_network", ip: "10.10.10.20", netmask: "255.255.255.0"
    
    log.vm.provider "virtualbox" do |vb|
      vb.name = "BlackDomain-LogServer"
      vb.memory = 1024
      vb.cpus = 2
      vb.gui = false
    end
    
    log.vm.provision "shell", path: "provisioning/logserver_setup.sh", privileged: true
  end
end

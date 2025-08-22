# 🧪 Wireshark Lab Setup Guide

This guide explains how to set up and run the **Wireshark Practice Lab** on Parrot OS (or other Debian-based systems) using **Vagrant + Libvirt (KVM)**.  

---

## 📂 Step 1: Unzip the Lab Files
```bash
unzip wireshark_lab.zip
cd wireshark_lab/documentation
cherrytree Setuplab.ctb
```

---

## 🔧 Step 2: Install Packages and Load KVM Modules
Install the virtualization stack:
```bash
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager cpu-checker
```

Load KVM kernel modules:
```bash
# Check your CPU vendor
lscpu | grep 'Vendor ID'

# Common base
sudo modprobe kvm

# For Intel CPUs
sudo modprobe kvm_intel

# For AMD CPUs
sudo modprobe kvm_amd

# Verify device node
ls -l /dev/kvm
```

---

## 🔧 Step 3: Verify KVM Support
```bash
kvm-ok
```

```plaintext
Expected output:
INFO: /dev/kvm exists
KVM acceleration can be used
```

---

## 🔧 Step 4: Enable and Start libvirtd
```bash
sudo systemctl enable --now libvirtd
```

```bash
# Add your user to groups
sudo usermod -aG kvm,libvirt $USER
newgrp libvirt
```

```bash
# Check service status
systemctl is-active libvirtd
```

---

## 🚀 Step 5: Bring Up the Lab
```bash
export LIBVIRT_DEFAULT_URI=qemu:///system
VAGRANT_DEFAULT_PROVIDER=libvirt vagrant up
```

---

## ⚠️ Troubleshooting
```plaintext
- No /dev/kvm device:
  → Enable Intel VT-x or AMD-V (SVM) in BIOS/UEFI
  → Disable Secure Boot if modules are blocked
  → If running Parrot inside VirtualBox/VMware/Hyper-V, enable nested virtualization on the outer host
```

---

## 🛠️ Sanity Checks
```bash
# Router forwarding and addresses
vagrant ssh ws-router  -c "ip a; sysctl net.ipv4.ip_forward"

# Server reachable from its own subnet
vagrant ssh ws-server  -c "curl -s http://10.20.20.20 | head"

# Victim ↔ Server connectivity
vagrant ssh ws-victim  -c "ping -c2 10.20.20.20"
vagrant ssh ws-victim  -c "dig +short server.lab.local @10.20.20.20"

# Sensor capture quick test
vagrant ssh ws-sensor  -c "/opt/capture/cap_netA.sh & sleep 3; pkill tshark; ls -l ~/*.pcapng"

# Attacker activity
vagrant ssh ws-attacker -c "nmap -sS -p 1-1000 10.20.20.20"
```

---

## 📡 Generate Traffic
Victim:
```bash
vagrant ssh ws-victim
curl http://server.lab.local
ftp 10.20.20.20
```

Attacker:
```bash
vagrant ssh ws-attacker
nmap -sS -p- 10.20.20.20
python3 /opt/traffic/beacon.py &
sudo hping3 -S -p 80 -c 50 10.20.20.20
```

Sensor (captures):
```bash
vagrant ssh ws-sensor
/opt/capture/cap_netA.sh
/opt/capture/cap_netB.sh
```

Copy PCAPs to host:
```bash
vagrant scp ws-sensor:~/*.pcapng ./captures/
```

---

## 🔍 Wireshark / Tshark Exercises
```plaintext
- SYN scan detection: tcp.flags.syn == 1 && tcp.flags.ack == 0
- Beaconing: filter http.request.method == "GET" and check inter-arrival deltas / IO Graphs
- FTP creds in clear: ftp.request.command == "USER" || ftp.request.command == "PASS"
- DNS oddities / exfil markers: dns && !(dns.qry.name contains "lab.local")
- TLS handshake sanity: tls.handshake → verify versions/ciphers, JA3, SNI
- Reassemble HTTP object: Follow TCP Stream or use tshark -q -z http,stat,1 -r file.pcapng
```

---

## 🧱 Hardening & Isolation
```bash
# Block anything but intra-lab on router with nftables
sudo nft add rule inet filter forward ip daddr != {10.10.10.0/24,10.20.20.0/24} drop

# Snapshotting
vagrant snapshot save baseline
```

---

## 🔄 Lifecycle
```bash
# Start lab
vagrant up

# Pause / resume
vagrant suspend
vagrant resume

# Snapshot before a risky test
vagrant snapshot save pre-mitm

# Destroy when done
vagrant destroy -f
```

---

## 📑 Quick Commands Cheat Sheet
Victim:
```bash
curl http://server.lab.local
ftp 10.20.20.20
```

Attacker:
```bash
nmap -sS -p- 10.20.20.20
python3 /opt/traffic/beacon.py &
sudo hping3 -S -p 80 -c 200 10.20.20.20
```

Sensor:
```bash
/opt/capture/cap_netA.sh
/opt/capture/cap_netB.sh
```

Server self-test:
```bash
curl -s http://10.20.20.20 | head
```

Router:
```bash
sysctl net.ipv4.ip_forward
sudo nft list ruleset
```

---

## 📝 License
This lab setup is provided for **educational and testing purposes only**.  

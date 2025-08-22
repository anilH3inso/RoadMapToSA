# 🧪 Wireshark Practice Lab (Vagrant + Libvirt)

This project provides a reproducible, isolated Wireshark practice lab using **Vagrant**, **libvirt/QEMU**, and **Ubuntu 22.04** base boxes.  
The lab simulates a small network with realistic traffic flows between:

- **Router** (`ws-router`)
- **Server** (`ws-server`)
- **Victim** (`ws-victim`)
- **Sensor** (`ws-sensor`)
- **Attacker** (`ws-attacker`)

PCAPs can be captured on the sensor and analyzed with **Wireshark/Tshark**.

---

## ⚙️ 1. Prerequisites

Make sure hardware virtualization is enabled in BIOS/UEFI (**Intel VT-x / AMD-V**).  
Check support:

```bash
lscpu | grep -i virtualization
```

Expected: `VT-x` (Intel) or `AMD-V`.

Install required system packages:

```bash
sudo apt update
sudo apt install -y qemu-system-x86 \
  libvirt-daemon-system libvirt-daemon-driver-qemu libvirt-clients \
  bridge-utils virt-manager \
  curl gpg lsb-release build-essential pkg-config
```

Enable libvirtd and add yourself to the correct groups:

```bash
sudo systemctl enable --now libvirtd
sudo usermod -aG kvm,libvirt $USER
newgrp libvirt
```

---

## 📦 2. Vagrant Setup

> ⚠️ On Parrot/Debian, the distro Vagrant package may be broken. Use the official HashiCorp build if `/usr/bin/vagrant` is missing.

### Install from HashiCorp:

```bash
sudo apt purge -y vagrant ruby-vagrant || true
sudo rm -f /usr/bin/vagrant

curl -fsSL https://apt.releases.hashicorp.com/gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update
sudo apt install -y vagrant
```

### Install libvirt provider plugin:

```bash
vagrant plugin install vagrant-libvirt
vagrant plugin update vagrant-libvirt
```

Verify:

```bash
vagrant --version
vagrant plugin list
```

---

## 📂 3. Project Setup

Clone/unzip this repo:

```bash
cd ~/Desktop
unzip wireshark_lab.zip -d wireshark_lab
cd wireshark_lab
```

Run the one-time setup script:

```bash
chmod +x setup_lab.sh
./setup_lab.sh ~/Desktop/wireshark_lab
```

This will:
- Install missing dependencies
- Fix permissions
- Patch `Vagrantfile` with sane defaults (`machine_type = "q35"`, `cpu_mode = "host-model"`)
- Force software QEMU if `/dev/kvm` is missing
- Create `.env-vagrant` with environment exports

---

## ▶️ 4. Starting the Lab

Always load the environment variables:

```bash
source .env-vagrant
```

Bring the lab up (serial to avoid libvirt race conditions):

```bash
vagrant up --no-parallel
```

Check domains:

```bash
virsh -c qemu:///system list --all
```

---

## 🔍 5. Sanity Checks

Router forwarding & addresses:
```bash
vagrant ssh ws-router -c "ip a; sysctl net.ipv4.ip_forward"
```

Server reachable:
```bash
vagrant ssh ws-server -c "curl -s http://10.20.20.20 | head"
```

Victim ↔ Server connectivity:
```bash
vagrant ssh ws-victim -c "ping -c2 10.20.20.20"
vagrant ssh ws-victim -c "dig +short server.lab.local @10.20.20.20"
```

Sensor capture test:
```bash
vagrant ssh ws-sensor -c "/opt/capture/cap_netA.sh & sleep 3; pkill tshark; ls -l ~/*.pcapng"
```

Attacker activity:
```bash
vagrant ssh ws-attacker -c "nmap -sS -p 1-1000 10.20.20.20"
```

---

## 🧰 6. Traffic Generation

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

Sensor (capture and copy PCAPs to host):
```bash
vagrant ssh ws-sensor
/opt/capture/cap_netA.sh
/opt/capture/cap_netB.sh

# Copy PCAPs out
vagrant scp ws-sensor:~/*.pcapng ./captures/
```

---

## 🔎 7. Wireshark/Tshark Exercises

- **SYN scan detection**  
  `tcp.flags.syn == 1 && tcp.flags.ack == 0`

- **Beaconing**  
  `http.request.method == "GET"` and check inter-arrival deltas

- **FTP creds in clear**  
  `ftp.request.command == "USER" || ftp.request.command == "PASS"`

- **DNS oddities**  
  `dns && !(dns.qry.name contains "lab.local")`

- **TLS sanity**  
  Inspect `tls.handshake` versions, ciphers, JA3, SNI

---

## 🔒 8. Hardening & Isolation

By default, libvirt networks use `forward_mode: none` (no external egress).  
Extra firewall rule on router:

```bash
sudo nft add rule inet filter forward ip daddr != {10.10.10.0/24,10.20.20.0/24} drop
```

Snapshot baseline after first successful boot:

```bash
vagrant snapshot save baseline
```

---

## 🛠️ 9. Troubleshooting

- **/dev/kvm missing** → enable Intel VT-x / AMD-V in BIOS/UEFI, or enable nested virtualization if inside a VM.
- **Connection refused on SSH** → VM still booting, cloud-init not finished, or sshd not started.
- **Preferred machine type errors** → set `libvirt.machine_type = "q35"` (or `"pc"`) in `Vagrantfile`.
- **Slow first boot** → add:
  ```ruby
  config.vm.boot_timeout = 600
  config.ssh.keep_alive  = true
  ```
- **Network stuck** → restart network:
  ```bash
  sudo virsh net-destroy vagrant-libvirt
  sudo virsh net-start vagrant-libvirt
  ```

---

## 📚 10. Lifecycle

```bash
# Start lab
vagrant up --no-parallel

# Pause / resume
vagrant suspend
vagrant resume

# Snapshot before a risky test
vagrant snapshot save pre-mitm

# Destroy when done
vagrant destroy -f
```

---

## ✅ 11. Cheat Sheet

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

Server:
```bash
curl -s http://10.20.20.20 | head
```

Router:
```bash
sysctl net.ipv4.ip_forward
sudo nft list ruleset
```

---

Done! 🎉 You now have a reproducible Wireshark practice lab with realistic traffic and capture paths.

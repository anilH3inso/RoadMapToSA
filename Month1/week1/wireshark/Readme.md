# 🧪 Wireshark Lab Setup Guide

This guide explains how to set up and run the **Wireshark Practice Lab** on Parrot OS (or other Debian-based systems) using **Vagrant + Libvirt (KVM)**.  

---

## 📂 Step 1: Unzip the Lab Files
```bash
unzip wireshark_lab.zip
cd wireshark_lab/documentation
Open the CherryTree file for documentation:

bash
Copy
Edit
cherrytree Setuplab.ctb
🔧 Step 2: Install Required Packages
Make sure the virtualization stack is installed:

bash
Copy
Edit
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager cpu-checker
🔧 Step 3: Load KVM Kernel Modules
Check your CPU vendor:

bash
Copy
Edit
lscpu | grep 'Vendor ID'
Load the appropriate kernel modules:

bash
Copy
Edit
# Common base
sudo modprobe kvm

# For Intel CPUs
sudo modprobe kvm_intel

# For AMD CPUs
sudo modprobe kvm_amd
Verify that the device node exists:

bash
Copy
Edit
ls -l /dev/kvm
🔧 Step 4: Verify KVM Support
bash
Copy
Edit
kvm-ok
plaintext
Copy
Edit
Expected output:
INFO: /dev/kvm exists
KVM acceleration can be used
🔧 Step 5: Enable and Start libvirtd
Enable the libvirt service:

bash
Copy
Edit
sudo systemctl enable --now libvirtd
Add your user to the necessary groups:

bash
Copy
Edit
sudo usermod -aG kvm,libvirt $USER
newgrp libvirt
Check service status:

bash
Copy
Edit
systemctl is-active libvirtd
🚀 Step 6: Bring Up the Lab
From your lab directory:

bash
Copy
Edit
export LIBVIRT_DEFAULT_URI=qemu:///system
VAGRANT_DEFAULT_PROVIDER=libvirt vagrant up
⚠️ Troubleshooting
plaintext
Copy
Edit
- No /dev/kvm device:
  → Enable Intel VT-x or AMD-V (SVM) in BIOS/UEFI
  → Disable Secure Boot if modules are blocked
  → If running Parrot inside VirtualBox/VMware/Hyper-V, enable nested virtualization on the outer ho

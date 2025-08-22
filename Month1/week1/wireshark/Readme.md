### Follow the steps
1. Unzip wireshark_lab.zip
2. go to documentation file 
3. open Setuplab.ctb in cherry tree app 


🔧 Step 1: Install required packages

Make sure the virtualization stack is installed:

sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager cpu-checker

🔧 Step 2: Load KVM kernel modules

Check your CPU vendor:

lscpu | grep 'Vendor ID'


Then run:

# Common base
sudo modprobe kvm

# For Intel CPUs:
sudo modprobe kvm_intel

# For AMD CPUs:
# sudo modprobe kvm_amd


👉 Now check if the device node appeared:

ls -l /dev/kvm

🔧 Step 3: Verify KVM support
kvm-ok


Expected:
INFO: /dev/kvm exists KVM acceleration can be used

🔧 Step 4: Enable and start libvirtd
sudo systemctl enable --now libvirtd


Also add your user to groups so you don’t need root every time:

sudo usermod -aG kvm,libvirt $USER
newgrp libvirt


Check:

systemctl is-active libvirtd

🔧 Step 5: Retry Vagrant

Now from your lab directory:

export LIBVIRT_DEFAULT_URI=qemu:///system
VAGRANT_DEFAULT_PROVIDER=libvirt vagrant up

⚠️ If /dev/kvm still doesn’t appear:

BIOS/UEFI issue → Reboot and enable Intel VT-x or AMD-V (SVM).

Secure Boot enabled → Sometimes blocks KVM modules → disable Secure Boot in BIOS.

Nested VM → If Parrot is running inside VirtualBox/VMware/Hyper-V, you’ll need to enable nested virtualization on the outer host (tell me your outer hypervisor and I’ll give you the exact command).

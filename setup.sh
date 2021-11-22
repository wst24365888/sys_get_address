# pre-setup
dir=$(pwd)
sudo apt update && sudo apt upgrade -y
sudo apt install build-essential libncurses-dev libssl-dev libelf-dev bison flex vim ccache -y

# download kernel
cd ~
wget https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.14.9.tar.xz
tar Jxvf linux-5.14.9.tar.xz
rm linux-5.14.9.tar.xz

# write source code for new syscall
cd ~/linux-5.14.9
mkdir get_address
cd get_address
cp $dir/get_address.c ./get_address.c
echo 'obj-y := get_address.o' >> Makefile

# edit config
cd ~/linux-5.14.9
## add get_address/ to core-y
vim Makefile
## add  449 common  get_address    sys_get_address
vim ~/linux-5.14.9/arch/x86/entry/syscalls/syscall_64.tbl
## append asmlinkage long sys_get_address(int mode, void *__user des_addr);
vim ~/linux-5.14.9/include/linux/syscalls.h

# compile
make clean
make menuconfig
## clear content in CONFIG_SYSTEM_TRUSTED_KEYS and SYSTEM_REVOCATION_KEYS
vim ~/linux-5.14.9/.config
make -j$(nproc) CC='ccache gcc'
make modules -j$(nproc) CC='ccache gcc'

# install
sudo make modules_install
sudo make install

# modify grub settings and restart
## comment out these two:
## GRUB_TIMEOUT_STYLE=hidden
## GRUB_TIMEOUT=0
sudo vim /etc/default/grub
sudo update-grub
reboot
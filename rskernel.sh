#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

#===============================================================#
# One Click Change Kernel to Adapt Serverspeeder for CentOS 6/7 #
# Github: https://github.com/uxh/shadowsocks_bash               #
# Author: https://www.banwagongzw.com & https://www.vultrcn.com #
#===============================================================#

#Color
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

#Check root
[[ $EUID -ne 0 ]] && echo -e "${red}This script must be run as root!${plain}" && exit 1

#Start information
clear
echo "#===============================================================#"
echo "# One Click Change Kernel to Adapt Serverspeeder for CentOS 6/7 #"
echo "# Github: https://github.com/uxh/shadowsocks_bash               #"
echo "# Author: https://www.banwagongzw.com & https://www.vultrcn.com #"
echo "#===============================================================#"
echo ""

#Check system
function check_release(){
    local value=$1

    local release=''

    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -Eqi "centos|red hat|redhat"; then
        release="centos"
    fi

    if [ "$value" == "$release" ]; then
        return 0
    else
        return 1
    fi
}

#Get centos main version
function get_centos_main_version(){
    if [[ -s /etc/redhat-release ]]; then
        grep -oE  "[0-9.]+" /etc/redhat-release
    else
        grep -oE  "[0-9.]+" /etc/issue
    fi
}

#Check centos main version
function check_centos_main_version(){
    local num=$1

    local version="$(get_centos_main_version)"
    local main_ver=${version%%.*}

    if [ "$num" == "$main_ver" ]; then
        return 0
    else
        return 1
    fi
}

#Main
if check_release centos; then
    if check_centos_main_version 6; then
        echo -e "[${green}INFO${plain}] System OS is CentOS6. Processing..."
        echo -e "-------------------------------------------"
        rpm -ivh https://filedown.me/Linux/Kernel/kernel-firmware-2.6.32-504.3.3.el6.noarch.rpm
        rpm -ivh https://filedown.me/Linux/Kernel/kernel-2.6.32-504.3.3.el6.x86_64.rpm --force
        if [ $? -eq 0 ]; then
            number=$(cat /boot/grub/grub.conf | awk '$1=="title" {print i++ " : " $NF}' | grep '2.6.32-504' | awk '{print $1}')
            sed -i "s/^default=.*/default=$number/g" /boot/grub/grub.conf
            echo -e "-------------------------------------------"
            echo -e "[${green}INFO${plain}] Success! Your server will reboot in 3s..."
            sleep 1
            echo -e "[${green}INFO${plain}] Success! Your server will reboot in 2s..."
            sleep 1
            echo -e "[${green}INFO${plain}] Success! Your server will reboot in 1s..."
            sleep 1
            echo -e "[${green}INFO${plain}] Reboot..."
            reboot
        else
            echo -e "[${red}ERROR${plain}] Change kernel failed!"
        fi
    elif check_centos_main_version 7; then
        echo -e "[${green}INFO${plain}] System OS is CentOS7. Processing..."
        echo -e "-------------------------------------------"
        rpm -ivh https://filedown.me/Linux/Kernel/kernel-3.10.0-229.1.2.el7.x86_64.rpm --force
        if [ $? -eq 0 ]; then
            grub2-set-default `awk -F\' '$1=="menuentry " {print i++ " : " $2}' /etc/grub2.cfg | grep '(3.10.0-229.1.2.el7.x86_64) 7 (Core)' | awk '{print $1}'`
            echo -e "-------------------------------------------"
            echo -e "[${green}INFO${plain}] Success! Your server will reboot in 3s..."
            sleep 1
            echo -e "[${green}INFO${plain}] Success! Your server will reboot in 2s..."
            sleep 1
            echo -e "[${green}INFO${plain}] Success! Your server will reboot in 1s..."
            sleep 1
            echo -e "[${green}INFO${plain}] Reboot..."
            reboot
        else
            echo -e "[${red}ERROR${plain}] Change kernel failed!"
        fi
    fi
else
    echo -e "[${yellow}WARNNING${plain}] This script only support CentOS6/7!"
	exit 1
fi

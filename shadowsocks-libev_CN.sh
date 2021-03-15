#! /usr/bin/env bash
PATH="/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin"
export PATH

#托管：https://github.com/uxh/shadowsocks_bash
#作者：https://www.banwagongzw.com & https://www.vultrcn.com
#致谢：https://teddysun.com

#设置输出颜色
red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"
plain="\033[0m"

#获取当前目录
currentdir=$(pwd)

#设置加密方式数组
ciphers=(
aes-256-gcm
aes-256-ctr
aes-256-cfb
chacha20-ietf-poly1305
chacha20-ietf
chacha20
rc4-md5
)

#环境及程序版本控制
libsodiumver="libsodium-1.0.18"
libsodiumurl="https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz"
mbedtlsver="mbedtls-2.16.6"
mbedtlsurl="https://tls.mbed.org/download/mbedtls-2.16.6-gpl.tgz"
shadowsocksver="shadowsocks-libev-3.3.5"
shadowsocksurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v3.3.5/shadowsocks-libev-3.3.5.tar.gz"
initscripturl="https://raw.githubusercontent.com/uxh/shadowsocks_bash/master/shadowsocks-libev"

#禁用 SElinux
function disable_selinux() {
    if [ -s /etc/selinux/config ] && grep "SELINUX=enforcing" /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}

#检查当前系统类型
function check_release() {
    local value=$1
    local release="none"

    if [ -f /etc/redhat-release ]; then
        release="centos"
    elif grep -qi "centos|red hat|redhat" /etc/issue; then
        release="centos"
    elif grep -qi "debian|raspbian" /etc/issue; then
        release="debian"
    elif grep -qi "ubuntu" /etc/issue; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /proc/version; then
        release="centos"
    elif grep -qi "debian" /proc/version; then
        release="debian"
    elif grep -qi "ubuntu" /proc/version; then
        release="ubuntu"
    elif grep -qi "centos|red hat|redhat" /etc/*-release; then
        release="centos"
    elif grep -qi "debian" /etc/*-release; then
        release="debian"
    elif grep -qi "ubuntu" /etc/*-release; then
        release="ubuntu"
    fi

    if [[ ${value} == ${release} ]]; then
        return 0
    else
        return 1
    fi
}

#检查 Shadowsocks 状态
function check_shadowsocks_status() {
    installedornot="not"
    runningornot="not"
    updateornot="not"
    command -v ss-server > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        installedornot="installed"
        ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            runningornot="running"
        fi
        local installedversion=$(ss-server -h | grep "shadowsocks-libev" | cut -d " " -f 2)
        local latestversion=$(echo "$(wget --no-check-certificate -qO- https://api.github.com/repos/shadowsocks/shadowsocks-libev/releases/latest | grep "tag_name" | cut -d "\"" -f 4)" | sed -e 's/^[a-zA-Z]//g')
        if [ ! -z ${latestversion} ]; then
            if [[ ${installedversion} != ${latestversion} ]]; then
                updateornot="update"
                shadowsocksnewver="shadowsocks-libev-${latestversion}"
                shadowsocksnewurl="https://github.com/shadowsocks/shadowsocks-libev/releases/download/v${latestversion}/${shadowsocksnewver}.tar.gz"
            fi
        fi
    fi
}

#检查 CentOS 系统大版本
function check_centos_main_version() {
    local value=$1
    local version="0.0.0"

    if [ -s /etc/redhat-release ]; then
        version=$(grep -Eo "[0-9.]+" /etc/redhat-release)
    else
        version=$(grep -Eo "[0-9.]+" /etc/issue)
    fi

    local mainversion=${version%%.*}

    if [ ${value} -eq ${mainversion} ]; then
        return 0
    else
        return 1
    fi
}

#检查当前系统内核一
function check_kernel_version() {
    local kernelversion=$(uname -r | cut -d "-" -f 1)
    local olderversion=$(echo "${kernelversion} 3.7.0" | tr " " "\n" | sort -V | head -n 1)
    if [[ ${olderversion} == "3.7.0" ]]; then
        return 0
    else
        return 1
    fi
}

#检查当前系统内核二
function check_kernel_headers() {
    local nowkernel=$(uname -r)
    if check_release centos; then
        rpm -qa | grep "headers-${nowkernel}" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    else
        dpkg -s linux-headers-${nowkernel} > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            return 0
        else
            return 1
        fi
    fi
}

#获取系统公网 IPv4
function get_ipv4() {
    local ipv4=$(ip addr | grep -Eo "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" | grep -Ev "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipv4.icanhazip.com)
    fi
    if [ -z ${ipv4} ]; then
        ipv4=$(wget -qO- -t 1 -T 10 ipinfo.io/ip)
    fi
    echo -e "${ipv4}"
}

#检查系统公网 IPv6
function check_ipv6() {
    local ipv6=$(wget -qO- -t 1 -T 10 ipv6.icanhazip.com)
    if [ -z ${ipv6} ]; then
        return 1
    else
        return 0
    fi
}

#设置 Shadowsocks 连接信息
function set_shadowsocks_config() {
    clear
    echo -e "${green}[提示]${plain} 开始配置 Shadowsocks 连接信息"
    echo -e "${green}[提示]${plain} 不清楚的地方，直接回车采用默认配置即可"
    echo ""
    echo "请设置 Shadowsocks 的连接密码"
    read -p "[默认为 Number1433223]：" sspassword
    if [ -z ${sspassword} ]; then
        sspassword="Number1433223"
    fi
    echo "-------------------------------"
    echo "连接密码已设置为：${sspassword}"
    echo "-------------------------------"

    local defaultport=$(shuf -i 9000-9999 -n 1)
    echo "请设置 Shadowsocks 连接端口（1~65535）"
    while true
    do
        read -p "[默认为 ${defaultport}]：" ssport
        if [ -z ${ssport} ]; then
            ssport=${defaultport}
        fi
        expr ${ssport} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ssport} -ge 1 ] && [ ${ssport} -le 65535 ]; then
                echo "-------------------------------"
                echo "连接端口已设置为：${ssport}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 65535 之间的数字！"
            fi
        else
            echo -e "${red}[错误]${plain} 请输入 1 和 65535 之间的数字！"
        fi
    done

    echo "请设置 Shadowsocks 的加密方式"
    for ((i=1;i<=${#ciphers[@]};i++));
    do
        local cipher=${ciphers[$i-1]}
        echo -e "${i}) ${cipher}"
    done
    while true
    do
        read -p "[默认为 ${ciphers[0]}]：" ciphernumber
        if [ -z ${ciphernumber} ]; then
            ciphernumber="1"
        fi
        expr ${ciphernumber} + 1 > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            if [ ${ciphernumber} -ge 1 ] && [ ${ciphernumber} -le ${#ciphers[@]} ]; then
                sscipher=${ciphers[${ciphernumber}-1]}
                echo "-------------------------------"
                echo "加密方式已设置为：${sscipher}"
                echo "-------------------------------"
                break
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 ${#ciphers[@]} 之间的数字！"
            fi
        else
            echo -e "${red}[错误]${plain} 请输入 1 和 ${#ciphers[@]} 之间的数字！"
        fi
    done

    echo ""
    echo "按回车键开始安装...或按 Ctrl+C 键取消"
    read -n 1
}

#安装依赖
function install_dependencies() {
    if check_release centos; then
        if [ ! -f /etc/yum.repos.d/epel.repo ]; then
            yum install -y epel-release
            if [ $? -ne 0 ]; then
                echo -e "${red}[错误]${plain} EPEL 更新源安装失败，请稍后重试！"
                exit 1
            fi
        fi
        command -v yum-config-manager > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            yum install -y yum-utils
        fi
        local epelstatus=$(yum-config-manager epel | grep -w "enabled" | cut -d " " -f 3)
        if [[ ${epelstatus} != "True" ]]; then
            yum-config-manager --enable epel
        fi
        yum install -y unzip openssl openssl-devel gettext gcc autoconf libtool automake make asciidoc xmlto libev-devel pcre pcre-devel git c-ares-devel wget
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} 依赖安装失败，请稍后重试！"
            exit 1
        fi
    else
        apt-get update
        apt-get install --no-install-recommends -y gettext build-essential autoconf automake libtool openssl libssl-dev zlib1g-dev libpcre3-dev libev-dev libc-ares-dev wget
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} 依赖安装失败，请稍后重试！"
            exit 1
        fi
    fi
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4" > /etc/resolv.conf
}

#设置防火墙
function set_firewall() {
    if check_release centos; then
        if check_centos_main_version 6; then
            /etc/init.d/iptables status > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                iptables -L -n | grep "${ssport}" > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${ssport} -j ACCEPT
                    iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${ssport} -j ACCEPT
                    /etc/init.d/iptables save
                    /etc/init.d/iptables restart
                fi
            fi
        elif check_centos_main_version 7; then
            systemctl status firewalld > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                firewall-cmd --query-port=${ssport}/tcp > /dev/null 2>&1
                if [ $? -ne 0 ]; then
                    firewall-cmd --permanent --zone=public --add-port=${ssport}/tcp
                    firewall-cmd --permanent --zone=public --add-port=${ssport}/udp
                    firewall-cmd --reload
                fi
            fi
        fi
    fi
}

#下载函数
function download() {
    local filename=$1

    if [ -s ${filename} ]; then
        echo -e "${green}[提示]${plain} ${filename} 已下载"
    else
        echo -e "${green}[提示]${plain} ${filename} 未找到，开始下载"
        wget --no-check-certificate -c -t 3 -T 60 -O $1 $2
        if [ $? -eq 0 ]; then
            echo -e "${green}[提示]${plain} ${filename} 下载完成"
        else
            echo -e "${red}[错误]${plain} ${filename} 下载失败，请稍后重试！"
            exit 1
        fi
    fi
}

#安装libsodium
function install_libsodium() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libsodium.a ]; then
        download "${libsodiumver}.tar.gz" "${libsodiumurl}"
        tar zxf ${libsodiumver}.tar.gz
        cd ${libsodiumver}
        ./configure --prefix=/usr && make && make install
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} ${libsodiumver} 安装失败，请稍后重试！"
            exit 1
        fi
    else
        echo -e "${green}[提示]${plain} ${libsodiumver} 已安装"
    fi

    cd ${currentdir}
    rm -rf ${libsodiumver} ${libsodiumver}.tar.gz
}

#安装mbedtls
function install_mbedtls() {
    cd ${currentdir}
    if [ ! -f /usr/lib/libmbedtls.a ]; then
        download "${mbedtlsver}-gpl.tgz" "${mbedtlsurl}"
        tar xf ${mbedtlsver}-gpl.tgz
        cd ${mbedtlsver}
        make SHARED=1 CFLAGS=-fPIC
        make DESTDIR=/usr install
        if [ $? -ne 0 ]; then
            echo -e "${red}[错误]${plain} ${mbedtlsver} 安装失败，请稍后重试！"
            exit 1
        fi
    else
        echo -e "${green}[提示]${plain} ${mbedtlsver} 已安装"
    fi

    cd ${currentdir}
    rm -rf ${mbedtlsver} ${mbedtlsver}-gpl.tgz
}

#创建shadowsocks配置文件
function config_shadowsocks() {
    if check_ipv6; then
        server_value="[\"[::0]\",\"0.0.0.0\"]"
    else
        server_value="\"0.0.0.0\""
    fi

    if check_kernel_version && check_kernel_headers; then
        fast_open="true"
    else
        fast_open="false"
    fi

    if [ ! -d /etc/shadowsocks-libev ]; then
        mkdir -p /etc/shadowsocks-libev
    fi

    cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":${server_value},
    "server_port":${ssport},
    "password":"${sspassword}",
    "timeout":300,
    "user":"nobody",
    "method":"${sscipher}",
    "fast_open":${fast_open},
    "nameserver":"8.8.8.8",
    "mode":"tcp_and_udp"
}
EOF
}

#安装shadowsocks
function install_shadowsocks() {
    ldconfig
    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        download "${shadowsocksver}.tar.gz" "${shadowsocksurl}"
        tar zxf ${shadowsocksver}.tar.gz
        cd ${shadowsocksver}
    else
        download "${shadowsocksnewver}.tar.gz" "${shadowsocksnewurl}"
        tar zxf ${shadowsocksnewver}.tar.gz
        cd ${shadowsocksnewver}
    fi
    ./configure --disable-documentation
    make && make install
    if [ $? -ne 0 ]; then
        echo -e "${red}[错误]${plain} Shadowsocks 安装失败，请稍后重试！"
        exit 1
    fi
    if [ ! -f /etc/init.d/shadowsocks ]; then
        download "/etc/init.d/shadowsocks" "${initscripturl}"
    fi
    chmod +x /etc/init.d/shadowsocks
    /etc/init.d/shadowsocks start
    if [ $? -ne 0 ]; then
        echo -e "${red}[错误]${plain} Shadowsocks 启动失败，请稍后重试！"
        exit 1
    fi
    if check_release centos; then
        chkconfig --add shadowsocks
        chkconfig shadowsocks on
    else
        update-rc.d -f shadowsocks defaults
    fi

    cd ${currentdir}
    if [[ ${updateornot} == "not" ]]; then
        rm -rf ${shadowsocksver} ${shadowsocksver}.tar.gz
    else
        rm -rf ${shadowsocksnewver} ${shadowsocksnewver}.tar.gz
    fi
}

#卸载shadowsocks
function uninstall_shadowsocks() {
    ps -ef | grep -v "grep" | grep "ss-server" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        /etc/init.d/shadowsocks stop
    fi
    if check_release centos; then
        chkconfig --del shadowsocks
    else
        update-rc.d -f shadowsocks remove
    fi
    rm -rf /etc/shadowsocks-libev
    rm -f /usr/local/bin/ss-local
    rm -f /usr/local/bin/ss-tunnel
    rm -f /usr/local/bin/ss-server
    rm -f /usr/local/bin/ss-manager
    rm -f /usr/local/bin/ss-redir
    rm -f /usr/local/bin/ss-nat
    rm -f /usr/local/lib/libshadowsocks-libev.a
    rm -f /usr/local/lib/libshadowsocks-libev.la
    rm -f /usr/local/include/shadowsocks.h
    rm -f /usr/local/lib/pkgconfig/shadowsocks-libev.pc
    rm -f /usr/local/share/man/man1/ss-local.1
    rm -f /usr/local/share/man/man1/ss-tunnel.1
    rm -f /usr/local/share/man/man1/ss-server.1
    rm -f /usr/local/share/man/man1/ss-manager.1
    rm -f /usr/local/share/man/man1/ss-redir.1
    rm -f /usr/local/share/man/man1/ss-nat.1
    rm -f /usr/local/share/man/man8/shadowsocks-libev.8
    rm -rf /usr/local/share/doc/shadowsocks-libev
    rm -f /etc/init.d/shadowsocks
    rm -f /root/shadowsocks.txt
}

#安装完成信息
function install_success() {
    local ssurl=$(echo -n "${sscipher}:${sspassword}@$(get_ipv4):${ssport}" | base64 -w0)
    clear
    echo -e "${green}[提示]${plain} Shadowsocks 安装成功，配置信息为"
    echo -e "==============================================="
    echo -e "服务器地址  : \033[41;37m $(get_ipv4) \033[0m"
    echo -e "服务端口    : \033[41;37m ${ssport} \033[0m"
    echo -e "连接密码    : \033[41;37m ${sspassword} \033[0m"
    echo -e "加密方式    : \033[41;37m ${sscipher} \033[0m"
    echo -e "-----------------------------------------------"
    echo -e "ss://${ssurl}"
    echo -e "==============================================="

    cat > /root/shadowsocks.txt << EOF
===============================================
服务器地址  : $(get_ipv4)
服务端口    : ${ssport}
连接密码    : ${sspassword}
加密方式    : ${sscipher}
-----------------------------------------------
ss://${ssurl}
===============================================
EOF
    echo -e "配置信息已备份在 /root/shadowsocks.txt 文件内"
    echo -e "Windows客户端：https://github.com/shadowsocks/shadowsocks-windows/releases"
    echo -e "macOS客户端：https://github.com/shadowsocks/ShadowsocksX-NG/releases"
    echo -e "Android客户端：https://github.com/shadowsocks/shadowsocks-android/releases"
    echo -e "iPhone/iPad客户端：App Store非国区下载shadowrocket"
    echo -e ""
    echo -e "更多教程请看：https://www.banwagongzw.com & https://www.vultrcn.com"
}

#功能部分一
install_main() {
    disable_selinux
    set_shadowsocks_config
    install_dependencies
    set_firewall
    install_libsodium
    install_mbedtls
    config_shadowsocks
    install_shadowsocks
    install_success
}

#功能部分二
uninstall_main() {
    uninstall_shadowsocks
    echo -e "${green}[提示]${plain} Shadowsocks 已成功卸载"
}

#功能部分三
update_main() {
    if [[ ${updateornot} == "update" ]]; then
        ps -ef | grep -v grep | grep -i "ss-server" > /dev/null 2>&1
        [ $? -eq 0 ] && /etc/init.d/shadowsocks stop
        install_shadowsocks
        echo -e "${green}[提示]${plain} Shadowsocks 更新成功"
    else
        echo -e "${green}[提示]${plain} Shadowsocks 已安装最新版，无需更新"
    fi
}

#功能部分四
start_main() {
    /etc/init.d/shadowsocks start
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 启动成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 启动失败，请稍后重试！"
    fi
}

#功能部分五
stop_main() {
    /etc/init.d/shadowsocks stop
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 停止成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 停止失败，请稍后重试！"
    fi
}

#功能部分六
restart_main() {
    /etc/init.d/shadowsocks stop
    /etc/init.d/shadowsocks start
    if [ $? -eq 0 ]; then
        echo -e "${green}[提示]${plain} Shadowsocks 重启成功"
    else
        echo -e "${red}[错误]${plain} Shadowsocks 重启失败，请稍后重试！"
    fi
}

#功能部分七
status_main() {
    echo -e "${green}[提示]${plain} 当前 Shadowsocks 配置信息为"
    cat /root/shadowsocks.txt
    echo "此信息仅供参考，具体请查看 Shadowsocks 配置文件"
}

#功能部分八
modify_main() {
    set_shadowsocks_config
    /etc/init.d/shadowsocks stop
    set_firewall
    config_shadowsocks
    /etc/init.d/shadowsocks start
    install_success
    echo ""
    echo "若修改后无法生效，请尝试重启解决！"
}

#起始部分
if [ $EUID -eq 0 ]; then
    if check_release centos || check_release debian || check_release ubuntu; then
        clear
        echo "================================"
        echo " Shadowsocks 一键管理脚本（libev） "
        echo "================================"
        echo " 1. 安装 Shadowsocks 服务        "
        echo " 2. 卸载 Shadowsocks 服务        "
        echo " 3. 更新 Shadowsocks 服务        "
        echo "--------------------------------"
        echo " 4. 启动 Shadowsocks 服务        "
        echo " 5. 停止 Shadowsocks 服务        "
        echo " 6. 重启 Shadowsocks 服务        "
        echo "--------------------------------"
        echo " 7. 查看 Shadowsocks 配置        "
        echo " 8. 修改 Shadowsocks 配置        "
        echo "================================"

        check_shadowsocks_status
        if [[ ${installedornot} == "installed" ]]; then
            if [[ ${runningornot} == "running" ]]; then
                if [[ ${updateornot} == "not" ]]; then
                    echo -e "${green}已安装且正在运行${plain}"
                else
                    echo -e "${green}已安装且正在运行，版本可更新${plain}"
                fi
            else
                echo -e "${yellow}已安装但未运行${plain}"
            fi
        else
            echo -e "${red}尚未安装${plain}"
        fi

        while true
        do
            echo ""
            read -p "请输入相应功能前面的数字：" choice
            [[ -z ${choice} ]] && choice="0"
            expr ${choice} + 1 > /dev/null 2>&1
            if [ $? -eq 0 ]; then
                if [ ${choice} -ge 1 ] && [ ${choice} -le 8 ]; then
                    if [ "${choice}" == "1" ]; then
                        install_main
                    elif [ "${choice}" == "2" ]; then
                        uninstall_main
                    elif [ "${choice}" == "3" ]; then
                        update_main
                    elif [ "${choice}" == "4" ]; then
                        start_main
                    elif [ "${choice}" == "5" ]; then
                        stop_main
                    elif [ "${choice}" == "6" ]; then
                        restart_main
                    elif [ "${choice}" == "7" ]; then
                        status_main
                    elif [ "${choice}" == "8" ]; then
                        modify_main
                    fi
                    break
                else
                    echo -e "${red}[错误]${plain} 请输入 1 和 8 之间的数字！"
                fi
            else
                echo -e "${red}[错误]${plain} 请输入 1 和 8 之间的数字！"
            fi
        done
    else
        echo -e "${red}[错误]${plain} 本脚本只支持 CentOS、Debian 及 Ubuntu 系统！"
        exit 1
    fi
else
    echo -e "${red}[错误]${plain} 请以 root 用户身份运行此脚本！"
    exit 1
fi

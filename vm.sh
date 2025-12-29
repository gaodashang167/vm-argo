#!/bin/bash

# =========================
# Argo + VMess + WS 安装脚本
# 基于老王sing-box脚本提取
# =========================

export LANG=en_US.UTF-8

# 定义颜色
re="\033[0m"
red="\033[1;91m"
green="\e[1;32m"
yellow="\e[1;33m"
purple="\e[1;35m"
skyblue="\e[1;36m"

red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
skyblue() { echo -e "\e[1;36m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 定义常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
export vmess_port=${PORT:-8001}
export CFIP=${CFIP:-'cf.877774.xyz'}
export CFPORT=${CFPORT:-'443'}

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查服务状态
check_service() {
    local service_name=$1
    local service_file=$2
    
    [[ ! -f "${service_file}" ]] && { red "not installed"; return 2; }
        
    if command_exists apk; then
        rc-service "${service_name}" status | grep -q "started" && green "running" || yellow "not running"
    else
        systemctl is-active "${service_name}" | grep -q "^active$" && green "running" || yellow "not running"
    fi
    return $?
}

check_singbox() {
    check_service "sing-box" "${work_dir}/${server_name}"
}

check_argo() {
    check_service "argo" "${work_dir}/argo"
}

check_nginx() {
    command_exists nginx || { red "not installed"; return 2; }
    check_service "nginx" "$(command -v nginx)"
}

# 包管理
manage_packages() {
    if [ $# -lt 2 ]; then
        red "Unspecified package name or action"
        return 1
    fi

    action=$1
    shift

    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then
                green "${package} already installed"
                continue
            fi
            yellow "正在安装 ${package}..."
            if command_exists apt; then
                DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then
                dnf install -y "$package"
            elif command_exists yum; then
                yum install -y "$package"
            elif command_exists apk; then
                apk update
                apk add "$package"
            else
                red "Unknown system!"
                return 1
            fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then
                yellow "${package} is not installed"
                continue
            fi
            yellow "正在卸载 ${package}..."
            if command_exists apt; then
                apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then
                dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then
                yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then
                apk del "$package"
            else
                red "Unknown system!"
                return 1
            fi
        fi
    done
}

# 获取IP
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then
        echo "[$(ipv6)]"
    elif curl -4 -sm 2 http://ipinfo.io/org | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then
        echo "[$(ipv6)]"
    else
        resp=$(curl -sm 8 "https://status.eooce.com/api/$ip" | jq -r '.status')
        if [ "$resp" = "Available" ]; then
            echo "$ip"
        else
            v6=$(ipv6)
            [ -n "$v6" ] && echo "[$v6]" || echo "$ip"
        fi
    fi
}

# 下载并安装 sing-box 和 cloudflared
install_singbox() {
    clear
    purple "正在安装sing-box中，请稍后..."
    
    # 判断系统架构
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    # 创建工作目录
    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    
    # 下载必要文件
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo ${work_dir}/qrencode

    # 生成UUID
    uuid=$(cat /proc/sys/kernel/random/uuid)
    password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 24)
    
    # 生成nginx端口
    nginx_port=$(shuf -i 2000-65000 -n 1)

    # 检测网络类型并设置DNS策略
    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

    # 生成配置文件
cat > "${config_dir}" << EOF
{
  "log": {
    "disabled": false,
    "level": "error",
    "output": "$work_dir/sb.log",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "local",
        "address": "local",
        "strategy": "$dns_strategy"
      }
    ]
  },
  "ntp": {
    "enabled": true,
    "server": "time.apple.com",
    "server_port": 123,
    "interval": "30m"
  },
  "inbounds": [
    {
      "type": "vmess",
      "tag": "vmess-ws",
      "listen": "::",
      "listen_port": $vmess_port,
      "users": [
        {
          "uuid": "$uuid"
        }
      ],
      "transport": {
        "type": "ws",
        "path": "/vmess-argo",
        "early_data_header_name": "Sec-WebSocket-Protocol"
      }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ]
}
EOF
}

# systemd 守护进程
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/etc/sing-box
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target

[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    if [ -f /etc/centos-release ]; then
        yum install -y chrony
        systemctl start chronyd
        systemctl enable chronyd
        chronyc -a makestep
        yum update -y ca-certificates
        bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    fi
    
    systemctl daemon-reload
    systemctl enable sing-box
    systemctl start sing-box
    systemctl enable argo
    systemctl start argo
}

# alpine OpenRC 守护进程
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run

description="sing-box service"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF

    cat > /etc/init.d/argo << EOF
#!/sbin/openrc-run

description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF

    chmod +x /etc/init.d/sing-box
    chmod +x /etc/init.d/argo

    rc-update add sing-box default > /dev/null 2>&1
    rc-update add argo default > /dev/null 2>&1
}

# 生成节点信息
get_info() {
    yellow "\nip检测中,请稍等...\n"
    server_ip=$(get_realip)
    clear
    isp=$(curl -s --max-time 2 https://ipapi.co/json | tr -d '\n[:space:]' | sed 's/.*"country_code":"\([^"]*\)".*"org":"\([^"]*\)".*/\1-\2/' | sed 's/ /_/g' 2>/dev/null || echo "$hostname")

    if [ -f "${work_dir}/argo.log" ]; then
        for i in {1..5}; do
            purple "第 $i 次尝试获取ArgoDoamin中..."
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
            [ -n "$argodomain" ] && break
            sleep 2
        done
    else
        restart_argo
        sleep 6
        argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log")
    fi

    green "\nArgoDomain：${purple}$argodomain${re}\n"

    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"false\"}"

    cat > ${work_dir}/url.txt <<EOF
vmess://$(echo "$VMESS" | base64 -w0)
EOF

    echo ""
    purple "$(cat ${work_dir}/url.txt)"
    
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
    chmod 644 ${work_dir}/sub.txt
    
    yellow "\n温馨提醒：需打开V2rayN或其他软件里的 "跳过证书验证"，或将节点的Insecure或TLS里设置为"true"\n"
    green "V2rayN,Shadowrocket,Nekobox,Loon,Karing,Sterisand订阅链接：http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "http://${server_ip}:${nginx_port}/${password}"
    yellow "\n=========================================================================================="
    green "\n\nClash,Mihomo系列订阅链接：https://sublink.eooce.com/clash?config=http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "https://sublink.eooce.com/clash?config=http://${server_ip}:${nginx_port}/${password}"
    yellow "\n=========================================================================================="
    green "\n\nSing-box订阅链接：https://sublink.eooce.com/singbox?config=http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "https://sublink.eooce.com/singbox?config=http://${server_ip}:${nginx_port}/${password}"
    yellow "\n==========================================================================================\n"
}

# nginx订阅配置
add_nginx_conf() {
    if ! command_exists nginx; then
        red "nginx未安装,无法配置订阅服务"
        return 1
    else
        manage_service "nginx" "stop" > /dev/null 2>&1
        pkill nginx > /dev/null 2>&1
    fi

    mkdir -p /etc/nginx/conf.d

    [[ -f "/etc/nginx/conf.d/sing-box.conf" ]] && cp /etc/nginx/conf.d/sing-box.conf /etc/nginx/conf.d/sing-box.conf.bak.sb

    cat > /etc/nginx/conf.d/sing-box.conf << EOF
server {
    listen $nginx_port;
    listen [::]:$nginx_port;
    server_name _;

    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    location = /$password {
        alias /etc/sing-box/sub.txt;
        default_type 'text/plain; charset=utf-8';
        add_header Cache-Control "no-cache, no-store, must-revalidate";
        add_header Pragma "no-cache";
        add_header Expires "0";
    }

    location / {
        return 404;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

    if [ -f "/etc/nginx/nginx.conf" ]; then
        cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.sb > /dev/null 2>&1
        if ! grep -q "include.*conf.d" /etc/nginx/nginx.conf; then
            http_end_line=$(grep -n "^}" /etc/nginx/nginx.conf | tail -1 | cut -d: -f1)
            if [ -n "$http_end_line" ]; then
                sed -i "${http_end_line}i \    include /etc/nginx/conf.d/*.conf;" /etc/nginx/nginx.conf > /dev/null 2>&1
            fi
        fi
    else
        cat > /etc/nginx/nginx.conf << EOF
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';
    
    access_log  /var/log/nginx/access.log  main;
    sendfile        on;
    keepalive_timeout  65;
    
    include /etc/nginx/conf.d/*.conf;
}
EOF
    fi

    if nginx -t > /dev/null 2>&1; then
        if nginx -s reload > /dev/null 2>&1; then
            green "nginx订阅配置已加载"
        else
            start_nginx > /dev/null 2>&1
        fi
    else
        yellow "nginx配置失败,订阅不可用,但不影响节点使用"
        restart_nginx > /dev/null 2>&1
    fi
}

# 服务管理
manage_service() {
    local service_name="$1"
    local action="$2"

    if [ -z "$service_name" ] || [ -z "$action" ]; then
        red "缺少服务名或操作参数\n"
        return 1
    fi

    case "$action" in
        "start"|"stop"|"restart")
            if command_exists rc-service; then
                rc-service "$service_name" "$action"
            elif command_exists systemctl; then
                systemctl daemon-reload
                systemctl "$action" "$service_name"
            fi
            ;;
    esac
}

start_singbox() { manage_service "sing-box" "start"; }
stop_singbox() { manage_service "sing-box" "stop"; }
restart_singbox() { manage_service "sing-box" "restart"; }
start_argo() { manage_service "argo" "start"; }
stop_argo() { manage_service "argo" "stop"; }
restart_argo() { manage_service "argo" "restart"; }
start_nginx() { manage_service "nginx" "start"; }
restart_nginx() { manage_service "nginx" "restart"; }

# 卸载
uninstall_singbox() {
    reading "确定要卸载吗? (y/n): " choice
    case "${choice}" in
        y|Y)
            yellow "正在卸载..."
            if command_exists rc-service; then
                rc-service sing-box stop
                rc-service argo stop
                rm /etc/init.d/sing-box /etc/init.d/argo
                rc-update del sing-box default
                rc-update del argo default
            else
                systemctl stop sing-box argo
                systemctl disable sing-box argo
                systemctl daemon-reload
            fi
            
            rm -rf "${work_dir}"
            rm -rf /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service
            rm -rf /etc/nginx/conf.d/sing-box.conf
            
            reading "\n是否卸载 Nginx？(y/n): " choice
            case "${choice}" in
                y|Y) manage_packages uninstall nginx ;;
                *) yellow "取消卸载Nginx\n" ;;
            esac

            green "\n卸载成功\n" && exit 0
            ;;
        *)
            purple "已取消卸载操作\n"
            ;;
    esac
}

# 创建快捷指令
create_shortcut() {
    cat > "$work_dir/vmess.sh" << 'EOF'
#!/usr/bin/env bash
bash <(curl -Ls https://raw.githubusercontent.com/gaodashang167/vm-argo/main/vm.sh) $1
EOF
    chmod +x "$work_dir/vmess.sh"
    ln -sf "$work_dir/vmess.sh" /usr/bin/vmess
    [ -s /usr/bin/vmess ] && green "\n快捷指令 vmess 创建成功\n" || red "\n快捷指令创建失败\n"
}

# Alpine适配
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 查看节点信息
check_nodes() {
    purple "$(cat ${work_dir}/url.txt)"
    server_ip=$(get_realip)
    lujing=$(sed -n 's|.*location = /\([^ ]*\).*|\1|p' "/etc/nginx/conf.d/sing-box.conf")
    sub_port=$(sed -n 's/^\s*listen \([0-9]\+\);/\1/p' "/etc/nginx/conf.d/sing-box.conf")
    base64_url="http://${server_ip}:${sub_port}/${lujing}"
    
    green "\n\nV2rayN等订阅链接: ${purple}${base64_url}${re}\n"
    green "Clash订阅链接: ${purple}https://sublink.eooce.com/clash?config=${base64_url}${re}\n"
    green "sing-box订阅链接: ${purple}https://sublink.eooce.com/singbox?config=${base64_url}${re}\n"
}

# Argo固定隧道配置
setup_argo_fixed() {
    clear
    yellow "\n固定隧道可为json或token，固定隧道端口为${vmess_port}，请自行在cf后台设置\n"
    yellow "json获取地址：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
    reading "\n请输入你的argo域名: " argo_domain
    reading "请输入你的argo密钥(token或json): " argo_auth
    
    if [[ $argo_auth =~ TunnelSecret ]]; then
        echo $argo_auth > ${work_dir}/tunnel.json
        cat > ${work_dir}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$argo_auth")
credentials-file: ${work_dir}/tunnel.json
protocol: http2

ingress:
  - hostname: $argo_domain
    service: http://localhost:${vmess_port}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
        if command_exists rc-service; then
            sed -i '/^command_args=/c\command_args="-c '\''/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1'\''"' /etc/init.d/argo
        else
            sed -i '/^ExecStart=/c\ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1"' /etc/systemd/system/argo.service
        fi
        restart_argo
        green "\n固定隧道已配置,域名: $argo_domain\n"
        
    elif [[ $argo_auth =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
        if command_exists rc-service; then
            sed -i "/^command_args=/c\command_args=\"-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'\"" /etc/init.d/argo
        else
            sed -i '/^ExecStart=/c\ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token '$argo_auth' 2>&1"' /etc/systemd/system/argo.service
        fi
        restart_argo
        green "\n固定隧道已配置,域名: $argo_domain\n"
    else
        red "输入的argo密钥格式不正确\n"
    fi
}

# 主菜单
menu() {
    singbox_status=$(check_singbox 2>/dev/null)
    nginx_status=$(check_nginx 2>/dev/null)
    argo_status=$(check_argo 2>/dev/null)
    
    clear
    echo ""
    purple "=== Argo + VMess + WS 安装脚本 ===\n"
    purple "---Argo 状态: ${argo_status}"
    purple "--Nginx 状态: ${nginx_status}"
    purple "singbox 状态: ${singbox_status}\n"
    green "1. 安装"
    red "2. 卸载"
    skyblue "==========="
    green "3. 查看节点信息"
    green "4. 配置Argo固定隧道"
    green "5. 重启服务"
    skyblue "==========="
    red "0. 退出"
    echo "==========="
    reading "请输入选择: " choice
    echo ""
}

# 主循环
while true; do
    menu
    case "${choice}" in
        1)
            check_singbox &>/dev/null; check_singbox=$?
            if [ ${check_singbox} -eq 0 ]; then
                yellow "已经安装！\n"
            else
                manage_packages install nginx jq tar openssl lsof coreutils
                install_singbox
                
                if command_exists systemctl; then
                    main_systemd_services
                elif command_exists rc-update; then
                    alpine_openrc_services
                    change_hosts
                    rc-service sing-box restart
                    rc-service argo restart
                fi

                sleep 5
                get_info
                add_nginx_conf
                create_shortcut
            fi
            ;;
        2) uninstall_singbox ;;
        3) check_nodes ;;
        4) setup_argo_fixed ;;
        5) restart_singbox && restart_argo && restart_nginx && green "服务已重启\n" ;;
        0) exit 0 ;;
        *) red "无效的选项" ;;
    esac
    read -n 1 -s -r -p $'\033[1;91m按任意键返回...\033[0m'
done

#!/bin/bash
# =========================
# Argo + VMess + WS 安装脚本 (v6 完美适配版)
# 1. 隧道协议更换为 QUIC (解决 v6 连不上/不绿的问题)
# 2. 自动检测 IPv6 环境并应用优化参数
# 3. 修复固定隧道刷新和显示逻辑
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

# 常量定义
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
# 请确保这里是你的真实 GitHub 地址
GITHUB_URL="https://raw.githubusercontent.com/gaodashang167/vm-argo/main/vm.sh"
LOCAL_SCRIPT="${work_dir}/vm.sh"

export vmess_port=${PORT:-8001}
export CFIP=${CFIP:-'cf.877774.xyz'}
export CFPORT=${CFPORT:-'443'}

# 检查Root
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# === 核心修复：智能网络环境检测 ===
check_network_env() {
    # 尝试连接 v4 地址，超时则认为只有 v6
    if curl -4 -s --connect-timeout 2 https://1.1.1.1 >/dev/null 2>&1; then
        echo "auto"
    else
        echo "6"
    fi
}
# 获取环境参数
ARGO_EDGE_IP=$(check_network_env)

# 基础检查函数
command_exists() { command -v "$1" >/dev/null 2>&1; }
check_service() {
    local n=$1; local f=$2
    [[ ! -f "$f" ]] && { red "not installed"; return 2; }
    if command_exists apk; then rc-service "$n" status | grep -q "started" && green "running" || yellow "not running"
    else systemctl is-active "$n" | grep -q "^active$" && green "running" || yellow "not running"; fi
}
check_singbox() { check_service "sing-box" "${work_dir}/${server_name}"; }
check_argo() { check_service "argo" "${work_dir}/argo"; }
check_nginx() { command_exists nginx || { red "not installed"; return 2; }; check_service "nginx" "$(command -v nginx)"; }

# 包管理
manage_packages() {
    if [ $# -lt 2 ]; then return 1; fi
    action=$1; shift
    for pkg in "$@"; do
        if [ "$action" == "install" ]; then
            command_exists "$pkg" && { green "$pkg installed"; continue; }
            yellow "Installing $pkg..."
            if command_exists apt; then DEBIAN_FRONTEND=noninteractive apt install -y "$pkg"
            elif command_exists apk; then apk update && apk add "$pkg"
            elif command_exists yum; then yum install -y "$pkg"
            elif command_exists dnf; then dnf install -y "$pkg"
            fi
        elif [ "$action" == "uninstall" ]; then
            command_exists "$pkg" || continue
            if command_exists apt; then apt remove -y "$pkg" && apt autoremove -y
            elif command_exists apk; then apk del "$pkg"
            elif command_exists yum; then yum remove -y "$pkg"
            fi
        fi
    done
}

# 获取IP
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then echo "[$(ipv6)]"
    else
        resp=$(curl -sm 2 "https://status.eooce.com/api/$ip" | jq -r '.status' 2>/dev/null)
        if [ "$resp" = "Available" ]; then echo "$ip"; else v6=$(ipv6); [ -n "$v6" ] && echo "[$v6]" || echo "$ip"; fi
    fi
}

# 安装Sing-box
install_singbox() {
    clear
    purple "正在安装sing-box..."
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86'|'i386') ARCH='386' ;;
        'aarch64'|'arm64') ARCH='arm64' ;;
        *) red "不支持架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    chmod +x "${work_dir}"/*
    
    uuid=$(cat /proc/sys/kernel/random/uuid)
    password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 24)
    nginx_port=$(shuf -i 2000-65000 -n 1)
    
    # 智能DNS: 纯v6环境优先使用Google v6 DNS
    dns_strategy=$(ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || echo "prefer_ipv6")

cat > "${config_dir}" << EOF
{
  "log": { "disabled": false, "level": "error", "output": "$work_dir/sb.log", "timestamp": true },
  "dns": { "servers": [ { "tag": "local", "address": "local", "strategy": "$dns_strategy" } ] },
  "ntp": { "enabled": true, "server": "time.apple.com", "server_port": 123, "interval": "30m" },
  "inbounds": [ { "type": "vmess", "tag": "vmess-ws", "listen": "::", "listen_port": $vmess_port, "users": [ { "uuid": "$uuid" } ], "transport": { "type": "ws", "path": "/vmess-argo", "early_data_header_name": "Sec-WebSocket-Protocol" } } ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
}

# Systemd服务 (已修改为 QUIC 协议)
main_systemd_services() {
    cat > /etc/systemd/system/sing-box.service << EOF
[Unit]
Description=sing-box
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/etc/sing-box
ExecStart=/etc/sing-box/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

    # 关键修改：--protocol quic
    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
NoNewPrivileges=yes
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version $ARGO_EDGE_IP --protocol quic > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

    if [ -f /etc/centos-release ]; then
        yum install -y chrony && systemctl start chronyd && systemctl enable chronyd
    fi
    systemctl daemon-reload
    systemctl enable sing-box argo
    systemctl start sing-box argo
}

# OpenRC服务 (已修改为 QUIC 协议)
alpine_openrc_services() {
    cat > /etc/init.d/sing-box << 'EOF'
#!/sbin/openrc-run
description="sing-box"
command="/etc/sing-box/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background=true
pidfile="/var/run/sing-box.pid"
EOF
    cat > /etc/init.d/argo << EOF
#!/sbin/openrc-run
description="Cloudflare Tunnel"
command="/bin/sh"
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version $ARGO_EDGE_IP --protocol quic > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF
    chmod +x /etc/init.d/sing-box /etc/init.d/argo
    rc-update add sing-box default > /dev/null 2>&1
    rc-update add argo default > /dev/null 2>&1
}

# 获取信息
get_info() {
    # 恢复 UUID
    if [ -z "$uuid" ] && [ -f "$config_dir" ]; then
        command_exists jq && uuid=$(jq -r '.inbounds[0].users[0].uuid' "$config_dir") || uuid=$(grep -o '"uuid": *"[^"]*"' "$config_dir" | head -1 | cut -d'"' -f4)
    fi
    yellow "\n获取节点信息..."
    server_ip=$(get_realip)
    isp=$(curl -s --max-time 2 https://ipapi.co/json | grep -o '"org":"[^"]*"' | cut -d'"' -f4 | sed 's/ /_/g' || echo "VPS")
    
    argodomain=""
    [ -f "${work_dir}/tunnel.yml" ] && argodomain=$(grep "hostname:" "${work_dir}/tunnel.yml" | head -1 | awk '{print $2}' | tr -d ' "')

    if [ -z "$argodomain" ]; then
        # 尝试读取日志
        for i in {1..3}; do
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
            [ -n "$argodomain" ] && break
            sleep 1
        done
        if [ -z "$argodomain" ]; then
            purple "临时域名生成较慢，尝试重启..."
            restart_argo >/dev/null 2>&1 && sleep 5
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
        fi
    else
        green "\n检测到固定隧道配置: ${argodomain}"
    fi
    
    [ -z "$argodomain" ] && red "获取 Argo 域名失败。如果是固定隧道，请检查 Cloudflare 后台状态。" && return

    green "\nArgo域名：${purple}$argodomain${re}\n"
    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"false\"}"

    echo "vmess://$(echo "$VMESS" | base64 -w0)" > ${work_dir}/url.txt
    echo ""
    purple "$(cat ${work_dir}/url.txt)"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt && chmod 644 ${work_dir}/sub.txt
    
    yellow "\n=========================================================="
    yellow " 重要提示：如果固定隧道已连接但无法上网："
    yellow " 请在 Cloudflare 后台 -> Access -> Tunnels -> Configure -> Public Hostname"
    yellow " 将 Service 设置为: ${green}http://localhost:${vmess_port}${yellow}"
    yellow " 如果 localhost 不行，请尝试: ${green}http://127.0.0.1:${vmess_port}${yellow} 或 ${green}http://[::1]:${vmess_port}${yellow}"
    yellow "=========================================================="
    green "\n订阅链接：http://${server_ip}:${nginx_port}/${password}\n"
}

# Nginx配置
add_nginx_conf() {
    if ! command_exists nginx; then return 1; else manage_service "nginx" "stop" >/dev/null 2>&1; fi
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/sing-box.conf << EOF
server {
    listen $nginx_port; listen [::]:$nginx_port; server_name _;
    add_header X-Frame-Options DENY;
    location = /$password { alias /etc/sing-box/sub.txt; default_type 'text/plain; charset=utf-8'; add_header Cache-Control "no-cache"; }
    location / { return 404; } location ~ /\. { deny all; access_log off; }
}
EOF
    [ ! -f "/etc/nginx/nginx.conf" ] && cat > /etc/nginx/nginx.conf << EOF
user nginx; worker_processes auto; error_log /var/log/nginx/error.log; pid /run/nginx.pid;
events { worker_connections 1024; }
http { include /etc/nginx/mime.types; default_type application/octet-stream; access_log /var/log/nginx/access.log; sendfile on; include /etc/nginx/conf.d/*.conf; }
EOF
    nginx -t >/dev/null 2>&1 && start_nginx || restart_nginx
}

# 服务管理
manage_service() { local n=$1; local a=$2; command_exists rc-service && rc-service "$n" "$a" || systemctl "$a" "$n"; }
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
    reading "确定卸载? (y/n): " choice
    [[ "$choice" != "y" && "$choice" != "Y" ]] && return
    yellow "正在卸载..."
    if command_exists rc-service; then
        rc-service sing-box stop; rc-service argo stop
        rc-update del sing-box default; rc-update del argo default
        rm /etc/init.d/sing-box /etc/init.d/argo
    else
        systemctl stop sing-box argo; systemctl disable sing-box argo
        rm /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service
        systemctl daemon-reload
    fi
    rm -rf "${work_dir}" /etc/nginx/conf.d/sing-box.conf /usr/bin/hu
    reading "卸载 Nginx? (y/n): " c2
    [[ "$c2" == "y" || "$c2" == "Y" ]] && manage_packages uninstall nginx
    green "卸载完成" && exit 0
}

# 快捷指令
create_shortcut() {
    yellow "\n配置快捷指令 hu..."
    curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL"
    chmod +x "$LOCAL_SCRIPT"
    cat > "/usr/bin/hu" << EOF
#!/bin/bash
if [ -s "$LOCAL_SCRIPT" ]; then bash "$LOCAL_SCRIPT" \$1; else
    echo -e "\033[1;33m尝试重新下载脚本...\033[0m"
    mkdir -p "$work_dir" && curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL" && chmod +x "$LOCAL_SCRIPT"
    [ -s "$LOCAL_SCRIPT" ] && bash "$LOCAL_SCRIPT" \$1 || echo "下载失败"
fi
EOF
    chmod +x "/usr/bin/hu"
    green "\n>>> hu 命令已配置 (v6 QUIC版) <<<\n"
}

# Alpine host
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 配置固定隧道
setup_argo_fixed() {
    clear
    yellow "\n固定隧道配置 (端口:${vmess_port})\n"
    reading "域名: " argo_domain
    reading "Token/Json: " argo_auth
    [ -z "$argo_domain" ] || [ -z "$argo_auth" ] && red "不能为空" && return
    stop_argo >/dev/null 2>&1
    
    # 强制使用 QUIC 协议
    EDGE_ARG="--edge-ip-version $ARGO_EDGE_IP"
    
    if [[ $argo_auth =~ TunnelSecret ]]; then
        echo "$argo_auth" > "${work_dir}/tunnel.json"
        TUNNEL_ID=$(cut -d\" -f12 <<< "$argo_auth")
        cat > "${work_dir}/tunnel.yml" << EOF
tunnel: $TUNNEL_ID
credentials-file: ${work_dir}/tunnel.json
protocol: quic
ingress:
  - hostname: $argo_domain
    service: http://localhost:${vmess_port}
    originRequest: { noTLSVerify: true }
  - service: http_status:404
EOF
        CMD_ARGS="-c '/etc/sing-box/argo tunnel $EDGE_ARG --config /etc/sing-box/tunnel.yml run 2>&1'"
    else
        # Token模式：写入Hostname供脚本读取
        echo "hostname: $argo_domain" > "${work_dir}/tunnel.yml"
        # 关键修改：--protocol quic
        CMD_ARGS="-c '/etc/sing-box/argo tunnel $EDGE_ARG --no-autoupdate --protocol quic run --token $argo_auth 2>&1'"
    fi

    if command_exists rc-service; then sed -i "/^command_args=/c\\command_args=\"$CMD_ARGS\"" /etc/init.d/argo
    else ESCAPED=$(echo "$CMD_ARGS" | sed 's/"/\\"/g'); sed -i "/^ExecStart=/c\\ExecStart=/bin/sh -c \"${CMD_ARGS//\'/}\"" /etc/systemd/system/argo.service; fi

    restart_argo
    green "\n配置完成，正在刷新..." && sleep 3 && get_info
}

# 菜单
menu() {
    singbox_status=$(check_singbox 2>/dev/null); nginx_status=$(check_nginx 2>/dev/null); argo_status=$(check_argo 2>/dev/null)
    clear
    purple "\n=== Argo + VMess + WS (纯v6/QUIC修复版) ===\n"
    echo -e "Argo: ${argo_status} | Nginx: ${nginx_status} | Sing-box: ${singbox_status}\n"
    green "1. 安装"
    red "2. 卸载"
    green "3. 查看节点"
    green "4. 配置固定隧道 (推荐)"
    green "5. 重启服务"
    red "0. 退出"
    reading "\n请选择: " choice
}

while true; do
    menu
    case "${choice}" in
        1)
            if check_singbox >/dev/null; then yellow "已安装"; create_shortcut; else
                manage_packages install nginx jq tar openssl lsof coreutils
                install_singbox
                if command_exists systemctl; then main_systemd_services; else alpine_openrc_services; change_hosts; rc-service sing-box restart; rc-service argo restart; fi
                sleep 5; get_info; add_nginx_conf; create_shortcut
            fi ;;
        2) uninstall_singbox ;;
        3) get_info ;;
        4) setup_argo_fixed ;;
        5) restart_singbox && restart_argo && restart_nginx && green "重启成功" ;;
        0) exit 0 ;;
        *) red "无效选项" ;;
    esac
    read -n 1 -s -r -p "按任意键继续..."
done

#!/bin/bash
# =========================
# Argo + VMess + WS 安装脚本 (IPv6 专用修复版)
# 1. 自动识别纯 IPv6 环境并强制 Argo 使用 v6
# 2. 修复 hu 命令下载问题
# 3. 修复固定隧道刷新问题
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

# GitHub 地址
GITHUB_URL="https://raw.githubusercontent.com/gaodashang167/vm-argo/main/vm.sh"
# 本地保存文件名
LOCAL_SCRIPT="${work_dir}/vm.sh"

export vmess_port=${PORT:-8001}
export CFIP=${CFIP:-'cf.877774.xyz'}
export CFPORT=${CFPORT:-'443'}

# 检查是否为root下运行
[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# === 网络环境检测函数 (核心修复) ===
check_network_env() {
    # 检测是否有 IPv4 出口
    if curl -4 -s --connect-timeout 2 https://1.1.1.1 >/dev/null 2>&1; then
        echo "auto"
    else
        echo "6" # 纯 IPv6 环境返回 6
    fi
}
# 获取当前环境的最佳 Argo 参数
ARGO_EDGE_IP=$(check_network_env)

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

check_singbox() { check_service "sing-box" "${work_dir}/${server_name}"; }
check_argo() { check_service "argo" "${work_dir}/argo"; }
check_nginx() { command_exists nginx || { red "not installed"; return 2; }; check_service "nginx" "$(command -v nginx)"; }

# 包管理
manage_packages() {
    if [ $# -lt 2 ]; then red "Unspecified package name or action"; return 1; fi
    action=$1
    shift
    for package in "$@"; do
        if [ "$action" == "install" ]; then
            if command_exists "$package"; then green "${package} already installed"; continue; fi
            yellow "正在安装 ${package}..."
            if command_exists apt; then DEBIAN_FRONTEND=noninteractive apt install -y "$package"
            elif command_exists dnf; then dnf install -y "$package"
            elif command_exists yum; then yum install -y "$package"
            elif command_exists apk; then apk update && apk add "$package"
            else red "Unknown system!"; return 1; fi
        elif [ "$action" == "uninstall" ]; then
            if ! command_exists "$package"; then yellow "${package} is not installed"; continue; fi
            yellow "正在卸载 ${package}..."
            if command_exists apt; then apt remove -y "$package" && apt autoremove -y
            elif command_exists dnf; then dnf remove -y "$package" && dnf autoremove -y
            elif command_exists yum; then yum remove -y "$package" && yum autoremove -y
            elif command_exists apk; then apk del "$package"
            else red "Unknown system!"; return 1; fi
        fi
    done
}

# 获取IP
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then echo "[$(ipv6)]"
    elif curl -4 -sm 2 http://ipinfo.io/org | grep -qE 'Cloudflare|UnReal|AEZA|Andrei'; then echo "[$(ipv6)]"
    else
        resp=$(curl -sm 8 "https://status.eooce.com/api/$ip" | jq -r '.status')
        if [ "$resp" = "Available" ]; then echo "$ip"; else v6=$(ipv6); [ -n "$v6" ] && echo "[$v6]" || echo "$ip"; fi
    fi
}

# 安装Singbox
install_singbox() {
    clear
    purple "正在安装sing-box中，请稍后..."
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86' | 'i686' | 'i386') ARCH='386' ;;
        'aarch64' | 'arm64') ARCH='arm64' ;;
        'armv7l') ARCH='armv7' ;;
        's390x') ARCH='s390x' ;;
        *) red "不支持的架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    [ ! -d "${work_dir}" ] && mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    
    # 下载必要文件
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    
    chown root:root ${work_dir} && chmod +x ${work_dir}/${server_name} ${work_dir}/argo ${work_dir}/qrencode
    
    uuid=$(cat /proc/sys/kernel/random/uuid)
    password=$(< /dev/urandom tr -dc 'A-Za-z0-9' | head -c 24)
    nginx_port=$(shuf -i 2000-65000 -n 1)
    
    # 智能 DNS 策略
    dns_strategy=$(ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1 && echo "prefer_ipv4" || (ping -c 1 -W 3 2001:4860:4860::8888 >/dev/null 2>&1 && echo "prefer_ipv6" || echo "prefer_ipv4"))

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

# Systemd服务 (已注入 IPv6 判断)
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

    # 这里的 ARGO_EDGE_IP 是动态检测的结果
    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
NoNewPrivileges=yes
TimeoutStartSec=0
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version $ARGO_EDGE_IP --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

    if [ -f /etc/centos-release ]; then
        yum install -y chrony && systemctl start chronyd && systemctl enable chronyd && chronyc -a makestep
        yum update -y ca-certificates && bash -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    fi
    systemctl daemon-reload
    systemctl enable sing-box argo
    systemctl start sing-box argo
}

# OpenRC服务 (已注入 IPv6 判断)
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
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version $ARGO_EDGE_IP --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF
    chmod +x /etc/init.d/sing-box /etc/init.d/argo
    rc-update add sing-box default > /dev/null 2>&1
    rc-update add argo default > /dev/null 2>&1
}

# 获取信息
get_info() {
    if [ -z "$uuid" ] && [ -f "$config_dir" ]; then
        command_exists jq && uuid=$(jq -r '.inbounds[0].users[0].uuid' "$config_dir") || uuid=$(grep -o '"uuid": *"[^"]*"' "$config_dir" | head -1 | cut -d'"' -f4)
    fi
    yellow "\n正在获取节点信息...\n"
    server_ip=$(get_realip)
    isp=$(curl -s --max-time 2 https://ipapi.co/json | grep -o '"org":"[^"]*"' | cut -d'"' -f4 | sed 's/ /_/g' || echo "VPS")
    
    argodomain=""
    [ -f "${work_dir}/tunnel.yml" ] && argodomain=$(grep "hostname:" "${work_dir}/tunnel.yml" | head -1 | awk '{print $2}' | tr -d ' "')

    if [ -z "$argodomain" ]; then
        if [ -f "${work_dir}/argo.log" ]; then
            for i in {1..3}; do
                argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
                [ -n "$argodomain" ] && break
                sleep 1
            done
        fi
        if [ -z "$argodomain" ]; then
            purple "临时域名获取中..."
            restart_argo >/dev/null 2>&1 && sleep 5
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
        fi
    else
        green "\n检测到固定隧道配置: ${argodomain}"
    fi
    [ -z "$argodomain" ] && red "获取 Argo 域名失败，纯 IPv6 请多等待一会或检查网络" && return

    green "\nArgo域名：${purple}$argodomain${re}\n"
    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"false\"}"

    echo "vmess://$(echo "$VMESS" | base64 -w0)" > ${work_dir}/url.txt
    echo ""
    purple "$(cat ${work_dir}/url.txt)"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt && chmod 644 ${work_dir}/sub.txt
    
    yellow "\n温馨提醒：需打开 \"跳过证书验证\" (AllowInsecure)"
    green "V2rayN等订阅链接：http://${server_ip}:${nginx_port}/${password}\n"
    $work_dir/qrencode "http://${server_ip}:${nginx_port}/${password}"
    green "\nClash订阅链接：https://sublink.eooce.com/clash?config=http://${server_ip}:${nginx_port}/${password}\n"
    green "\nSing-box订阅链接：https://sublink.eooce.com/singbox?config=http://${server_ip}:${nginx_port}/${password}\n"
}

# Nginx配置
add_nginx_conf() {
    if ! command_exists nginx; then red "nginx未安装"; return 1; else manage_service "nginx" "stop" > /dev/null 2>&1; pkill nginx > /dev/null 2>&1; fi
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/sing-box.conf << EOF
server {
    listen $nginx_port; listen [::]:$nginx_port; server_name _;
    add_header X-Frame-Options DENY; add_header X-Content-Type-Options nosniff;
    location = /$password { alias /etc/sing-box/sub.txt; default_type 'text/plain; charset=utf-8'; add_header Cache-Control "no-cache"; }
    location / { return 404; } location ~ /\. { deny all; access_log off; }
}
EOF
    if [ ! -f "/etc/nginx/nginx.conf" ]; then
        cat > /etc/nginx/nginx.conf << EOF
user nginx; worker_processes auto; error_log /var/log/nginx/error.log; pid /run/nginx.pid;
events { worker_connections 1024; }
http { include /etc/nginx/mime.types; default_type application/octet-stream; access_log /var/log/nginx/access.log; sendfile on; keepalive_timeout 65; include /etc/nginx/conf.d/*.conf; }
EOF
    elif ! grep -q "include.*conf.d" /etc/nginx/nginx.conf; then
        sed -i "/http {/a \    include /etc/nginx/conf.d/*.conf;" /etc/nginx/nginx.conf
    fi
    nginx -t >/dev/null 2>&1 && start_nginx || restart_nginx
}

# 服务管理
manage_service() {
    local n=$1; local a=$2
    command_exists rc-service && rc-service "$n" "$a" || systemctl "$a" "$n"
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
    [[ "$choice" != "y" && "$choice" != "Y" ]] && purple "取消卸载" && return
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
    reading "\n是否卸载 Nginx？(y/n): " choice
    [[ "$choice" == "y" || "$choice" == "Y" ]] && manage_packages uninstall nginx
    green "\n卸载成功\n" && exit 0
}

# 创建快捷指令
create_shortcut() {
    yellow "\n配置快捷指令 hu..."
    curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL"
    chmod +x "$LOCAL_SCRIPT"
    
    cat > "/usr/bin/hu" << EOF
#!/bin/bash
if [ -s "$LOCAL_SCRIPT" ]; then
    bash "$LOCAL_SCRIPT" \$1
else
    echo -e "\033[1;33m本地脚本丢失，尝试从 GitHub 重新下载...\033[0m"
    mkdir -p "$work_dir"
    curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL"
    chmod +x "$LOCAL_SCRIPT"
    [ -s "$LOCAL_SCRIPT" ] && bash "$LOCAL_SCRIPT" \$1 || echo -e "\033[1;91m下载失败\033[0m"
fi
EOF
    chmod +x "/usr/bin/hu"
    green "\n>>> 快捷指令 hu 已配置 (纯 IPv6 适配版) <<<\n"
}

# Alpine适配
change_hosts() {
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 菜单功能
setup_argo_fixed() {
    clear
    yellow "\n固定隧道配置 (端口:${vmess_port})\n"
    reading "域名: " argo_domain
    reading "Token/Json: " argo_auth
    [ -z "$argo_domain" ] || [ -z "$argo_auth" ] && red "不能为空" && return
    stop_argo >/dev/null 2>&1
    
    # 动态参数
    EDGE_ARG="--edge-ip-version $ARGO_EDGE_IP"
    
    if [[ $argo_auth =~ TunnelSecret ]]; then
        echo "$argo_auth" > "${work_dir}/tunnel.json"
        TUNNEL_ID=$(cut -d\" -f12 <<< "$argo_auth")
        cat > "${work_dir}/tunnel.yml" << EOF
tunnel: $TUNNEL_ID
credentials-file: ${work_dir}/tunnel.json
protocol: http2
ingress:
  - hostname: $argo_domain
    service: http://localhost:${vmess_port}
    originRequest: { noTLSVerify: true }
  - service: http_status:404
EOF
        CMD_ARGS="-c '/etc/sing-box/argo tunnel $EDGE_ARG --config /etc/sing-box/tunnel.yml run 2>&1'"
    else
        echo "hostname: $argo_domain" > "${work_dir}/tunnel.yml"
        CMD_ARGS="-c '/etc/sing-box/argo tunnel $EDGE_ARG --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'"
    fi

    if command_exists rc-service; then sed -i "/^command_args=/c\\command_args=\"$CMD_ARGS\"" /etc/init.d/argo
    else ESCAPED=$(echo "$CMD_ARGS" | sed 's/"/\\"/g'); sed -i "/^ExecStart=/c\\ExecStart=/bin/sh -c \"${CMD_ARGS//\'/}\"" /etc/systemd/system/argo.service; fi

    restart_argo
    green "\n配置完成，正在刷新信息..." && sleep 3 && get_info
}

# 主菜单
menu() {
    singbox_status=$(check_singbox 2>/dev/null); nginx_status=$(check_nginx 2>/dev/null); argo_status=$(check_argo 2>/dev/null)
    clear
    purple "\n=== Argo + VMess + WS 管理脚本 (纯v6适配版) ===\n"
    echo -e "Argo: ${argo_status} | Nginx: ${nginx_status} | Sing-box: ${singbox_status}\n"
    green "1. 安装"
    red "2. 卸载"
    green "3. 查看节点信息"
    green "4. 配置固定隧道"
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

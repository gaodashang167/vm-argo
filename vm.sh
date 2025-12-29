#!/bin/bash
# =========================
# Argo + VMess + WS 安装脚本 (复刻老王核心逻辑版)
# 1. 全局强制修复 /etc/hosts (解决 v6 localhost 解析问题)
# 2. 严格区分 Token/JSON 启动方式
# 3. 修复 hu 命令和节点显示
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

# 常量
server_name="sing-box"
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
domain_file="${work_dir}/fixed_domain.txt" # 单独记录固定域名
GITHUB_URL="https://raw.githubusercontent.com/gaodashang167/vm-argo/main/vm.sh"
LOCAL_SCRIPT="${work_dir}/vm.sh"

export vmess_port=${PORT:-8001}
export CFIP=${CFIP:-'cf.877774.xyz'}
export CFPORT=${CFPORT:-'443'}

[[ $EUID -ne 0 ]] && red "请在root用户下运行脚本" && exit 1

# === 关键函数：强制修复 Hosts (参考老王脚本) ===
fix_hosts() {
    # 无论什么系统，确保 localhost 同时解析到 v4 和 v6 回环
    if [ -f /etc/hosts ]; then
        # 备份一下
        cp /etc/hosts /etc/hosts.bak 2>/dev/null
        # 确保第一行是 127.0.0.1，第二行是 ::1
        sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
        sed -i '2s/.*/::1         localhost/' /etc/hosts
        # 有些系统需要这个参数
        if [ -f /proc/sys/net/ipv4/ping_group_range ]; then
            echo "0 0" > /proc/sys/net/ipv4/ping_group_range
        fi
    fi
}

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

get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    ipv6() { curl -6 -sm 2 ip.sb; }
    if [ -z "$ip" ]; then echo "[$(ipv6)]"
    else echo "$ip"; fi
}

install_singbox() {
    clear
    purple "正在安装sing-box..."
    fix_hosts # 安装时执行 Hosts 修复

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

    # 默认临时隧道配置
    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
NoNewPrivileges=yes
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1"
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
command_args="-c '/etc/sing-box/argo tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF
    chmod +x /etc/init.d/sing-box /etc/init.d/argo
    rc-update add sing-box default > /dev/null 2>&1
    rc-update add argo default > /dev/null 2>&1
}

get_info() {
    if [ -z "$uuid" ] && [ -f "$config_dir" ]; then
        command_exists jq && uuid=$(jq -r '.inbounds[0].users[0].uuid' "$config_dir") || uuid=$(grep -o '"uuid": *"[^"]*"' "$config_dir" | head -1 | cut -d'"' -f4)
    fi
    yellow "\n获取节点信息..."
    server_ip=$(get_realip)
    isp=$(curl -s --max-time 2 https://ipapi.co/json | grep -o '"org":"[^"]*"' | cut -d'"' -f4 | sed 's/ /_/g' || echo "VPS")
    
    argodomain=""
    
    # 1. 优先读取固定域名文件 (Token模式)
    if [ -f "$domain_file" ]; then
        argodomain=$(cat "$domain_file")
    # 2. 其次读取 yml (JSON模式)
    elif [ -f "${work_dir}/tunnel.yml" ]; then
        argodomain=$(grep "hostname:" "${work_dir}/tunnel.yml" | head -1 | awk '{print $2}' | tr -d ' "')
    fi

    # 3. 最后才找日志 (临时模式)
    if [ -z "$argodomain" ]; then
        for i in {1..3}; do
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
            [ -n "$argodomain" ] && break
            sleep 1
        done
        if [ -z "$argodomain" ]; then
            purple "临时域名获取中..."
            restart_argo >/dev/null 2>&1 && sleep 5
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
        fi
    else
        green "\n检测到固定隧道: ${argodomain}"
    fi
    
    [ -z "$argodomain" ] && red "获取域名失败，请检查服务。" && return

    green "\nArgo域名：${purple}$argodomain${re}\n"
    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"false\"}"

    echo "vmess://$(echo "$VMESS" | base64 -w0)" > ${work_dir}/url.txt
    echo ""
    purple "$(cat ${work_dir}/url.txt)"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt && chmod 644 ${work_dir}/sub.txt
    
    green "\n订阅链接：http://${server_ip}:${nginx_port}/${password}\n"
}

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

manage_service() { local n=$1; local a=$2; command_exists rc-service && rc-service "$n" "$a" || systemctl "$a" "$n"; }
start_singbox() { manage_service "sing-box" "start"; }
stop_singbox() { manage_service "sing-box" "stop"; }
restart_singbox() { manage_service "sing-box" "restart"; }
start_argo() { manage_service "argo" "start"; }
stop_argo() { manage_service "argo" "stop"; }
restart_argo() { manage_service "argo" "restart"; }
start_nginx() { manage_service "nginx" "start"; }
restart_nginx() { manage_service "nginx" "restart"; }

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

create_shortcut() {
    yellow "\n配置快捷指令 hu..."
    curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL"
    chmod +x "$LOCAL_SCRIPT"
    cat > "/usr/bin/hu" << EOF
#!/bin/bash
if [ -s "$LOCAL_SCRIPT" ]; then bash "$LOCAL_SCRIPT" \$1; else
    mkdir -p "$work_dir" && curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL" && chmod +x "$LOCAL_SCRIPT"
    [ -s "$LOCAL_SCRIPT" ] && bash "$LOCAL_SCRIPT" \$1 || echo "下载失败"
fi
EOF
    chmod +x "/usr/bin/hu"
    green "\n>>> hu 命令已配置 <<<\n"
}

# 核心修复部分：固定隧道
setup_argo_fixed() {
    clear
    yellow "\n固定隧道配置 (端口:${vmess_port})\n"
    reading "域名: " argo_domain
    reading "Token/Json: " argo_auth
    [ -z "$argo_domain" ] || [ -z "$argo_auth" ] && red "不能为空" && return
    stop_argo >/dev/null 2>&1
    
    # 记录域名到文件，供 get_info 使用 (替代 tunnel.yml 在 Token 模式下的作用)
    echo "$argo_domain" > "$domain_file"

    # 执行一次 hosts 修复，确保万无一失
    fix_hosts

    if [[ $argo_auth =~ TunnelSecret ]]; then
        # === JSON 模式 ===
        echo "$argo_auth" > "${work_dir}/tunnel.json"
        TUNNEL_ID=$(cut -d\" -f12 <<< "$argo_auth")
        
        # 老王同款配置，显式指定 ingress
        cat > "${work_dir}/tunnel.yml" << EOF
tunnel: $TUNNEL_ID
credentials-file: ${work_dir}/tunnel.json
protocol: http2
ingress:
  - hostname: $argo_domain
    service: http://localhost:${vmess_port}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
        # 启动命令
        CMD_ARGS="-c '/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1'"
    else
        # === Token 模式 ===
        # 严格遵守老王逻辑：Token模式下不使用 tunnel.yml 配置 Ingress
        # 而是直接命令行启动。注意：Cloudflare 后台必须配置 Service: http://localhost:8001
        
        # 移除可能存在的旧 tunnel.yml 防止干扰
        rm -f "${work_dir}/tunnel.yml"
        
        # 启动命令 (同老王)
        CMD_ARGS="-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'"
    fi

    # 注入服务
    if command_exists rc-service; then
        sed -i "/^command_args=/c\\command_args=\"$CMD_ARGS\"" /etc/init.d/argo
    else
        ESCAPED=$(echo "$CMD_ARGS" | sed 's/"/\\"/g')
        sed -i "/^ExecStart=/c\\ExecStart=/bin/sh -c \"${CMD_ARGS//\'/}\"" /etc/systemd/system/argo.service
    fi

    restart_argo
    green "\n配置完成，正在刷新..." && sleep 3 && get_info
}

menu() {
    singbox_status=$(check_singbox 2>/dev/null); nginx_status=$(check_nginx 2>/dev/null); argo_status=$(check_argo 2>/dev/null)
    clear
    purple "\n=== Argo + VMess + WS (复刻老王版) ===\n"
    echo -e "Argo: ${argo_status} | Nginx: ${nginx_status} | Sing-box: ${singbox_status}\n"
    green "1. 安装"
    red "2. 卸载"
    green "3. 查看节点"
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
                if command_exists systemctl; then main_systemd_services; else alpine_openrc_services; rc-service sing-box restart; rc-service argo restart; fi
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

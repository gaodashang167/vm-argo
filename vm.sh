#!/bin/bash
# =========================
# Argo + VMess + WS 安装脚本 (稳定重制版)
# 基于老王核心逻辑 + 智能 IPv6 回源适配
# =========================

export LANG=en_US.UTF-8

# 颜色定义
red() { echo -e "\e[1;91m$1\033[0m"; }
green() { echo -e "\e[1;32m$1\033[0m"; }
yellow() { echo -e "\e[1;33m$1\033[0m"; }
purple() { echo -e "\e[1;35m$1\033[0m"; }
reading() { read -p "$(red "$1")" "$2"; }

# 变量配置
work_dir="/etc/sing-box"
config_dir="${work_dir}/config.json"
client_dir="${work_dir}/url.txt"
domain_file="${work_dir}/fixed_domain.txt"
GITHUB_URL="https://raw.githubusercontent.com/gaodashang167/vm-argo/main/vm.sh"
LOCAL_SCRIPT="${work_dir}/vm.sh"

export vmess_port=${PORT:-8001}
export CFIP=${CFIP:-'cf.877774.xyz'} 
export CFPORT=${CFPORT:-'443'}

# 检查 Root
[[ $EUID -ne 0 ]] && red "请在root用户下运行" && exit 1

# === 核心探测函数 ===
# 检测是否为纯 IPv6 环境
check_ipv6_only() {
    if ! ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1; then return 0; else return 1; fi
}

# 决定 Argo 连接 Sing-box 的地址 (解决 localhost 不通的问题)
get_origin_url() {
    if check_ipv6_only; then
        echo "http://[::1]:$vmess_port"
    else
        echo "http://127.0.0.1:$vmess_port"
    fi
}
# 决定 Argo 连接 Cloudflare 的 IP 版本
get_edge_ip_arg() {
    if check_ipv6_only; then echo "--edge-ip-version 6"; else echo "--edge-ip-version auto"; fi
}

command_exists() { command -v "$1" >/dev/null 2>&1; }

# 检查服务状态
check_service() {
    local n=$1; local f=$2
    [[ ! -f "$f" ]] && { red "未安装"; return 2; }
    if command_exists apk; then rc-service "$n" status | grep -q "started" && green "运行中" || yellow "未运行"
    else systemctl is-active "$n" | grep -q "^active$" && green "运行中" || yellow "未运行"; fi
}

check_status() {
    echo -e "Argo: $(check_service argo ${work_dir}/argo) | Sing-box: $(check_service sing-box ${work_dir}/sing-box)"
}

# 依赖管理
manage_packages() {
    if [ $# -lt 2 ]; then return 1; fi
    action=$1; shift
    for pkg in "$@"; do
        if [ "$action" == "install" ]; then
            command_exists "$pkg" && continue
            yellow "安装 $pkg..."
            if command_exists apt; then DEBIAN_FRONTEND=noninteractive apt install -y "$pkg"
            elif command_exists apk; then apk update && apk add "$pkg"
            elif command_exists yum; then yum install -y "$pkg"
            elif command_exists dnf; then dnf install -y "$pkg"
            fi
        elif [ "$action" == "uninstall" ]; then
            command_exists "$pkg" || continue
            if command_exists apt; then apt remove -y "$pkg"
            elif command_exists apk; then apk del "$pkg"
            elif command_exists yum; then yum remove -y "$pkg"
            fi
        fi
    done
}

# 获取公网IP
get_realip() {
    ip=$(curl -4 -sm 2 ip.sb)
    if [ -z "$ip" ]; then curl -6 -sm 2 ip.sb; else echo "$ip"; fi
}

# 安装核心
install_singbox() {
    clear
    purple "正在安装 Sing-box..."
    
    # 架构检测
    ARCH_RAW=$(uname -m)
    case "${ARCH_RAW}" in
        'x86_64') ARCH='amd64' ;;
        'x86'|'i386') ARCH='386' ;;
        'aarch64'|'arm64') ARCH='arm64' ;;
        *) red "不支持架构: ${ARCH_RAW}"; exit 1 ;;
    esac

    mkdir -p "${work_dir}" && chmod 777 "${work_dir}"
    
    # 增加下载校验
    yellow "下载组件中..."
    curl -sLo "${work_dir}/qrencode" "https://$ARCH.ssss.nyc.mn/qrencode"
    curl -sLo "${work_dir}/sing-box" "https://$ARCH.ssss.nyc.mn/sbx"
    curl -sLo "${work_dir}/argo" "https://$ARCH.ssss.nyc.mn/bot"
    
    if [ ! -s "${work_dir}/sing-box" ] || [ ! -s "${work_dir}/argo" ]; then
        red "下载失败！请检查网络或更换 VPS DNS。"
        exit 1
    fi

    chmod +x "${work_dir}"/*
    chown root:root "${work_dir}"/*

    # 生成配置
    uuid=$(cat /proc/sys/kernel/random/uuid)
    # 如果已有配置文件且有 UUID，保留它
    if [ -f "$config_dir" ]; then
        old_uuid=$(grep -o '"uuid": *"[^"]*"' "$config_dir" | head -1 | cut -d'"' -f4)
        [ -n "$old_uuid" ] && uuid="$old_uuid"
    fi

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

# 配置系统服务
main_systemd_services() {
    ORIGIN=$(get_origin_url)
    EDGE_ARG=$(get_edge_ip_arg)

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

    cat > /etc/systemd/system/argo.service << EOF
[Unit]
Description=Cloudflare Tunnel
After=network.target
[Service]
Type=simple
NoNewPrivileges=yes
ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --url $ORIGIN --no-autoupdate $EDGE_ARG --protocol http2 > /etc/sing-box/argo.log 2>&1"
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable sing-box argo
    systemctl restart sing-box argo
}

alpine_openrc_services() {
    ORIGIN=$(get_origin_url)
    EDGE_ARG=$(get_edge_ip_arg)

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
command_args="-c '/etc/sing-box/argo tunnel --url $ORIGIN --no-autoupdate $EDGE_ARG --protocol http2 > /etc/sing-box/argo.log 2>&1'"
command_background=true
pidfile="/var/run/argo.pid"
EOF
    chmod +x /etc/init.d/sing-box /etc/init.d/argo
    rc-update add sing-box default
    rc-update add argo default
    
    # 仅 Alpine 修改 hosts
    sh -c 'echo "0 0" > /proc/sys/net/ipv4/ping_group_range'
    sed -i '1s/.*/127.0.0.1   localhost/' /etc/hosts
    sed -i '2s/.*/::1         localhost/' /etc/hosts
}

# 获取信息
get_info() {
    yellow "\n获取节点信息..."
    
    # 确保 uuid 存在
    if [ -z "$uuid" ]; then
        if [ -f "$config_dir" ]; then
             uuid=$(grep -o '"uuid": *"[^"]*"' "$config_dir" | head -1 | cut -d'"' -f4)
        fi
        [ -z "$uuid" ] && red "无法读取 UUID，请检查安装。" && return
    fi

    server_ip=$(get_realip)
    isp=$(curl -s --max-time 2 https://ipapi.co/json | grep -o '"org":"[^"]*"' | cut -d'"' -f4 | sed 's/ /_/g' || echo "VPS")
    
    argodomain=""
    # 优先读取文件记录
    [ -f "$domain_file" ] && argodomain=$(cat "$domain_file")
    
    # 读取日志
    if [ -z "$argodomain" ]; then
        for i in {1..3}; do
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
            [ -n "$argodomain" ] && break
            sleep 1
        done
        # 还没获取到，尝试重启一次
        if [ -z "$argodomain" ]; then
            purple "临时域名未生成，正在重试..."
            if command_exists systemctl; then systemctl restart argo; else rc-service argo restart; fi
            sleep 5
            argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "${work_dir}/argo.log" | head -1)
        fi
    else
        green "\n检测到固定隧道: ${argodomain}"
    fi

    if [ -z "$argodomain" ]; then
        red "获取 Argo 域名失败！"
        yellow "请检查日志: tail -n 20 /etc/sing-box/argo.log"
        return
    fi

    green "\nArgo域名：${purple}$argodomain${re}\n"
    
    VMESS="{ \"v\": \"2\", \"ps\": \"${isp}\", \"add\": \"${CFIP}\", \"port\": \"${CFPORT}\", \"id\": \"${uuid}\", \"aid\": \"0\", \"scy\": \"none\", \"net\": \"ws\", \"type\": \"none\", \"host\": \"${argodomain}\", \"path\": \"/vmess-argo?ed=2560\", \"tls\": \"tls\", \"sni\": \"${argodomain}\", \"alpn\": \"\", \"fp\": \"firefox\", \"allowlnsecure\": \"false\"}"

    echo "vmess://$(echo "$VMESS" | base64 -w0)" > ${work_dir}/url.txt
    echo ""
    purple "$(cat ${work_dir}/url.txt)"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt && chmod 644 ${work_dir}/sub.txt
    
    green "\n订阅链接：http://${server_ip}:${nginx_port}/${password}\n"
}

# 配置 Nginx
add_nginx_conf() {
    if ! command_exists nginx; then return 1; fi
    mkdir -p /etc/nginx/conf.d
    cat > /etc/nginx/conf.d/sing-box.conf << EOF
server {
    listen $nginx_port; listen [::]:$nginx_port; server_name _;
    location = /$password { alias /etc/sing-box/sub.txt; default_type 'text/plain; charset=utf-8'; add_header Cache-Control "no-cache"; }
    location / { return 404; }
}
EOF
    [ ! -f "/etc/nginx/nginx.conf" ] && cat > /etc/nginx/nginx.conf << EOF
user nginx; worker_processes auto; error_log /var/log/nginx/error.log; pid /run/nginx.pid;
events { worker_connections 1024; }
http { include /etc/nginx/mime.types; default_type application/octet-stream; access_log /var/log/nginx/access.log; sendfile on; include /etc/nginx/conf.d/*.conf; }
EOF
    nginx -t >/dev/null 2>&1 && { if command_exists systemctl; then systemctl restart nginx; else rc-service nginx restart; fi; }
}

# 卸载
uninstall_singbox() {
    reading "确定卸载? (y/n): " choice
    [[ "$choice" != "y" && "$choice" != "Y" ]] && return
    yellow "正在卸载..."
    if command_exists systemctl; then
        systemctl stop sing-box argo
        systemctl disable sing-box argo
        rm /etc/systemd/system/sing-box.service /etc/systemd/system/argo.service
        systemctl daemon-reload
    else
        rc-service sing-box stop; rc-service argo stop
        rc-update del sing-box default; rc-update del argo default
        rm /etc/init.d/sing-box /etc/init.d/argo
    fi
    rm -rf "${work_dir}" /etc/nginx/conf.d/sing-box.conf /usr/bin/hu
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
    mkdir -p "$work_dir" && curl -sLo "$LOCAL_SCRIPT" "$GITHUB_URL" && chmod +x "$LOCAL_SCRIPT"
    [ -s "$LOCAL_SCRIPT" ] && bash "$LOCAL_SCRIPT" \$1
fi
EOF
    chmod +x "/usr/bin/hu"
    green "\n>>> hu 命令已配置 <<<\n"
}

# 配置固定隧道
setup_argo_fixed() {
    clear
    yellow "\n固定隧道配置 (端口:${vmess_port})\n"
    reading "域名: " argo_domain
    reading "Token/Json: " argo_auth
    [ -z "$argo_domain" ] || [ -z "$argo_auth" ] && red "不能为空" && return
    
    # 停止服务
    if command_exists systemctl; then systemctl stop argo; else rc-service argo stop; fi
    
    # 记录域名
    echo "$argo_domain" > "$domain_file"
    
    ORIGIN=$(get_origin_url)
    EDGE_ARG=$(get_edge_ip_arg)

    if [[ $argo_auth =~ TunnelSecret ]]; then
        # JSON 模式
        echo "$argo_auth" > "${work_dir}/tunnel.json"
        TUNNEL_ID=$(cut -d\" -f12 <<< "$argo_auth")
        cat > "${work_dir}/tunnel.yml" << EOF
tunnel: $TUNNEL_ID
credentials-file: ${work_dir}/tunnel.json
protocol: http2
ingress:
  - hostname: $argo_domain
    service: $ORIGIN
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF
        CMD_ARGS="-c '/etc/sing-box/argo tunnel $EDGE_ARG --config /etc/sing-box/tunnel.yml run 2>&1'"
    else
        # Token 模式：不使用 tunnel.yml，直接命令行
        # ⚠️ 再次提醒用户修改后台
        yellow "\n======================================================="
        yellow "⚠️ 警告：使用 Token 模式"
        yellow "请务必登录 Cloudflare 后台 -> Tunnels -> Configure -> Public Hostname"
        yellow "将 Service URL 修改为: ${green}${ORIGIN}${yellow}"
        yellow "=======================================================\n"
        reading "确认已在后台修改完成？(按回车继续)" confirm
        
        # 删除旧 yml 避免干扰
        rm -f "${work_dir}/tunnel.yml"
        CMD_ARGS="-c '/etc/sing-box/argo tunnel $EDGE_ARG --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'"
    fi

    # 更新启动命令
    if command_exists rc-service; then
        sed -i "/^command_args=/c\\command_args=\"$CMD_ARGS\"" /etc/init.d/argo
        rc-service argo restart
    else
        ESCAPED=$(echo "$CMD_ARGS" | sed 's/"/\\"/g')
        sed -i "/^ExecStart=/c\\ExecStart=/bin/sh -c \"${CMD_ARGS//\'/}\"" /etc/systemd/system/argo.service
        systemctl daemon-reload
        systemctl restart argo
    fi

    green "\n配置完成，正在刷新..." && sleep 3 && get_info
}

# 菜单
menu() {
    clear
    purple "\n=== Argo + VMess + WS (稳定版) ===\n"
    check_status
    echo ""
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
            if [ -f "${work_dir}/sing-box" ]; then yellow "已安装"; create_shortcut; else
                manage_packages install nginx jq tar openssl lsof coreutils
                install_singbox
                if command_exists systemctl; then main_systemd_services; else alpine_openrc_services; fi
                sleep 5; get_info; add_nginx_conf; create_shortcut
            fi ;;
        2) uninstall_singbox ;;
        3) get_info ;;
        4) setup_argo_fixed ;;
        5) if command_exists systemctl; then systemctl restart sing-box argo nginx; else rc-service sing-box restart; rc-service argo restart; rc-service nginx restart; fi; green "已重启" ;;
        0) exit 0 ;;
        *) red "无效选项" ;;
    esac
    read -n 1 -s -r -p "按任意键继续..."
done

# 查看节点信息
check_nodes() {
    if [ ! -f "${work_dir}/url.txt" ]; then
        yellow "节点信息文件不存在，请先安装\n"
        return 1
    fi
    
    purple "$(cat ${work_dir}/url.txt)"
    server_ip=$(get_realip)
    lujing=$(sed -n 's|.*location = /\([^ ]*\).*|\1|p' "/etc/nginx/conf.d/sing-box.conf" 2>/dev/null)
    sub_port=$(sed -n 's/^\s*listen \([0-9]\+\);/\1/p' "/etc/nginx/conf.d/sing-box.conf" 2>/dev/null)
    
    if [ -n "$lujing" ] && [ -n "$sub_port" ]; then
        base64_url="http://${server_ip}:${sub_port}/${lujing}"
        green "\n\nV2rayN等订阅链接: ${purple}${base64_url}${re}\n"
        green "Clash订阅链接: ${purple}https://sublink.eooce.com/clash?config=${base64_url}${re}\n"
        green "sing-box订阅链接: ${purple}https://sublink.eooce.com/singbox?config=${base64_url}${re}\n"
    else
        yellow "\n订阅服务未配置\n"
    fi
}

# Argo 管理菜单
manage_argo() {
    local argo_status=$(check_argo 2>/dev/null)
    local argo_installed=$?

    clear
    echo ""
    green "=== Argo 隧道管理 ===\n"
    green "Argo当前状态: $argo_status\n"
    green "1. 启动Argo服务"
    skyblue "------------"
    green "2. 停止Argo服务"
    skyblue "------------"
    green "3. 重启Argo服务"
    skyblue "------------"
    green "4. 添加Argo固定隧道"
    skyblue "----------------"
    green "5. 切换回Argo临时隧道"
    skyblue "------------------"
    green "6. 重新获取Argo临时域名"
    skyblue "-------------------"
    purple "0. 返回主菜单"
    skyblue "-----------"
    reading "\n请输入选择: " choice
    case "${choice}" in
        1)  start_argo ;;
        2)  stop_argo ;; 
        3)  
            clear
            if command_exists rc-service 2>/dev/null; then
                grep -Fq -- '--url http://localhost' /etc/init.d/argo && get_quick_tunnel && change_argo_domain || { green "\n当前使用固定隧道,无需获取临时域名\n"; sleep 2; }
            else
                grep -q 'ExecStart=.*--url http://localhost' /etc/systemd/system/argo.service && get_quick_tunnel && change_argo_domain || { green "\n当前使用固定隧道,无需获取临时域名\n"; sleep 2; }
            fi
         ;; 
        4)
            clear
            yellow "\n固定隧道可为json或token，固定隧道端口为${vmess_port}，请自行在cf后台设置\n\njson在f佬维护的站点里获取，获取地址：${purple}https://fscarmen.cloudflare.now.cc${re}\n"
            reading "\n请输入你的argo域名: " argo_domain
            ArgoDomain=$argo_domain
            reading "\n请输入你的argo密钥(token或json): " argo_auth
            
            if [[ $argo_auth =~ TunnelSecret ]]; then
                echo $argo_auth > ${work_dir}/tunnel.json
                cat > ${work_dir}/tunnel.yml << EOF
tunnel: $(cut -d\" -f12 <<< "$argo_auth")
credentials-file: ${work_dir}/tunnel.json
protocol: http2
                                           
ingress:
  - hostname: $ArgoDomain
    service: http://localhost:${vmess_port}
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF

                if command_exists rc-service 2>/dev/null; then
                    sed -i '/^command_args=/c\command_args="-c '\''/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1'\''"' /etc/init.d/argo
                else
                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --config /etc/sing-box/tunnel.yml run 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo
                sleep 1 
                change_argo_domain

            elif [[ $argo_auth =~ ^[A-Z0-9a-z=]{120,250}$ ]]; then
                if command_exists rc-service 2>/dev/null; then
                    sed -i "/^command_args=/c\command_args=\"-c '/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token $argo_auth 2>&1'\"" /etc/init.d/argo
                else
                    sed -i '/^ExecStart=/c ExecStart=/bin/sh -c "/etc/sing-box/argo tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token '$argo_auth' 2>&1"' /etc/systemd/system/argo.service
                fi
                restart_argo
                sleep 1 
                change_argo_domain
            else
                yellow "你输入的argo域名或token不匹配，请重新输入\n"
                sleep 2
                manage_argo            
            fi
            ;; 
        5)
            clear
            yellow "正在切换回临时隧道...\n"
            if command_exists rc-service 2>/dev/null; then
                alpine_openrc_services
            else
                main_systemd_services
            fi
            get_quick_tunnel
            change_argo_domain 
            ;; 

        6)  
            if command_exists rc-service 2>/dev/null; then
                if grep -Fq -- '--url http://localhost' "/etc/init.d/argo"; then
                    get_quick_tunnel
                    change_argo_domain 
                else
                    yellow "当前使用固定隧道，无法获取临时隧道\n"
                    sleep 2
                fi
            else
                if grep -q 'ExecStart=.*--url http://localhost' "/etc/systemd/system/argo.service"; then
                    get_quick_tunnel
                    change_argo_domain 
                else
                    yellow "当前使用固定隧道，无法获取临时隧道\n"
                    sleep 2
                fi
            fi 
            ;; 
        0)  return ;; 
        *)  red "无效的选项！\n" && sleep 1 && manage_argo ;;
    esac
}

# 获取argo临时隧道
get_quick_tunnel() {
    restart_argo
    yellow "获取临时argo域名中，请稍等...\n"
    sleep 3
    if [ -f /etc/sing-box/argo.log ]; then
        for i in {1..5}; do
            purple "第 $i 次尝试获取ArgoDoamin中..."
            get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "/etc/sing-box/argo.log")
            [ -n "$get_argodomain" ] && break
            sleep 2
        done
    else
        restart_argo
        sleep 6
        get_argodomain=$(sed -n 's|.*https://\([^/]*trycloudflare\.com\).*|\1|p' "/etc/sing-box/argo.log")
    fi
    green "ArgoDomain：${purple}$get_argodomain${re}\n"
    ArgoDomain=$get_argodomain
}

# 更新Argo域名到订阅
change_argo_domain() {
    if [ ! -f "$client_dir" ]; then
        red "节点配置文件不存在\n"
        return 1
    fi
    
    content=$(cat "$client_dir")
    vmess_url=$(grep -o 'vmess://[^ ]*' "$client_dir")
    
    if [ -z "$vmess_url" ]; then
        red "未找到vmess节点信息\n"
        return 1
    fi
    
    vmess_prefix="vmess://"
    encoded_vmess="${vmess_url#"$vmess_prefix"}"
    decoded_vmess=$(echo "$encoded_vmess" | base64 --decode 2>/dev/null)
    
    if [ -z "$decoded_vmess" ]; then
        red "vmess节点解码失败\n"
        return 1
    fi
    
    updated_vmess=$(echo "$decoded_vmess" | jq --arg new_domain "$ArgoDomain" '.host = $new_domain | .sni = $new_domain')
    encoded_updated_vmess=$(echo "$updated_vmess" | base64 | tr -d '\n')
    new_vmess_url="${vmess_prefix}${encoded_updated_vmess}"
    new_content=$(echo "$content" | sed "s|$vmess_url|$new_vmess_url|")
    echo "$new_content" > "$client_dir"
    base64 -w0 ${work_dir}/url.txt > ${work_dir}/sub.txt
    green "vmess节点已更新,请更新订阅或手动复制以下vmess-argo节点\n"
    purple "$new_vmess_url\n" 
}

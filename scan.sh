#!/bin/bash

# 配置文件路径
CONFIG_FILE="$HOME/.scan_config"
# 后台任务日志文件
BACKGROUND_LOG="$HOME/scan_background.log"
# PID文件，保存后台运行的进程ID
PID_FILE="$HOME/scan_background.pid"
# 结果文件夹
RESULT_DIR="result"

# 加载上次配置
load_config() {
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        # 默认配置
        LAST_RATE="2500"
        LAST_PORTS="443,80-65535"
        LAST_CIDR=""
    fi
}

# 保存配置
save_config() {
    echo "LAST_RATE=\"$RATE\"" > "$CONFIG_FILE"
    echo "LAST_PORTS=\"$PORTS\"" >> "$CONFIG_FILE"
    echo "LAST_CIDR=\"$CIDR\"" >> "$CONFIG_FILE"
}

# 检查是否有后台任务正在运行
check_background_task() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            return 0  # 有任务正在运行
        else
            rm -f "$PID_FILE"  # 进程不存在，删除PID文件
            return 1  # 无任务运行
        fi
    else
        return 1  # 无任务运行
    fi
}

# 显示后台任务状态
show_background_status() {
    echo "========================================================"
    if check_background_task; then
        PID=$(cat "$PID_FILE")
        echo "状态: 有后台扫描任务正在运行 (PID: $PID)"
        echo "日志位置: $BACKGROUND_LOG"
        echo "查看日志: tail -f $BACKGROUND_LOG"
    else
        echo "状态: 当前没有后台扫描任务在运行"
    fi
    echo "========================================================"
}

# 安装masscan及依赖，并检查jq
install_masscan() {
    echo "开始安装masscan及其依赖..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y masscan
    elif command -v yum &> /dev/null; then
        sudo yum install -y masscan
    else
        echo "无法自动安装masscan，请手动安装后再运行此脚本"
        echo "可尝试以下方法安装："
        echo "1. Ubuntu/Debian: sudo apt-get install masscan"
        echo "2. CentOS/RHEL: sudo yum install masscan"
        echo "3. 从源码编译: https://github.com/robertdavidgraham/masscan"
        return 1
    fi

    # 检查并安装jq (用于处理JSON)
    if ! command -v jq &> /dev/null; then
        echo "jq未安装，正在尝试安装..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y jq
        elif command -v yum &> /dev/null; then
            sudo yum install -y jq
        else
            echo "无法自动安装jq，请手动安装后再运行此脚本"
            echo "可尝试以下方法安装："
            echo "1. Ubuntu/Debian: sudo apt-get install jq"
            echo "2. CentOS/RHEL: sudo yum install jq"
            echo "3. 访问 https://stedolan.github.io/jq/download/"
            # return 1 # Don't necessarily fail if jq install fails, can fallback
        fi
        if ! command -v jq &> /dev/null; then
             echo "警告: jq安装失败，将尝试使用grep/awk处理JSON，可能不稳定。"
        else
             echo "jq安装成功！"
        fi
    fi

    if command -v masscan &> /dev/null; then
        echo "masscan安装成功！"
        masscan --version
        return 0
    else
        echo "masscan安装失败，请尝试手动安装。"
        return 1
    fi
}

# 核心扫描与处理逻辑 (内部函数)
# 参数: CIDR, PORTS, RATE, JSON_OUTPUT_FILE, IP_SUCCESS_FILE, LOG_FILE (可选, 用于后台)
_execute_scan_logic() {
    local cidr="$1"
    local ports="$2"
    local rate="$3"
    local json_output="$4"
    local ip_success="$5"
    local log_file="$6" # Optional log file for background task

    local log_cmd=""
    if [ ! -z "$log_file" ]; then
        # 如果提供了日志文件，则将输出追加到日志
        exec >> "$log_file" 2>&1 # Redirect stdout/stderr of this function to log file
        echo "-----------------------------------------"
        echo "$(date): Starting scan execution..."
        log_cmd=">> \"$log_file\" 2>&1" # Command suffix for logging
    fi

    # 创建结果文件夹
    mkdir -p "$(dirname "$json_output")"

    # 执行masscan扫描，输出JSON格式
    echo "$(date): Running: sudo masscan $cidr -p$ports --rate=$rate -oJ \"$json_output\" --status-updates"
    eval "sudo masscan \"$cidr\" -p\"$ports\" --rate=\"$rate\" -oJ \"$json_output\" --status-updates $log_cmd"
    local masscan_exit_code=$?

    # 检查扫描是否成功
    if [ $masscan_exit_code -ne 0 ]; then
        echo "$(date): Masscan scan failed with exit code $masscan_exit_code!"
        [ ! -s "$json_output" ] && rm -f "$json_output"
        return 1
    fi
    echo "$(date): Masscan scan finished."

    # 处理结果，从JSON提取IP:端口
    echo "$(date): Processing results from $json_output..."
    local total_count=0
    if [ -s "$json_output" ]; then # 检查JSON文件是否非空
        if command -v jq &> /dev/null; then
            echo "$(date): Using jq to extract IP:Port..."
            jq -r '.[] | .ip + ":" + (.ports[0].port | tostring)' "$json_output" > "$ip_success"
            local jq_exit_code=$?
            if [ $jq_exit_code -eq 0 ]; then
                 total_count=$(jq '. | length' "$json_output")
                 echo "$(date): jq processing successful. Count: $total_count"
            else
                 echo "$(date): jq processing failed with exit code $jq_exit_code!"
                 > "$ip_success" # Create empty file on failure
                 total_count=0
            fi
        else
            # jq不可用时，尝试使用grep/awk
            echo "$(date): Warning: jq not found, attempting grep/awk extraction..."
            grep -oE '"ip": "[^"]+", "timestamp": "[^"]+", "ports": \[{"port": [0-9]+, "proto": "[^"]+", "status": "open"' "$json_output" | \
            awk -F'[:,"]+' '{print $4 ":" $14}' > "$ip_success"
            # Simple check if awk produced output
            if [ -s "$ip_success" ]; then
                 total_count=$(wc -l < "$ip_success") # Approximate count
                 echo "$(date): grep/awk extraction produced output. Count: $total_count"
            else
                 echo "$(date): grep/awk extraction failed or produced no output."
                 > "$ip_success"
                 total_count=0
            fi
        fi
    else
         echo "$(date): Scan completed, but no open ports found or JSON file is empty."
         > "$ip_success" # 创建一个空的ip_success.txt文件
         total_count=0
    fi

    echo "$(date): Result processing finished. Found $total_count open port records."
    return 0
}


# 启动后台任务的通用函数
# 参数: CIDR, PORTS, RATE, JSON_OUTPUT_FILE, IP_SUCCESS_FILE
_launch_background_task() {
    local cidr="$1"
    local ports="$2"
    local rate="$3"
    local json_output="$4"
    local ip_success="$5"

    echo "========================================================"
    echo "准备启动后台扫描任务..."
    echo "IP段: $cidr"
    echo "端口: $ports"
    echo "扫描速率: $rate pps"
    echo "原始JSON输出: $json_output"
    echo "IP:端口输出: $ip_success"
    echo "日志文件: $BACKGROUND_LOG"
    echo "PID 文件: $PID_FILE"
    echo "========================================================"
    echo "重要提示: 为了确保后台任务顺利运行（特别是长时间扫描），"
    echo "建议配置sudoers允许当前用户无密码执行masscan命令。"
    echo "例如，将类似 'your_username ALL=(ALL) NOPASSWD: /usr/bin/masscan' 的行添加到sudoers文件中。"
    echo "========================================================"
    read -p "确认启动后台任务吗? (y/n): " confirm_bg
    if [[ "$confirm_bg" != "y" && "$confirm_bg" != "Y" ]]; then
        echo "后台任务已取消。"
        return 1
    fi

    # 创建后台任务脚本 (使用内部函数)
    TEMP_SCRIPT="$HOME/scan_temp_script_$(date +%s).sh"
    cat > "$TEMP_SCRIPT" << EOL
#!/bin/bash
# Source the main script to get functions and variables
source "$0" --source-only # Pass a flag to avoid running menu etc.

# Call the core logic function
_execute_scan_logic "$cidr" "$ports" "$rate" "$json_output" "$ip_success" "$BACKGROUND_LOG"
SCAN_EXIT_CODE=\$?

# Clean up PID file after execution
rm -f "$PID_FILE"

echo "\$(date): Background scan script finished with exit code \$SCAN_EXIT_CODE." >> "$BACKGROUND_LOG"
exit \$SCAN_EXIT_CODE
EOL

    # 添加执行权限
    chmod +x "$TEMP_SCRIPT"

    # 启动后台任务
    nohup "$TEMP_SCRIPT" > /dev/null 2>&1 &
    BACKGROUND_PID=$!
    echo $BACKGROUND_PID > "$PID_FILE"

    echo "后台扫描任务已启动 (PID: $BACKGROUND_PID)"
    echo "可以安全退出SSH连接，扫描任务将在后台继续运行"
    echo "使用 'tail -f $BACKGROUND_LOG' 命令可以查看扫描进度"

    # 等待一会，确保任务正常启动
    sleep 2

    # 检查任务是否还在运行
    if ps -p $BACKGROUND_PID > /dev/null 2>&1; then
        echo "后台任务运行正常"
    else
        echo "后台任务启动失败！请检查日志文件: $BACKGROUND_LOG"
        rm -f "$PID_FILE"
    fi

    # 删除临时脚本 (nohup已经读取，可以删除)
    # rm -f $TEMP_SCRIPT # Keep it for debugging? Or remove it. Let's remove it.
    rm -f "$TEMP_SCRIPT"
    return 0
}


# 执行端口扫描 (选项2)
run_scan() {
    # 加载上次配置
    load_config

    # 获取用户输入的参数
    echo "请配置扫描参数："
    
    # 获取扫描速率
    read -p "请输入扫描速率(每秒数据包数)[上次: ${LAST_RATE:-1000}]: " RATE
    if [ -z "$RATE" ]; then
        RATE="${LAST_RATE:-1000}"
    fi
    
    # 获取端口范围
    read -p "请输入要扫描的端口范围(如443,80-65535)[上次: ${LAST_PORTS:-80,443}]: " PORTS
    if [ -z "$PORTS" ]; then
        PORTS="${LAST_PORTS:-80,443}"
    fi
    
    # 获取CIDR格式IP段，支持多个
    echo "请输入要扫描的CIDR格式IP段(如192.168.1.0/24)"
    echo "可输入多个IP段，每行一个，输入空行结束"
    if [ ! -z "$LAST_CIDR" ]; then
        echo "上次扫描的IP段: $LAST_CIDR"
    fi
    
    CIDR=""
    while true; do
        read -p "> " cidr_input
        if [ -z "$cidr_input" ]; then
            if [ -z "$CIDR" ] && [ ! -z "$LAST_CIDR" ]; then
                # 如果用户没有输入任何IP段且有上次记录，则使用上次的记录
                CIDR="$LAST_CIDR"
                break
            elif [ ! -z "$CIDR" ]; then
                # 如果已经输入了至少一个IP段，则结束输入
                break
            else
                echo "IP段不能为空！请输入至少一个CIDR格式IP段："
            fi
        else
            if [ -z "$CIDR" ]; then
                CIDR="$cidr_input"
            else
                CIDR="$CIDR,$cidr_input"
            fi
        fi
    done

    # 保存配置
    save_config

    # 创建结果文件夹
    mkdir -p "$RESULT_DIR"

    # 设置输出文件路径
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    JSON_OUTPUT_FILE="$RESULT_DIR/scan_raw_$TIMESTAMP.json"
    IP_SUCCESS_FILE="$RESULT_DIR/ip_success.txt"

    echo "========================================================"
    echo "扫描配置完成:"
    echo "IP段: $CIDR"
    echo "端口: $PORTS"
    echo "扫描速率: $RATE pps"
    echo "原始JSON输出: $JSON_OUTPUT_FILE"
    echo "IP:端口输出: $IP_SUCCESS_FILE"
    echo "========================================================"

    # 询问是否后台运行
    read -p "是否将本次扫描放入后台运行? (y/n, 默认 n): " run_in_bg
    if [[ "$run_in_bg" == "y" || "$run_in_bg" == "Y" ]]; then
        # 检查是否已有后台任务
        if check_background_task; then
            echo "错误: 已经有一个后台扫描任务在运行中！请等待其完成或手动停止。"
            return 1
        fi
        # 调用后台启动函数
        _launch_background_task "$CIDR" "$PORTS" "$RATE" "$JSON_OUTPUT_FILE" "$IP_SUCCESS_FILE"
    else
        # 在前台运行
        echo "将在前台执行扫描..."
        # 检查是否需要root权限
        if [ "$(id -u)" -ne 0 ]; then
            echo "注意: masscan通常需要root权限才能运行"
            echo "请输入密码以继续:"
            sudo echo "已获取临时权限" || { echo "未能获取root权限，扫描可能失败"; return 1; }
        fi

        # 调用核心扫描逻辑 (前台，无日志文件参数)
        _execute_scan_logic "$CIDR" "$PORTS" "$RATE" "$JSON_OUTPUT_FILE" "$IP_SUCCESS_FILE"
        local scan_exit_code=$?

        if [ $scan_exit_code -eq 0 ]; then
             echo "========================================================"
             echo "扫描结果已处理完成"
             echo "原始JSON数据保存在: $JSON_OUTPUT_FILE"
             echo "IP:端口格式数据保存在: $IP_SUCCESS_FILE"
             # 重新计算总数，因为_execute_scan_logic可能在后台运行
             if [ -f "$IP_SUCCESS_FILE" ];then
                TOTAL_COUNT=$(wc -l < "$IP_SUCCESS_FILE")
             else
                TOTAL_COUNT=0
             fi
             echo "共发现 $TOTAL_COUNT 个开放端口记录"
             echo "========================================================"

             # 显示前5个结果预览
             if [ $TOTAL_COUNT -gt 0 ]; then
                 echo "结果预览(前5个):"
                 head -n 5 "$IP_SUCCESS_FILE"
                 if [ $TOTAL_COUNT -gt 5 ]; then
                     echo "... 还有更多结果 ..."
                 fi
                 echo "========================================================"
             fi
        else
            echo "扫描或处理过程中发生错误。"
        fi
    fi
}

# 在后台运行端口扫描 (选项3)
background_scan() {
    # 显示当前后台任务状态
    show_background_status

    # 如果已有后台任务正在运行，提示用户
    if check_background_task; then
        echo "已经有一个后台扫描任务在运行中！"
        # read -p "是否要停止当前任务并开始新的扫描? (y/n): " choice # Removed forced stop
        # if [ "$choice" == "y" ] || [ "$choice" == "Y" ]; then
        #     PID=$(cat "$PID_FILE")
        #     echo "正在停止当前任务 (PID: $PID)..."
        #     kill $PID
        #     rm -f "$PID_FILE"
        # else
        #     return
        # fi
        echo "请等待当前任务完成或手动停止 (kill $(cat $PID_FILE)) 后再启动新任务。"
        return 1
    fi

    # 加载上次配置
    load_config

    # 获取用户输入的参数
    echo "请配置后台扫描参数："
    
    # 获取扫描速率
    read -p "请输入扫描速率(每秒数据包数)[上次: ${LAST_RATE:-1000}]: " RATE
    if [ -z "$RATE" ]; then
        RATE="${LAST_RATE:-1000}"
    fi
    
    # 获取端口范围
    read -p "请输入要扫描的端口范围(如443,80-65535)[上次: ${LAST_PORTS:-80,443}]: " PORTS
    if [ -z "$PORTS" ]; then
        PORTS="${LAST_PORTS:-80,443}"
    fi
    
    # 获取CIDR格式IP段，支持多个
    echo "请输入要扫描的CIDR格式IP段(如192.168.1.0/24)"
    echo "可输入多个IP段，每行一个，输入空行结束"
    if [ ! -z "$LAST_CIDR" ]; then
        echo "上次扫描的IP段: $LAST_CIDR"
    fi
    
    CIDR=""
    while true; do
        read -p "> " cidr_input
        if [ -z "$cidr_input" ]; then
            if [ -z "$CIDR" ] && [ ! -z "$LAST_CIDR" ]; then
                # 如果用户没有输入任何IP段且有上次记录，则使用上次的记录
                CIDR="$LAST_CIDR"
                break
            elif [ ! -z "$CIDR" ]; then
                # 如果已经输入了至少一个IP段，则结束输入
                break
            else
                echo "IP段不能为空！请输入至少一个CIDR格式IP段："
            fi
        else
            if [ -z "$CIDR" ]; then
                CIDR="$cidr_input"
            else
                CIDR="$CIDR,$cidr_input"
            fi
        fi
    done

    # 保存配置
    save_config

    # 创建结果文件夹
    mkdir -p "$RESULT_DIR"

    # 设置输出文件路径
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    JSON_OUTPUT_FILE="$RESULT_DIR/scan_raw_$TIMESTAMP.json"
    IP_SUCCESS_FILE="$RESULT_DIR/ip_success.txt" # Still overwrite this one

    # 调用后台启动函数
    _launch_background_task "$CIDR" "$PORTS" "$RATE" "$JSON_OUTPUT_FILE" "$IP_SUCCESS_FILE"

}

# 显示主菜单
show_menu() {
    clear
    echo "========================================================"
    echo "                   端口扫描工具                         "
    echo "========================================================"
    
    # 显示后台任务状态
    if check_background_task; then
        PID=$(cat "$PID_FILE")
        echo "状态: 有后台扫描任务正在运行 (PID: $PID)"
    else
        echo "状态: 当前没有后台扫描任务在运行"
    fi
    
    echo "------------------------------------------------------"
    echo "请选择操作："
    echo "1. 安装masscan工具及依赖"
    echo "2. 配置扫描参数并执行扫描"
    echo "3. 后台运行扫描任务"
    echo "0. 退出"
    echo "========================================================"
    read -p "请输入选项[0-3]: " choice
    
    case $choice in
        1)
            install_masscan
            read -p "按任意键继续..." key
            show_menu
            ;;
        2)
            # 检查masscan是否已安装
            if ! command -v masscan &> /dev/null; then
                echo "masscan未安装，请先选择选项1进行安装。"
                read -p "按任意键继续..." key
                show_menu
            else
                run_scan
                read -p "按任意键继续..." key
                show_menu
            fi
            ;;
        3)
            # 检查masscan是否已安装
            if ! command -v masscan &> /dev/null; then
                echo "masscan未安装，请先选择选项1进行安装。"
                read -p "按任意键继续..." key
                show_menu
            else
                background_scan
                read -p "按任意键继续..." key
                show_menu
            fi
            ;;
        0)
            echo "感谢使用，再见！"
            exit 0
            ;;
        *)
            echo "无效选项，请重新输入！"
            read -p "按任意键继续..." key
            show_menu
            ;;
    esac
}

# 程序入口
# 检查jq是否安装
if ! command -v jq &> /dev/null; then
    echo "警告: JSON处理工具jq未安装，部分功能可能受限或不稳定。"
    echo "建议运行选项1进行安装检查。"
fi
show_menu

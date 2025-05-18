import concurrent.futures
import subprocess
import sys
import os
import json
from time import time
from datetime import datetime
from urllib.parse import urlparse
import argparse
import ipaddress
import signal
import threading
import re

# 直接在脚本中定义配置，这些值将被动态修改
DEFAULT_TEST_URL = "https://api.ipify.org"
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 3

USERNAME_LIST = ['admin', '123456', '123', 'socks5', '12345678', '111']
PASSWORD_LIST = ['admin', '123456', '123', 'socks5', '12345678', '111']

print_lock = threading.Lock() # 全局打印锁
LINE_CLEAR_SEQUENCE = f"\r{' '*95}\r" # 用于清除行的序列，长度95基本足够

def parse_proxy(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None

    # Try Format 1: ip:port|user:pwd
    if '|' in line:
        try:
            addr_part, auth_part = line.split('|', 1)
            ip_str, port_str = addr_part.split(':', 1)
            user_str, pwd_str = auth_part.split(':', 1)
            
            ip_str = ip_str.strip()
            port_str = port_str.strip()
            user_str = user_str.strip()
            pwd_str = pwd_str.strip()

            if port_str.isdigit():
                ipaddress.ip_address(ip_str) # Validate IP
                return {'ip': ip_str, 'port': port_str, 'user': user_str, 'pwd': pwd_str}
        except ValueError: # Handles errors from split, strip, isdigit, or ip_address
            pass # Malformed or invalid IP/port, try other formats

    # Try Format 2: CSV with IP in 2nd column, Port in 3rd (e.g., FOFA output)
    # Example: host,ip,port,...
    # User's KR.csv header: 主机,IP,端口,...
    if ',' in line: # Check if comma exists
        parts = [p.strip() for p in line.split(',')]
        
        # Handle FOFA-like CSV (IP in 2nd col, Port in 3rd col)
        if len(parts) >= 3:
            # Skip typical CSV header lines (case-insensitive check)
            # Check for user's specific header: 主机,IP,端口 (from KR.csv)
            if parts[0].lower() == '主机' and parts[1].lower() == 'ip' and parts[2].lower() == '端口':
                 return None
            # Generic check for headers like "some_host_col_name,ip,port,..." or "...,ip,端口,..."
            if parts[1].lower() == 'ip' and (parts[2].lower() == 'port' or parts[2].lower() == '端口'):
                 return None

            ip_str = parts[1]
            port_str = parts[2]

            if port_str.isdigit():
                try:
                    ipaddress.ip_address(ip_str) # Validate IP format
                    return {'ip': ip_str, 'port': port_str, 'user': None, 'pwd': None}
                except ValueError:
                    # This might not be the FOFA format, or IP is invalid.
                    # It could be the simpler "ip,port" format if line.count(',') == 1.
                    pass 
        
        # Try Format 3: ip,port (exactly one comma, resulting in 2 parts)
        if line.count(',') == 1: 
            try:
                ip_str_simple, port_str_simple = [p.strip() for p in line.split(',', 1)]
                if port_str_simple.isdigit():
                    ipaddress.ip_address(ip_str_simple) # Validate IP
                    return {'ip': ip_str_simple, 'port': port_str_simple, 'user': None, 'pwd': None}
            except ValueError:
                pass # Malformed or not ip,port

    # Try Format 4: ip:port (no auth, no comma, no pipe)
    if ':' in line and '|' not in line and ',' not in line:
        try:
            ip_str, port_str = [p.strip() for p in line.split(':', 1)]
            # Ensure not misinterpreting user:pwd@ip as ip and port is digit
            if '@' not in ip_str and port_str.isdigit():
                ipaddress.ip_address(ip_str) # Validate IP
                return {'ip': ip_str, 'port': port_str, 'user': None, 'pwd': None}
        except ValueError:
            pass # Malformed or not ip:port

    return None # If none of the formats match

def format_proxy(proxy):
    if proxy['user'] and proxy['pwd']:
        return f"socks5://{proxy['user']}:{proxy['pwd']}@{proxy['ip']}:{proxy['port']}"
    else:
        return f"socks5://{proxy['ip']}:{proxy['port']}"

def test_proxy(proxy, test_url, timeout):
    ip, port = proxy['ip'], proxy['port']
    user, pwd = proxy['user'], proxy['pwd']

    if user and pwd:
        proxy_specifier = f"socks5://{user}:{pwd}@{ip}:{port}"
    else:
        proxy_specifier = f"socks5://{ip}:{port}"

    cmd = [
        "curl", "--silent", "--output", os.devnull, "--write-out", "%{http_code}",
        "--connect-timeout", str(timeout), "--max-time", str(timeout),
        "-x", proxy_specifier, test_url
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        code = result.stdout.strip()
        return code.isdigit() and 200 <= int(code) < 400
    except subprocess.TimeoutExpired:
        return False # Curl command timed out
    except Exception:
        return False

def test_proxy_with_credentials(proxy, username, password, test_url, timeout):
    """使用指定用户名和密码测试SOCKS5代理"""
    ip, port = proxy['ip'], proxy['port']
    proxy_specifier = f"socks5://{username}:{password}@{ip}:{port}"

    cmd = [
        "curl", "--silent", "--output", os.devnull, "--write-out", "%{http_code}",
        "--connect-timeout", str(timeout), "--max-time", str(timeout),
        "-x", proxy_specifier, test_url
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, 
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        code = result.stdout.strip()
        return code.isdigit() and 200 <= int(code) < 400
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def save_working_proxies(ok_list, input_filename):
    """保存可用代理到指定文件"""
    # 获取输入文件的目录
    input_dir = os.path.dirname(os.path.abspath(input_filename))
    # 从输入文件名生成输出文件名
    base_name = os.path.basename(input_filename)
    name_without_ext, _ = os.path.splitext(base_name)
    # 在同一目录下创建输出文件，并固定扩展名为 .txt
    output_filename = os.path.join(input_dir, f"{name_without_ext}_valid.txt")
    
    try:
        with open(output_filename, "w", encoding="utf-8") as f_out:
            for p_ok in ok_list:
                f_out.write(format_proxy(p_ok) + "\n")
        print(f"\n可用代理已保存到 {output_filename}")
    except IOError:
        print(f"\n错误: 无法写入可用代理文件到 {output_filename}")

def save_config_to_script(config_dict):
    """将当前配置保存回脚本文件本身"""
    script_path = os.path.abspath(__file__)
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # 更新 DEFAULT_TEST_URL
        new_url_val = config_dict['test_url']
        content = re.sub(r"^(DEFAULT_TEST_URL\s*=\s*).*$", f"DEFAULT_TEST_URL = \"{new_url_val}\"", content, flags=re.MULTILINE)
        
        # 更新 DEFAULT_CONCURRENCY
        new_concurrency_val = config_dict['concurrency']
        content = re.sub(r"^(DEFAULT_CONCURRENCY\s*=\s*).*$", f"DEFAULT_CONCURRENCY = {new_concurrency_val}", content, flags=re.MULTILINE)

        # 更新 DEFAULT_TIMEOUT
        # 使用 config_dict 中的 'timeout'键来获取正确的值
        timeout_val_from_dict = config_dict['timeout'] 
        content = re.sub(r"^(DEFAULT_TIMEOUT\s*=\s*)\d+.*$", f"DEFAULT_TIMEOUT = {timeout_val_from_dict}", content, flags=re.MULTILINE)

        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(content)
        # print("配置已更新并保存到脚本中。") # 可选的确认信息
        return True
    except Exception as e:
        with print_lock:
            print(f"\n错误：无法将配置保存回脚本: {e}")
        return False

def main(proxy_file_arg):
    print("SOCKS5代理批量检测工具")
    
    # 配置直接从脚本顶部的全局常量初始化
    # 这些全局常量会在 save_config_to_script 中被修改
    config = {
        'test_url': DEFAULT_TEST_URL,
        'concurrency': DEFAULT_CONCURRENCY,
        'timeout': DEFAULT_TIMEOUT
    }
    
    # 全局变量用于标记中断状态
    global interrupted
    interrupted = False

    # 定义信号处理函数
    def signal_handler(sig, frame):
        global interrupted
        if interrupted:  # 如果已经中断过一次，第二次按Ctrl+C则立即退出
            print("\n强制退出程序！")
            sys.exit(1)
        interrupted = True
        print("\n\n检测被用户中断！正在停止测试，请稍候...")
        print("(再次按Ctrl+C将强制退出程序)")

    # 设置信号处理
    original_sigint_handler = signal.getsignal(signal.SIGINT)

    while True:
        # 在每次循环开始重置中断标志
        interrupted = False
        
        print("\n当前设置:")
        print(f"  测试网址: {config['test_url']}")
        print(f"  并发数: {config['concurrency']}")
        print(f"  超时时间 (秒): {config['timeout']}")
        print("\n菜单选项:")
        print("  1. 开始socks5检测")
        print("  2. 修改并发数")
        print("  3. 修改测试网址")
        print("  4. 修改超时时间")
        print("  0. 退出")

        choice = input("请输入选项: ").strip()

        if choice == '1':
            file_to_use_for_testing = proxy_file_arg # 优先使用命令行参数

            if file_to_use_for_testing is None:
                # 如果没有通过命令行提供文件，则提示用户输入
                file_to_use_for_testing = input("请输入代理文件路径: ").strip()
                if not file_to_use_for_testing: # 用户没有输入任何内容
                    print("错误: 未输入代理文件路径。操作已取消。")
                    continue # 返回主菜单
            else:
                # 如果通过命令行提供了文件，打印提示信息
                print(f"信息: 将使用命令行提供的代理文件 '{file_to_use_for_testing}' 进行检测。")

            # 检查文件是否存在 (无论是来自命令行还是用户输入)
            if not os.path.isfile(file_to_use_for_testing):
                print(f"错误: 代理文件 '{file_to_use_for_testing}' 不存在或路径无效。")
                # 如果文件来自命令行且无效，用户需要用正确的参数重启脚本
                # 如果文件来自用户输入且无效，下次选择选项1时会再次提示
                continue # 返回主菜单

            # 使用确定好的文件路径 (file_to_use_for_testing) 进行后续操作
            with open(file_to_use_for_testing, encoding='utf-8') as f:
                lines = f.readlines()
            proxies = [parse_proxy(line) for line in lines]
            proxies = [p for p in proxies if p]
            total = len(proxies)
            if total == 0:
                print("没有从文件中解析到有效代理。")
                continue

            print(f"共{total}个代理，使用测试网址 {config['test_url']}, 并发数 {config['concurrency']}, 超时 {config['timeout']}s.")
            print("开始检测...")

            ok_list = []
            done_count = 0
            start_time = time()

            def task(proxy_item):
                nonlocal done_count
                ip_port = f"{proxy_item['ip']}:{proxy_item['port']}"
                with print_lock:
                    print(f"\n正在测试代理: {ip_port}") # 每个新代理测试开始时换行

                # 1. 明确地先测试无密码访问
                current_status_line = f"  测试无密码访问...{' '*60}" # 预留足够空间
                with print_lock:
                    print(f"\r{current_status_line}", end="")
                
                # 使用一个不包含user/pwd的proxy_item副本进行无密码测试
                no_auth_proxy_item = proxy_item.copy()
                no_auth_proxy_item['user'] = None
                no_auth_proxy_item['pwd'] = None
                
                is_ok = test_proxy(no_auth_proxy_item, config['test_url'], config['timeout'])
                if is_ok:
                    with print_lock:
                        print(LINE_CLEAR_SEQUENCE, end="") # 清除 "测试无密码访问..." 行
                        done_count += 1
                        # 格式化输出时，确保使用原始的proxy_item，如果它本身就无密码
                        # 或者使用修改后的no_auth_proxy_item，如果原始的有密码但无密码测试成功
                        print(f"[{done_count}/{total}] {format_proxy(no_auth_proxy_item)} - 无密码可用 \033[32m✅\033[0m")
                    return no_auth_proxy_item # 返回认证成功的代理信息
                
                # 无密码访问失败
                with print_lock:
                    print(LINE_CLEAR_SEQUENCE, end="") # 清除 "测试无密码访问..." 行
                    print(f"  无密码访问失败，开始测试弱密码组合...")
                    
                    actual_weak_combinations_to_test = len(USERNAME_LIST) * len(PASSWORD_LIST)
                    if actual_weak_combinations_to_test < 0: actual_weak_combinations_to_test = 0 
                    print(f"    共需测试 {actual_weak_combinations_to_test} 种弱密码凭证组合")

                tested_combinations = set() 
                weak_creds_tested_count = 0

                # 2. 优先测试相同索引位置的凭证组合 (从更新后的USERNAME_LIST和PASSWORD_LIST)
                with print_lock:
                    print(f"    优先测试相同索引位置的凭证组合...")
                min_len = min(len(USERNAME_LIST), len(PASSWORD_LIST))
                for i in range(min_len):
                    if interrupted: return None
                    
                    username = USERNAME_LIST[i]
                    password = PASSWORD_LIST[i]
                        
                    key = f"{username}:{password}"
                    if key in tested_combinations: continue 
                    tested_combinations.add(key)
                    weak_creds_tested_count += 1
                    
                    status_msg = f"    L1 [{ip_port}] 测试 ({weak_creds_tested_count}/{actual_weak_combinations_to_test}): {username}:{password}"
                    with print_lock:
                        print(f"\r{status_msg:<95}", end="")
                    
                    is_ok = test_proxy_with_credentials(proxy_item, username, password, config['test_url'], config['timeout'])
                    if is_ok:
                        proxy_result = proxy_item.copy()
                        proxy_result.update({'user': username, 'pwd': password})
                        with print_lock:
                            print(LINE_CLEAR_SEQUENCE, end="")
                            done_count += 1
                            print(f"[{done_count}/{total}] {format_proxy(proxy_result)} - 可用 \033[32m✅\033[0m")
                        return proxy_result
                
                # 3. 测试其他所有组合 (从更新后的USERNAME_LIST和PASSWORD_LIST)
                with print_lock:
                    print(LINE_CLEAR_SEQUENCE, end="") 
                    print(f"    测试其他凭证组合...")
                for username in USERNAME_LIST:
                    if interrupted: return None
                    for password in PASSWORD_LIST:
                        if interrupted: return None

                        key = f"{username}:{password}"
                        if key in tested_combinations: continue
                        tested_combinations.add(key)
                        weak_creds_tested_count += 1
                        
                        status_msg = f"    L2 [{ip_port}] 测试 ({weak_creds_tested_count}/{actual_weak_combinations_to_test}): {username}:{password}"
                        with print_lock:
                            print(f"\r{status_msg:<95}", end="")
                        
                        is_ok = test_proxy_with_credentials(proxy_item, username, password, config['test_url'], config['timeout'])
                        if is_ok:
                            proxy_result = proxy_item.copy()
                            proxy_result.update({'user': username, 'pwd': password})
                            with print_lock:
                                print(LINE_CLEAR_SEQUENCE, end="")
                                done_count += 1
                                print(f"[{done_count}/{total}] {format_proxy(proxy_result)} - 可用 \033[32m✅\033[0m")
                            return proxy_result
                
                with print_lock:
                    print(LINE_CLEAR_SEQUENCE, end="") 
                    done_count += 1
                    print(f"[{done_count}/{total}] {format_proxy(proxy_item)} - 不可用")
                return None

            signal.signal(signal.SIGINT, signal_handler)

            try:
                with print_lock:
                     print(f"\n开始测试 {total} 个代理，使用 {config['concurrency']} 线程并行处理")

                with concurrent.futures.ThreadPoolExecutor(max_workers=config['concurrency']) as executor:
                    futures = [executor.submit(task, p) for p in proxies]
                    
                    for fut in concurrent.futures.as_completed(futures):
                        try:
                            if interrupted:
                                for f_cancel in futures:
                                    if not f_cancel.done():
                                        f_cancel.cancel()
                                break
                                
                            res = fut.result()
                            if res:
                                ok_list.append(res)
                                
                        except Exception as e:
                            with print_lock: # 确保错误信息也不会交错
                                print(f"\n任务执行出错: {str(e)}")

                # 如果是正常完成的（非中断）
                if not interrupted:
                    print(f"\n检测完成, 可用代理{len(ok_list)}个, 用时{int(time()-start_time)}秒")
                    if ok_list:
                        save_working_proxies(ok_list, file_to_use_for_testing)

            except Exception as e:
                print(f"\n发生错误: {e}")
                
            finally:
                # 恢复原始信号处理
                signal.signal(signal.SIGINT, original_sigint_handler)
                
                # 如果是因为中断而结束的
                if interrupted:
                    print(f"已测试: {done_count}/{total}, 找到可用代理: {len(ok_list)}个, 用时{int(time()-start_time)}秒")
                    
                    # 保存已测试成功的代理
                    if ok_list:
                        save_working_proxies(ok_list, file_to_use_for_testing)
                    
                    # 符合需求的提示：按Enter继续或Ctrl+C退出
                    try:
                        print("\n按Enter继续或Ctrl+C退出...")
                        input()  # 等待用户按Enter
                        # 用户按了Enter，继续主循环
                    except KeyboardInterrupt:
                        print("\n退出程序。")
                        sys.exit(0)

        elif choice == '2':  # 修改并发数
            new_concurrency_str = input(f"请输入新的并发数 (当前: {config['concurrency']}): ").strip()
            if new_concurrency_str:
                try:
                    new_concurrency = int(new_concurrency_str)
                    if new_concurrency > 0:
                        # 添加防止并发数过高导致系统报错的保护机制
                        if new_concurrency > 100:
                            print("警告: 并发数过高可能导致系统错误。")
                            confirm = input("是否确认使用高并发数? (y/n): ").strip().lower()
                            if confirm != 'y':
                                print("已取消修改并发数。")
                                continue
                        
                        config['concurrency'] = new_concurrency
                        if save_config_to_script(config):
                            print("并发数已更新。")
                        else:
                            print("并发数更新，但保存到脚本失败。")
                    else:
                        print("并发数必须为正整数。")
                except ValueError:
                    print("无效输入，并发数需为整数。")
            else:
                print("输入为空, 未作修改。")
                
        elif choice == '3':  # 修改测试网址
            new_url = input(f"请输入新的测试网址 (当前: {config['test_url']}): ").strip()
            if new_url:
                config['test_url'] = new_url
                if save_config_to_script(config):
                    print("测试网址已更新。")
                else:
                    print("测试网址更新，但保存到脚本失败。")
            else:
                print("输入为空, 未作修改。")
                
        elif choice == '4':  # 修改超时时间
            new_timeout_str = input(f"请输入新的超时时间 (秒) (当前: {config['timeout']}): ").strip()
            if new_timeout_str:
                try:
                    new_timeout = int(new_timeout_str)
                    if new_timeout > 0:
                        config['timeout'] = new_timeout
                        if save_config_to_script(config):
                            print("超时时间已更新。")
                        else:
                            print("超时时间更新，但保存到脚本失败。")
                    else:
                        print("超时时间必须为正整数。")
                except ValueError:
                    print("无效输入，超时时间需为整数。")
            else:
                print("输入为空, 未作修改。")
        elif choice == '0':
            print("退出程序。")
            sys.exit(0)
            
        else:
            print("无效选项，请重新输入。")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test SOCKS5 proxies from a file. Proxies can be 'host:port' or 'socks5://user:pass@host:port'.",
        epilog="Example: python socks5_proxy_tester.py proxies.txt"
    )
    parser.add_argument(
        "proxy_file",
        nargs='?', # 使参数变为可选
        default=None, # 如果未提供参数，则默认为 None
        help="Path to the file containing proxy list (one proxy per line). Lines starting with '#' are ignored as comments. This argument is optional; if not provided, you will be prompted."
    )
    
    args = parser.parse_args()
    
    # Pre-check if curl is available and working
    try:
        curl_check_proc = subprocess.run(["curl", "--version"], capture_output=True, text=True, check=True)
        print(f"Using curl version: {curl_check_proc.stdout.splitlines()[0]}")
    except FileNotFoundError:
        print("错误: curl 命令未找到或无法执行。请确保 curl 已安装并存在于系统 PATH 中。")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"ERROR: curl command is installed but not working correctly. Output:\n{e.stderr}")
        sys.exit(1)

    main(args.proxy_file)

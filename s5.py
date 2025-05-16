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

# 直接在脚本中定义配置，不再使用外部配置文件
DEFAULT_TEST_URL = "https://api.ipify.org"
DEFAULT_CONCURRENCY = 10
DEFAULT_TIMEOUT = 5

# 弱密码测试用的用户名和密码列表
USERNAME_LIST = ['admin', '123456', '123', 'socks5', '12345678', '111']
PASSWORD_LIST = ['admin', '123456', '123', 'socks5', '12345678', '111']

def parse_proxy(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    if '|' in line:
        addr, auth = line.split('|', 1)
        if ':' in addr:
            ip, port = addr.split(':', 1)
            if ':' in auth:
                user, pwd = auth.split(':', 1)
                return {'ip': ip, 'port': port, 'user': user, 'pwd': pwd}
    elif ',' in line and line.count(',') == 1:
        ip, port = line.split(',', 1)
        return {'ip': ip.strip(), 'port': port.strip(), 'user': None, 'pwd': None}
    elif ':' in line:
        ip, port = line.split(':', 1)
        return {'ip': ip, 'port': port, 'user': None, 'pwd': None}
    return None

def format_proxy(proxy):
    if proxy['user'] and proxy['pwd']:
        return f"socks5://{proxy['user']}:{proxy['pwd']}@{proxy['ip']}:{proxy['port']}"
    else:
        return f"socks5://{proxy['ip']}:{proxy['port']}"

def test_proxy(proxy, test_url, timeout):
    """无密码测试SOCKS5代理"""
    ip, port = proxy['ip'], proxy['port']
    user, pwd = proxy['user'], proxy['pwd']

    if user and pwd:
        proxy_specifier = f"socks5://{user}:{pwd}@{ip}:{port}"
    else:
        proxy_specifier = f"socks5://{ip}:{port}"

    cmd = [
        "curl", 
        "--connect-timeout", str(timeout), 
        "--max-time", str(timeout),
        "-x", proxy_specifier, 
        test_url
    ]
    try:
        # 不使用--silent和--output os.devnull，让curl返回实际内容
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, 
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        response_content = result.stdout.strip()
        
        # 检查响应内容是否非空，表示代理可用
        return result.returncode == 0 and len(response_content) > 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def test_proxy_with_credentials(proxy, username, password, test_url, timeout):
    """
    使用用户名和密码测试SOCKS5代理
    """
    ip, port = proxy['ip'], proxy['port']
    proxy_specifier = f"socks5://{username}:{password}@{ip}:{port}"

    cmd = [
        "curl", 
        "--connect-timeout", str(timeout), 
        "--max-time", str(timeout),
        "-x", proxy_specifier, 
        test_url
    ]
    try:
        # 不使用--silent和--output os.devnull，让curl返回实际内容
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2, 
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        response_content = result.stdout.strip()
        
        # 检查响应内容是否非空，表示代理可用
        is_valid = result.returncode == 0 and len(response_content) > 0
        
        # 调试信息：如果失败了，但返回码是0，打印响应内容帮助诊断
        if not is_valid and result.returncode == 0:
            print(f"\n调试信息 - 返回码: {result.returncode}, 内容: '{response_content}'")
        
        return is_valid
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        # 提供更详细的错误信息
        print(f"\n调试信息 - 测试失败: {str(e)}")
        return False

def save_working_proxies(ok_list, input_filename):
    """保存可用代理到指定文件"""
    # 获取输入文件的目录
    input_dir = os.path.dirname(os.path.abspath(input_filename))
    # 从输入文件名生成输出文件名
    base_name = os.path.basename(input_filename)
    name_without_ext, ext = os.path.splitext(base_name)
    # 在同一目录下创建输出文件
    output_filename = os.path.join(input_dir, f"{name_without_ext}_valid{ext}")
    
    try:
        with open(output_filename, "w", encoding="utf-8") as f_out:
            for p_ok in ok_list:
                f_out.write(format_proxy(p_ok) + "\n")
        print(f"\n可用代理已保存到 {output_filename}")
    except IOError:
        print(f"\n错误: 无法写入可用代理文件到 {output_filename}")

def weak_password_test(file_to_use_for_testing, config, signal_handler, original_sigint_handler):
    """弱密码批量测试函数"""
    global interrupted
    interrupted = False
    
    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        with open(file_to_use_for_testing, encoding='utf-8') as f:
            lines = f.readlines()
        proxies = [parse_proxy(line) for line in lines]
        proxies = [p for p in proxies if p]
        total = len(proxies)
        if total == 0:
            print("没有从文件中解析到有效代理。")
            return
            
        print(f"共{total}个代理，使用测试网址 {config['test_url']}, 并发数 {config['concurrency']}, 超时 {config['timeout']}s.")
        print("开始弱密码检测...")
        
        # 扩展用户名和密码列表，增加常见组合
        if 'admin' not in USERNAME_LIST:
            USERNAME_LIST.append('admin')
        if 'admin' not in PASSWORD_LIST:
            PASSWORD_LIST.append('admin')
        
        ok_list = []
        done_count = 0
        start_time = time()

        # 对每个代理进行弱密码测试
        for proxy in proxies:
            if interrupted:
                break
                
            print(f"\n测试代理 {proxy['ip']}:{proxy['port']}")
            found_valid_creds = False
            
            # 计算测试凭证总数
            same_index_count = min(len(USERNAME_LIST), len(PASSWORD_LIST))
            # 计算不重复的实际组合总数
            unique_combinations = len(USERNAME_LIST) * len(PASSWORD_LIST) - len(set(USERNAME_LIST) & set(PASSWORD_LIST))
            total_combinations = unique_combinations + len(set(USERNAME_LIST) & set(PASSWORD_LIST))
            creds_count = 0
            
            # 创建已测试的凭证集合，避免重复测试
            tested_creds = set()
            
            # 先测试用户名密码相同的组合 (如admin:admin, root:root)
            print("\n先测试用户名密码相同的组合...")
            for username in USERNAME_LIST:
                if username in PASSWORD_LIST and username not in tested_creds:
                    if interrupted or found_valid_creds:
                        break
                    
                    password = username
                    cred_key = f"{username}:{password}"
                    tested_creds.add(cred_key)
                    
                    creds_count += 1
                    print(f"\r尝试凭证 [{creds_count}/{total_combinations}] {username}:{password}\033[K", end="")
                    
                    is_ok = test_proxy_with_credentials(proxy, username, password, config['test_url'], config['timeout'])
                    if is_ok:
                        # 设置可用凭证
                        proxy['user'] = username
                        proxy['pwd'] = password
                        found_valid_creds = True
                        ok_list.append(proxy.copy())  # 使用copy避免后续修改影响已保存的数据
                        print(f"\r尝试凭证 [{creds_count}/{total_combinations}] {username}:{password} - 可用 \033[32m√\033[0m\033[K")
                        break
            
            # 然后测试所有其他组合（避免重复）
            if not found_valid_creds and not interrupted:
                print("\n测试所有其他账号密码组合...")
                for username in USERNAME_LIST:
                    if interrupted or found_valid_creds:
                        break
                        
                    for password in PASSWORD_LIST:
                        if interrupted:
                            break
                        
                        # 跳过已测试的凭证
                        cred_key = f"{username}:{password}"
                        if cred_key in tested_creds:
                            continue
                            
                        tested_creds.add(cred_key)
                        creds_count += 1
                        
                        print(f"\r尝试凭证 [{creds_count}/{total_combinations}] {username}:{password}\033[K", end="")
                        
                        is_ok = test_proxy_with_credentials(proxy, username, password, config['test_url'], config['timeout'])
                        if is_ok:
                            # 设置可用凭证
                            proxy['user'] = username
                            proxy['pwd'] = password
                            found_valid_creds = True
                            ok_list.append(proxy.copy())  # 使用copy避免后续修改影响已保存的数据
                            print(f"\r尝试凭证 [{creds_count}/{total_combinations}] {username}:{password} - 可用 \033[32m√\033[0m\033[K")
                            break
            
            if not found_valid_creds and not interrupted:
                print(f"\r尝试所有凭证 [{creds_count}/{total_combinations}] - 未找到可用凭证\033[K")
            
            done_count += 1
            print(f"\n进度: [{done_count}/{total}] 代理")
        
        # 处理结果
        if not interrupted:
            print(f"\n检测完成, 可用代理{len(ok_list)}个, 用时{int(time()-start_time)}秒")
            if ok_list:
                save_working_proxies(ok_list, file_to_use_for_testing)
        else:
            print(f"已测试: {done_count}/{total}, 找到可用代理: {len(ok_list)}个, 用时{int(time()-start_time)}秒")
            if ok_list:
                save_working_proxies(ok_list, file_to_use_for_testing)
                
    except Exception as e:
        print(f"\n发生错误: {e}")
    
    finally:
        # 恢复原始信号处理
        signal.signal(signal.SIGINT, original_sigint_handler)
        
        # 如果是因为中断而结束的
        if interrupted:
            # 询问是否返回主菜单或退出程序
            while True:
                try:
                    choice = input("\n是否返回主菜单? (y/n): ").strip().lower()
                    if choice == 'n':
                        print("退出程序。")
                        sys.exit(0)
                    elif choice == 'y':
                        break
                    else:
                        print("请输入 y 或 n")
                except KeyboardInterrupt:
                    print("\n退出程序。")
                    sys.exit(0)

def main(proxy_file_arg):
    print("SOCKS5代理批量检测工具")
    
    # 使用内存中的配置，不再从文件加载
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
        print("  1. 开始s5无密码检测")
        print("  2. 开始s5弱密码检测")
        print("  3. 修改测试网址")
        print("  4. 修改并发数")
        print("  5. 修改超时时间")
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

            print(f"共{total}个代理，使用测试网址 {config['test_url']}, 并发数 {config['concurrency']}, 超时 {config['timeout']}s。")
            print("开始检测...")

            ok_list = []
            done_count = 0
            start_time = time()

            def task(proxy_item):
                nonlocal done_count
                # 检查是否已中断
                if interrupted:
                    return None
                    
                is_ok = test_proxy(proxy_item, config['test_url'], config['timeout'])
                done_count += 1
                status = "可用" if is_ok else "不可用"
                
                # 添加绿色√标记
                if is_ok:
                    print(f"[{done_count}/{total}] {format_proxy(proxy_item)} - {status} \033[32m√\033[0m")
                else:
                    print(f"[{done_count}/{total}] {format_proxy(proxy_item)} - {status}")
                
                return proxy_item if is_ok else None

            # 安装信号处理器
            signal.signal(signal.SIGINT, signal_handler)

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=config['concurrency']) as executor:
                    # 提交所有任务
                    futures = [executor.submit(task, p) for p in proxies]
                    
                    # 处理完成的任务
                    for fut in concurrent.futures.as_completed(futures):
                        try:
                            # 检查是否中断
                            if interrupted:
                                # 取消所有未完成的任务
                                for f in futures:
                                    if not f.done():
                                        f.cancel()
                                break
                                
                            res = fut.result()
                            if res:
                                ok_list.append(res)
                        except Exception:
                            # 忽略任务执行中的异常
                            pass

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
                    
                    # 询问是否返回主菜单或退出程序
                    while True:
                        try:
                            choice = input("\n是否返回主菜单? (y/n): ").strip().lower()
                            if choice == 'n':
                                print("退出程序。")
                                sys.exit(0)
                            elif choice == 'y':
                                break
                            else:
                                print("请输入 y 或 n")
                        except KeyboardInterrupt:
                            print("\n退出程序。")
                            sys.exit(0)

        elif choice == '2':
            # 弱密码检测功能
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
                continue # 返回主菜单
                
            # 开始弱密码测试
            weak_password_test(file_to_use_for_testing, config, signal_handler, original_sigint_handler)

        elif choice == '3':
            new_url = input(f"请输入新的测试网址 (当前: {config['test_url']}): ").strip()
            if new_url:
                config['test_url'] = new_url
                print("测试网址已更新。")
            else:
                print("输入为空, 未作修改。")
        elif choice == '4':
            new_concurrency_str = input(f"请输入新的并发数 (当前: {config['concurrency']}): ").strip()
            if new_concurrency_str:
                try:
                    new_concurrency = int(new_concurrency_str)
                    if new_concurrency > 0:
                        config['concurrency'] = new_concurrency
                        print("并发数已更新。")
                    else:
                        print("并发数必须为正整数。")
                except ValueError:
                    print("无效输入，并发数需为整数。")
            else:
                print("输入为空, 未作修改。")
        elif choice == '5':
            new_timeout_str = input(f"请输入新的超时时间 (秒) (当前: {config['timeout']}): ").strip()
            if new_timeout_str:
                try:
                    new_timeout = int(new_timeout_str)
                    if new_timeout > 0:
                        config['timeout'] = new_timeout
                        print("超时时间已更新。")
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

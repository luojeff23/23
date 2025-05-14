import asyncio
import aiohttp
import os
import sys
import time
from typing import List, Dict, Any, Tuple

# 初始配置项
CONFIG = {
    "timeout": 5,  # 请求超时时间（秒）
    "concurrency": 30,  # 并发请求数
    "output_file": "xui-success.txt",  # 结果输出文件
    "input_file": "xui.txt",  # 输入的IP:端口文件
    "show_progress": True,  # 显示进度
}

# X-UI面板的特征标记
PANEL_FEATURES = [
    # XUI标记
    '<title>登录</title>',
    'anticon-user',
    'anticon-lock',
    # 3XUI标记
    '<section class="login ant-layout"',
    'ant-input-affix-wrapper',
]

async def check_with_protocol(session: aiohttp.ClientSession, ip_port: str, protocol: str) -> Dict[str, Any]:
    """使用指定协议检查IP:端口"""
    url = f"{protocol}://{ip_port}/"
    try:
        # 为每个请求单独设置超时
        timeout = aiohttp.ClientTimeout(total=CONFIG["timeout"])
        async with session.get(url, timeout=timeout, ssl=False) as response:
            try:
                data = await response.text()
                
                # 检查是否为面板
                if any(feature in data for feature in PANEL_FEATURES):
                    panel_type = "3X-UI" if '<section class="login ant-layout"' in data else "X-UI"
                    return {
                        "ipPort": ip_port,
                        "success": True,
                        "protocol": protocol,
                        "statusCode": response.status,
                        "panelType": panel_type
                    }
                else:
                    return {
                        "ipPort": ip_port,
                        "success": False,
                        "protocol": protocol,
                        "statusCode": response.status,
                        "error": "Not a panel"
                    }
            except Exception as e:
                return {
                    "ipPort": ip_port,
                    "success": False,
                    "protocol": protocol,
                    "error": f"Failed to decode response: {str(e)}"
                }
    except asyncio.TimeoutError:
        return {
            "ipPort": ip_port,
            "success": False,
            "protocol": protocol,
            "error": "Connection timeout"
        }
    except Exception as e:
        return {
            "ipPort": ip_port,
            "success": False,
            "protocol": protocol,
            "error": str(e)
        }

async def check_ip_port(session: aiohttp.ClientSession, ip_port: str) -> Dict[str, Any]:
    """检测单个IP:端口"""
    # 先尝试HTTPS
    result = await check_with_protocol(session, ip_port, "https")
    if result["success"]:
        return result
    
    # 如果HTTPS失败，尝试HTTP
    return await check_with_protocol(session, ip_port, "http")

async def batch_check(ip_list: List[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """批量检测IP:端口"""
    results = []
    success_results = []
    
    try:
        # 限制并发连接数
        connector = aiohttp.TCPConnector(limit=CONFIG["concurrency"], ssl=False)
        # 设置客户端会话的总超时，而不是单个请求的超时
        timeout = aiohttp.ClientTimeout(total=None)  # 不设置总超时
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            # 将IP列表分成批次处理，避免一次创建太多任务
            batch_size = 100  # 每批处理100个IP
            total_processed = 0
            total = len(ip_list)
            
            for i in range(0, total, batch_size):
                batch = ip_list[i:i+batch_size]
                # 创建这批IP的任务
                tasks = []
                for ip_port in batch:
                    task = asyncio.create_task(check_ip_port(session, ip_port))
                    tasks.append(task)
                
                # 等待所有任务完成
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # 处理结果
                for result in batch_results:
                    if isinstance(result, Exception):
                        print(f"任务异常: {str(result)}")
                        continue
                    
                    results.append(result)
                    if result["success"]:
                        success_results.append(result)
                
                # 更新进度
                total_processed += len(batch)
                if CONFIG["show_progress"]:
                    progress_percent = total_processed / total * 100
                    print(f"进度: {total_processed}/{total} ({progress_percent:.1f}%), 成功: {len(success_results)}    ", end="\r")
            
            # 完成后的进度显示
            if CONFIG["show_progress"]:
                print(f"\n检测完成! 进度: {total}/{total} (100%), 成功: {len(success_results)}    ")
    
    except Exception as e:
        print(f"批量检查过程中发生错误: {str(e)}")
    
    return results, success_results

def read_ip_list(filepath: str) -> List[str]:
    """读取IP:端口列表"""
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"读取文件失败: {e}")
        return []

def save_results(success_results: List[Dict[str, Any]]) -> None:
    """保存结果到文件"""
    try:
        content = "\n".join([f"{r['protocol']}://{r['ipPort']}/ ({r['panelType']})" for r in success_results])
        
        with open(CONFIG["output_file"], "w", encoding="utf-8") as file:
            file.write(content)
        
        print(f"成功结果已保存到 {CONFIG['output_file']}")
    except Exception as e:
        print(f"保存结果时出错: {str(e)}")

def show_config_ui():
    """显示配置界面"""
    print("\n===== X-UI 面板检测工具 - 配置 =====")
    
    # 显示当前配置
    print(f"\n当前配置:")
    print(f"1. 输入文件: {CONFIG['input_file']}")
    print(f"2. 输出文件: {CONFIG['output_file']}")
    print(f"3. 并发请求数: {CONFIG['concurrency']} (建议值: 30-100)")
    print(f"4. 请求超时(秒): {CONFIG['timeout']} (建议值: 5-10)")
    
    print("\n要修改配置请输入选项编号, 直接回车开始运行:")
    
    while True:
        choice = input("> ").strip()
        
        if choice == "":
            # 用户直接按回车，使用当前配置
            break
        
        try:
            choice_num = int(choice)
            
            if choice_num == 1:
                value = input("输入文件路径: ").strip()
                if value:
                    CONFIG["input_file"] = value
            elif choice_num == 2:
                value = input("输出文件路径: ").strip()
                if value:
                    CONFIG["output_file"] = value
            elif choice_num == 3:
                value = input("并发请求数 (建议 10-100): ").strip()
                if value:
                    try:
                        CONFIG["concurrency"] = int(value)
                    except ValueError:
                        print("请输入有效的数字!")
            elif choice_num == 4:
                value = input("请求超时秒数 (建议 3-10): ").strip()
                if value:
                    try:
                        CONFIG["timeout"] = int(value)
                    except ValueError:
                        print("请输入有效的数字!")
            else:
                print("无效的选项!")
                continue
            
            # 再次显示当前配置
            print(f"\n当前配置:")
            print(f"1. 输入文件: {CONFIG['input_file']}")
            print(f"2. 输出文件: {CONFIG['output_file']}")
            print(f"3. 并发请求数: {CONFIG['concurrency']}")
            print(f"4. 请求超时(秒): {CONFIG['timeout']}")
            print("\n要修改配置请输入选项编号, 直接回车开始运行:")
            
        except ValueError:
            print("请输入有效的选项号码!")

async def main():
    """主函数"""
    try:
        print("X-UI 面板检测工具 (Python版)")
        print("------------------------")
        
        # 显示配置界面
        show_config_ui()
        
        input_path = CONFIG["input_file"]
        if not os.path.exists(input_path):
            print(f"错误: 未找到输入文件 {input_path}")
            input("按回车键退出...")
            return
        
        start_time = time.time()
        ip_list = read_ip_list(input_path)
        if not ip_list:
            print("IP列表为空，请检查输入文件!")
            input("按回车键退出...")
            return
        
        print(f"从 {input_path} 读取了 {len(ip_list)} 个IP:端口")
        print(f"开始检测 (并发数: {CONFIG['concurrency']}, 超时: {CONFIG['timeout']}秒)...")
        print(f"测试可能需要几分钟时间，请耐心等待...")
        
        _, success_results = await batch_check(ip_list)
        
        elapsed_time = time.time() - start_time
        print(f"\n检测完成! 耗时: {elapsed_time:.2f} 秒")
        print(f"总共: {len(ip_list)}, 成功: {len(success_results)}")
        
        if success_results:
            print("\n成功列表 (前10个):")
            for r in success_results[:10]:
                print(f"{r['protocol']}://{r['ipPort']}/ ({r['panelType']})")
            
            if len(success_results) > 10:
                print(f"...以及另外 {len(success_results) - 10} 个结果")
            
            save_results(success_results)
        else:
            print("未找到可用的X-UI面板")
        
        input("\n按回车键退出...")
    
    except Exception as e:
        print(f"程序发生错误: {str(e)}")
        input("按回车键退出...")

if __name__ == "__main__":
    try:
        # 检查Python版本
        if sys.version_info < (3, 7):
            print("错误: 此脚本需要 Python 3.7 或更高版本")
            input("按回车键退出...")
            sys.exit(1)
        
        # 在Windows上设置事件循环策略
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        # 运行主程序
        asyncio.run(main())
    except Exception as e:
        print(f"启动程序时出错: {str(e)}")
        input("按回车键退出...")

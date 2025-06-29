import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress

# 目标URL列表
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

# 正则表达式支持 IPv4 和 IPv6（包括 :: 简写）
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b|\[([A-Fa-f0-9:]+)\]'

# 检查ip.txt文件是否存在,如果存在则删除它
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 用集合存储IP，自动去重
ip_set = set()

# 请求网页并提取IP
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"请求失败: {url} 错误信息: {e}")
        continue

    soup = BeautifulSoup(response.text, 'html.parser')

    # 自动提取所有可能包含IP的元素
    elements = soup.find_all(['tr', 'li', 'p', 'div'])

    for element in elements:
        element_text = element.get_text()

        # 匹配所有 IP（包括 IPv4、IPv6、带方括号的 IPv6）
        ip_matches = re.findall(ip_pattern, element_text)

        for ip in ip_matches:
            ip = ip.strip('[]')  # 去除方括号，方便后续处理
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    continue  # 过滤掉内网地址
                ip_set.add(ip_obj)
            except ValueError:
                continue  # 过滤掉非合法IP

# 写入文件
if ip_set:
    with open('ip.txt', 'w') as file:
        for ip in sorted(ip_set, key=lambda x: (x.version, str(x))):
            if ip.version == 6:
                file.write(f'[{ip}]\n')  # IPv6 加方括号
            else:
                file.write(f'{ip}\n')    # IPv4 直接写
    print(f'成功抓取 {len(ip_set)} 个唯一公网 IP 地址，已保存到 ip.txt 文件中。')
else:
    print('没有找到任何公网 IP 地址。')

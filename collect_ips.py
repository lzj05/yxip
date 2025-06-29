import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress  # 导入ipaddress模块

# 目标URL列表
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

# 正则表达式
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # IPv4 正则
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'  # IPv6 正则

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

        # 匹配IPv4
        ipv4_matches = re.findall(ipv4_pattern, element_text)
        for ip in ipv4_matches:
            try:
                ip_obj = ipaddress.ip_address(ip)  # 判断是否是合法IP
                ip_set.add(str(ip_obj))
            except ValueError:
                continue  # 非法IP跳过

        # 匹配IPv6
        ipv6_matches = re.findall(ipv6_pattern, element_text)
        for ip in ipv6_matches:
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_set.add(str(ip_obj))
            except ValueError:
                continue

# 写入文件
if ip_set:
    with open('ip.txt', 'w') as file:
        for ip in sorted(ip_set):
            file.write(ip + '\n')
    print(f'成功抓取 {len(ip_set)} 个唯一 IP 地址（IPv4 + IPv6），已保存到 ip.txt 文件中。')
else:
    print('没有找到任何 IP 地址。')

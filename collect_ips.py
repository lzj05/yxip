import requests
from bs4 import BeautifulSoup
import re
import os

# 目标URL列表
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

# 正则表达式：支持 IPv4 和 IPv6
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b|\[([A-Fa-f0-9:]+)\]'

# 不删除旧文件，追加写入
ip_set = set()

for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"请求失败: {url} 错误信息: {e}")
        continue

    soup = BeautifulSoup(response.text, 'html.parser')
    elements = soup.find_all(['tr', 'li', 'p', 'div'])

    for element in elements:
        element_text = element.get_text()
        ip_matches = re.findall(ip_pattern, element_text)

        for ip in ip_matches:
            ip = ip.strip('[]')
            ip_set.add(ip)

# 分类排序
ipv4_list = sorted([ip for ip in ip_set if ':' not in ip])  # IPv4 没有冒号
ipv6_list = sorted([ip for ip in ip_set if ':' in ip])      # IPv6 包含冒号

# 追加写入文件
if ip_set:
    with open('ip.txt', 'a') as file:  # 追加写入
        for ip in ipv4_list:
            file.write(f'{ip}\n')
        for ip in ipv6_list:
            file.write(f'[{ip}]\n')
    print(f'成功抓取 {len(ip_set)} 个 IP 地址，IPv4 已排在 IPv6 前面，已追加保存到 ip.txt 文件中。')
else:
    print('没有找到任何 IP 地址。')

import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress

urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

old_ips = []
old_ips_set = set()

# 先读取旧文件，保存顺序
if os.path.exists('ip.txt'):
    with open('ip.txt', 'r') as f:
        for line in f:
            ip = line.strip()
            if not ip:
                continue
            if ip.startswith('[') and ip.endswith(']'):
                ip = ip[1:-1]
            old_ips.append(ip)
            old_ips_set.add(ip)

new_ips_set = set()

# 抓取新IP
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
        text = element.get_text()

        for ip in re.findall(ipv4_pattern, text):
            try:
                ip_obj = ipaddress.ip_address(ip)
                new_ips_set.add(str(ip_obj))
            except ValueError:
                continue

        for ip in re.findall(ipv6_pattern, text):
            try:
                ip_obj = ipaddress.ip_address(ip)
                new_ips_set.add(str(ip_obj))
            except ValueError:
                continue

# 取旧文件列表和新抓取集合的交集，保持旧文件顺序
final_ips = [ip for ip in old_ips if ip in new_ips_set]

# 排序 IPv4 和 IPv6，IPv4排前，IPv6排后
ipv4_list = sorted([ip for ip in final_ips if ':' not in ip])
ipv6_list = sorted([ip for ip in final_ips if ':' in ip])

# 写回文件，IPv6加方括号
with open('ip.txt', 'w') as f:
    for ip in ipv4_list:
        f.write(f"{ip}\n")
    for ip in ipv6_list:
        f.write(f"[{ip}]\n")

print(f"共保存 {len(final_ips)} 个与新抓取IP匹配的旧IP，写回 ip.txt 文件。")

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

if os.path.exists('ip.txt'):
    os.remove('ip.txt')

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

        ipv4_matches = re.findall(ipv4_pattern, element_text)
        for ip in ipv4_matches:
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_set.add(str(ip_obj))
            except ValueError:
                continue

        ipv6_matches = re.findall(ipv6_pattern, element_text)
        for ip in ipv6_matches:
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_set.add(str(ip_obj))
            except ValueError:
                continue

if ip_set:
    with open('ip.txt', 'w') as file:
        for ip in sorted(ip_set):
            if ':' in ip:  # IPv6 地址包含冒号
                file.write(f'[{ip}]\n')
            else:
                file.write(f'{ip}\n')
    print(f'成功抓取 {len(ip_set)} 个唯一 IP 地址（IPv4 + IPv6），已保存到 ip.txt 文件中。')
else:
    print('没有找到任何 IP 地址。')

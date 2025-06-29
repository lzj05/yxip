import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress

urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz',
    'https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/#cloudflare'
]

ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

old_ips = []
old_ips_set = set()

# 读取旧文件（保持顺序）
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
site_ip_counts = {}

for url in urls:
    site_ips = set()
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"请求失败: {url} 错误信息: {e}")
        site_ip_counts[url] = 0
        continue

    soup = BeautifulSoup(response.text, 'html.parser')
    elements = soup.find_all(['tr', 'li', 'p', 'div'])

    for element in elements:
        text = element.get_text()

        for ip in re.findall(ipv4_pattern, text):
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_str = str(ip_obj)
                site_ips.add(ip_str)
            except ValueError:
                continue

        for ip in re.findall(ipv6_pattern, text):
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_str = str(ip_obj)
                site_ips.add(ip_str)
            except ValueError:
                continue

    site_ip_counts[url] = len(site_ips)
    new_ips_set.update(site_ips)

# 取旧文件和新抓取交集（保持旧文件顺序）
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

# 输出统计
print("每个网站抓取到的唯一 IP 数量：")
for site, count in site_ip_counts.items():
    print(f"  {site} ：{count} 个 IP")

print(f"\n抓取到的新 IP 总数: {len(new_ips_set)}")
print(f"最终写入文件的 IP 数量（交集）: {len(final_ips)}")

import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
import json

# ======= IP 正则 =======
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

# ======= 判断公网 IP =======
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False

# ======= IP 格式化 =======
def format_ip(ip):
    ip = ip.strip()
    if ':' in ip:
        return f'[{ip}]'
    return ip

# ======= 请求抓取函数 =======
def fetch_ips_requests():
    urls = [
        'https://api.uouin.com/cloudflare.html',
        'https://ip.164746.xyz',
        'https://cf.090227.xyz/',
        'https://dot.lzj.x10.bz/?doh=https%3A%2F%2Fdot.lzj.x10.bz%2Fdns-query&domain=bpb.yousef.isegaro.com&type=all',
        'https://addressesapi.090227.xyz/ip.164746.xyz',
        'https://addressesapi.090227.xyz/CloudFlareYes',
        'https://ipdb.api.030101.xyz/?type=bestcf&country=true'
    ]

    ip_set = set()

    for url in urls:
        try:
            response = requests.get(url, timeout=15)
            count = 0

            if url == 'https://api.uouin.com/cloudflare.html':
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                carrier_ip_count = {}
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        carrier = cols[0].text.strip()
                        ip = cols[1].text.strip()
                        if is_public_ip(ip):
                            carrier_ip_count.setdefault(carrier, 0)
                            if carrier_ip_count[carrier] < 5:
                                ip_set.add(f"{format_ip(ip)}#{carrier}")
                                carrier_ip_count[carrier] += 1
                                count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP（格式 IP#名称，单运营商最多 5 个）")

            elif url == 'https://ip.164746.xyz':
                ipv4_matches = re.findall(ipv4_pattern, response.text)
                ipv6_matches = re.findall(ipv6_pattern, response.text)
                for ip in ipv4_matches + ipv6_matches:
                    if is_public_ip(ip):
                        ip_set.add(format_ip(ip))
                        count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP")

            elif url == 'https://cf.090227.xyz/':
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font'])
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            ip_set.add(format_ip(ip))
                            count += 1
                            if count >= 30:
                                break
                    if count >= 30:
                        break
                print(f"[requests] {url} 抓取到 {count} 个 IP（限制 30 个）")

            elif url == 'https://dot.lzj.x10.bz/?doh=https%3A%2F%2Fdot.lzj.x10.bz%2Fdns-query&domain=bpb.yousef.isegaro.com&type=all':
                json_data = response.json()
                answers = json_data.get('Answer', [])
                for answer in answers:
                    ip = answer.get('data', '').strip()
                    if is_public_ip(ip):
                        ip_set.add(format_ip(ip))
                        count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP")

            else:
                ipv4_matches = re.findall(ipv4_pattern, response.text)
                ipv6_matches = re.findall(ipv6_pattern, response.text)
                for ip in ipv4_matches + ipv6_matches:
                    if is_public_ip(ip):
                        ip_set.add(format_ip(ip))
                        count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP")

        except Exception as e:
            print(f"[requests] 抓取失败: {url} 错误: {e}")
    return ip_set

# ======= 更新 IP 文件 =======
def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    cleaned_ips = set(new_ips)

    ipv4_list = []
    ipv6_list = []

    for ip in cleaned_ips:
        ip_only = ip.split('#')[0].strip('[]')
        try:
            ip_obj = ipaddress.ip_address(ip_only)
            if ip_obj.version == 4:
                ipv4_list.append(ip)
            else:
                ipv6_list.append(ip)
        except ValueError:
            continue

    ipv4_sorted = sorted(ipv4_list, key=lambda ip: ipaddress.ip_address(ip.split('#')[0].strip('[]')))
    ipv6_sorted = sorted(ipv6_list, key=lambda ip: ipaddress.ip_address(ip.split('#')[0].strip('[]')))

    sorted_ips = ipv4_sorted + ipv6_sorted

    new_ip_count = len(cleaned_ips)
    removed_ips = existing_ips - cleaned_ips
    removed_ip_count = len(removed_ips)

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")

    print(f"共更新 {new_ip_count} 个 IP")
    print(f"删除了 {removed_ip_count} 个 IP")

# ======= 主程序 =======
if __name__ == "__main__":
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

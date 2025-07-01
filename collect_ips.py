import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
import json
from collections import defaultdict

# ======= IP 正则 =======
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

# ======= 判断公网 IP =======
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip.strip('[]'))
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False

# ======= 格式化 IP =======
def format_ip(ip):
    if ':' in ip:  # IPv6
        return f"[{ip.strip('[]')}]"
    else:
        return ip.strip('[]')

# ======= requests 抓取 =======
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
            response = requests.get(url, timeout=10)

            if 'api.uouin.com/cloudflare.html' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                count = 0
                operator_ips = defaultdict(int)

                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 3:
                        name = cols[0].get_text(strip=True)
                        ip = cols[1].get_text(strip=True)

                        if re.match(ipv4_pattern, ip) or re.match(ipv6_pattern, ip):
                            if is_public_ip(ip) and operator_ips[name] < 5:
                                formatted_ip = f"{format_ip(ip)}#{name}"
                                ip_set.add(formatted_ip)
                                operator_ips[name] += 1
                                count += 1

                print(f"[requests] {url} 抓取到 {count} 个 IP（格式 IP#名称，单运营商最多 5 个）")

            elif 'dot.lzj.x10.bz' in url:
                json_data = response.json()
                count = 0
                if 'Answer' in json_data:
                    for answer in json_data['Answer']:
                        ip = answer.get('data')
                        if ip and is_public_ip(ip):
                            ip_set.add(format_ip(ip))
                            count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP")

            elif 'cf.090227.xyz' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font'])
                count = 0
                for element in elements:
                    if count >= 30:
                        break
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            ip_set.add(format_ip(ip))
                            count += 1
                            if count >= 30:
                                break
                print(f"[requests] {url} 抓取到 {count} 个 IP（限制 30 个）")

            else:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font'])
                count = 0
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            ip_set.add(format_ip(ip))
                            count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP")

        except Exception as e:
            print(f"[requests] 抓取失败: {url} 错误: {e}")
    return ip_set

# ======= 合并、去重、排序、写入 =======
def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    cleaned_ips = set(new_ips)

    sorted_ips = sorted(cleaned_ips, key=lambda ip: ipaddress.ip_address(ip.split('#')[0].strip('[]')))

    new_ip_count = len(cleaned_ips)
    removed_ips = existing_ips - cleaned_ips
    removed_ip_count = len(removed_ips)

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")

    print(f"共更新 {new_ip_count} 个 IP")
    print(f"删除了 {removed_ip_count} 个 IP")

if __name__ == "__main__":
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

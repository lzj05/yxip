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

# ======= 格式化 IP =======
def format_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version == 6:
        return f'[{ip}]'  # IPv6 加上括号
    return ip

# ======= requests 抓取 =======
def fetch_ips_requests():
    urls = [
        'https://api.uouin.com/cloudflare.html',
        'https://ip.164746.xyz',
        'https://cf.090227.xyz/',
        'https://dot.lzj.x10.bz/?doh=https%3A%2F%2Fdot.lzj.x10.bz%2Fdns-query&domain=bpb.yousef.isegaro.com&type=all'
    ]
    ip_set = set()
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            count = 0
            unlimited = ('dot.lzj.x10.bz' in url) or ('api.uouin.com' in url)

            if unlimited:
                try:
                    data = response.json()
                    answers = data.get("Answer", [])
                    for ans in answers:
                        ip = ans.get("data", "").strip()
                        if ip and is_public_ip(ip):
                            ip_set.add(format_ip(ip))
                    print(f"[requests] {url} 抓取到 {len(answers)} 个 IP（不限制数量）")
                except Exception:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    elements = soup.find_all(['tr', 'li', 'p', 'div', 'font', 'span', 'td', 'code'])
                    for element in elements:
                        text = element.get_text()
                        ipv4_matches = re.findall(ipv4_pattern, text)
                        ipv6_matches = re.findall(ipv6_pattern, text)
                        for ip in ipv4_matches + ipv6_matches:
                            if is_public_ip(ip):
                                ip_set.add(format_ip(ip))
                    print(f"[requests] {url} 抓取到 {len(ip_set)} 个 IP（不限制数量）")

            elif 'cf.090227.xyz' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = cols[1].get_text(strip=True)
                        if re.match(ipv4_pattern, ip) and is_public_ip(ip):
                            if ip not in ip_set:
                                ip_set.add(format_ip(ip))
                                count += 1
                                if count >= 30:
                                    break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多30个）")

            else:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font', 'span', 'td', 'code'])
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            if ip not in ip_set:
                                ip_set.add(format_ip(ip))
                                count += 1
                                if count >= 30:
                                    break
                    if count >= 30:
                        break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多30个）")

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

    all_ips = existing_ips.union(new_ips)

    cleaned_ips = set(ip.strip('[]') for ip in all_ips)

    def ip_sort_key(ip):
        ip_obj = ipaddress.ip_address(ip)
        return (ip_obj.version, ip_obj)

    sorted_ips = sorted(cleaned_ips, key=ip_sort_key)

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 6:
                f.write(f'[{ip}]\n')  # IPv6 输出带括号
            else:
                f.write(f'{ip}\n')

    print(f"总共写入 {len(sorted_ips)} 个 IP 到文件 {filename}")

if __name__ == '__main__':
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

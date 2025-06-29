import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress

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

# ======= requests 抓取，限制每个网址最多抓取30个有效IP =======
def fetch_ips_requests():
    urls = [
        'https://api.uouin.com/cloudflare.html',
        'https://ip.164746.xyz',
        'https://cf.090227.xyz/'
    ]
    ip_set = set()
    max_per_url = 30  # 每个网址最大有效IP数量限制

    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.find_all(['tr', 'li', 'p', 'div', 'font'])
            count = 0
            for element in elements:
                text = element.get_text()
                ipv4_matches = re.findall(ipv4_pattern, text)
                ipv6_matches = re.findall(ipv6_pattern, text)
                for ip in ipv4_matches + ipv6_matches:
                    if is_public_ip(ip):
                        if ip not in ip_set and count < max_per_url:
                            ip_set.add(ip)
                            count += 1
                    if count >= max_per_url:
                        break
                if count >= max_per_url:
                    break
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

    all_ips = existing_ips.union(new_ips)

    # 清理 IP（去除空白和方括号）
    cleaned_ips = set(ip.strip().strip("[]") for ip in all_ips)

    ipv4_list = []
    ipv6_list = []

    for ip in cleaned_ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version == 4:
                ipv4_list.append(ip)
            else:
                ipv6_list.append(ip)
        except ValueError:
            pass  # 跳过无效IP

    ipv4_sorted = sorted(ipv4_list, key=lambda ip: ipaddress.IPv4Address(ip))
    ipv6_sorted = sorted(ipv6_list, key=lambda ip: ipaddress.IPv6Address(ip))

    sorted_ips = ipv4_sorted + ipv6_sorted

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(ip + '\n')

    print(f"更新后的 IP 列表写入到 {filename}，共 {len(sorted_ips)} 条记录。")

if __name__ == '__main__':
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

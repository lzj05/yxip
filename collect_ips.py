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
        return f'[{ip}]'  # IPv6 加括号
    return ip

# ======= 抓取函数 =======
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

            if 'api.uouin.com' in url:
                # 每个运营商最多抓5个IP（IPv4+IPv6总数）
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                carrier_ip_count = {}
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        carrier = cols[0].get_text(strip=True)
                        ip = cols[1].get_text(strip=True)
                        if is_public_ip(ip):
                            current_count = carrier_ip_count.get(carrier, 0)
                            if current_count < 5:
                                entry = f"{format_ip(ip)} + {carrier} - {format_ip(ip)}"
                                if entry not in ip_set:
                                    ip_set.add(entry)
                                    carrier_ip_count[carrier] = current_count + 1
                                    count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP（每运营商最多5个）")

            elif 'cf.090227.xyz' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                count = 0
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = cols[1].get_text(strip=True)
                        carrier = cols[0].get_text(strip=True) if len(cols[0].get_text(strip=True)) > 0 else None
                        if re.match(ipv4_pattern, ip) and is_public_ip(ip):
                            if carrier:
                                entry = f"{format_ip(ip)} + {carrier} - {format_ip(ip)}"
                            else:
                                entry = format_ip(ip)
                            if entry not in ip_set:
                                ip_set.add(entry)
                                count += 1
                                if count >= 30:
                                    break
                print(f"[requests] {url} 抓取到 {count} 个 IP（限制30条）")

            elif 'addressesapi.090227.xyz' in url or 'ipdb.api.030101.xyz' in url:
                text = response.text
                ipv4_matches = re.findall(ipv4_pattern, text)
                ipv6_matches = re.findall(ipv6_pattern, text)
                total_matches = ipv4_matches + ipv6_matches
                for ip in total_matches:
                    if is_public_ip(ip):
                        # 这类网址没有运营商信息，只用IP
                        entry = format_ip(ip)
                        if entry not in ip_set:
                            ip_set.add(entry)
                print(f"[requests] {url} 抓取到 {len(total_matches)} 个 IP（无运营商）")

            else:
                # 其他网页默认抓取IP，尝试解析运营商，如果无运营商就只用IP
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font', 'span', 'td', 'code'])
                count = 0
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            # 尝试找同元素前面或附近是否有运营商名，简化版只用默认IP
                            entry = format_ip(ip)
                            if entry not in ip_set:
                                ip_set.add(entry)
                                count += 1
                                if count >= 30:
                                    break
                    if count >= 30:
                        break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多30条）")

        except Exception as e:
            print(f"[requests] 抓取失败: {url} 错误: {e}")

    return ip_set

# ======= 写入文件 =======
def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    # 分离带运营商和不带运营商
    ips_with_carrier = []
    ips_without_carrier = []

    for ip in new_ips:
        if '+' in ip and '-' in ip:
            ips_with_carrier.append(ip)
        else:
            ips_without_carrier.append(ip)

    def ip_sort_key(ip):
        # 去除格式中的运营商后缀，只留下IP部分
        if '+' in ip and '-' in ip:
            ip_part = ip.split('+')[0].strip()
        else:
            ip_part = ip
        ip_part = ip_part.strip('[]')
        ip_obj = ipaddress.ip_address(ip_part)
        return (ip_obj.version, ip_obj)

    ips_with_carrier_sorted = sorted(ips_with_carrier, key=ip_sort_key)
    ips_without_carrier_sorted = sorted(ips_without_carrier, key=ip_sort_key)

    sorted_ips = ips_with_carrier_sorted + ips_without_carrier_sorted

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(ip + "\n")

    added_ips = new_ips - existing_ips
    removed_ips = existing_ips - new_ips

    print(f"共更新了 {len(sorted_ips)} 个 IP")
    print(f"新增 IP: {len(added_ips)} 个")
    print(f"删除 IP: {len(removed_ips)} 个")

if __name__ == "__main__":
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

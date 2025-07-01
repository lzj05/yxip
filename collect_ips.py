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

# ======= 抓取 IP 主函数 =======
def fetch_ips_requests():
    urls = [
        'https://api.uouin.com/cloudflare.html',
        'https://ip.164746.xyz',
        'https://cf.090227.xyz/',
        'https://dot.lzj.x10.bz/?doh=https%3A%2F%2Fdot.lzj.x10.bz%2Fdns-query&domain=bpb.yousef.isegaro.com&type=all',
        'https://addressesapi.090227.xyz/ct',
        'https://addressesapi.090227.xyz/cmcc',
        'https://addressesapi.090227.xyz/cmcc-ipv6',
        'https://addressesapi.090227.xyz/CloudFlareYes',
        'https://addressesapi.090227.xyz/ip.164746.xyz',
        'https://ipdb.api.030101.xyz/?type=bestproxy&country=true',
        'https://ipdb.api.030101.xyz/?type=bestcf&country=true'
    ]

    ip_set = set()
    # 用于 api.uouin.com 限制每个运营商最多5个IP（IPv4+IPv6总共）
    carrier_ip_count = {}

    for url in urls:
        try:
            response = requests.get(url, timeout=15)
            count = 0

            # api.uouin.com 限制每个运营商最多5个IP
            if 'api.uouin.com/cloudflare.html' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        carrier = cols[0].text.strip()
                        ip = cols[1].text.strip()
                        if is_public_ip(ip):
                            if carrier_ip_count.get(carrier, 0) < 5:
                                entry = f"{format_ip(ip)}#{carrier}"
                                if entry not in ip_set:
                                    ip_set.add(entry)
                                    carrier_ip_count[carrier] = carrier_ip_count.get(carrier, 0) + 1
                                    count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP（每运营商最多5个）")

            # dot.lzj.x10.bz 返回 JSON 格式，提取Answer里的IP，最多30条
            elif 'dot.lzj.x10.bz' in url:
                try:
                    data = response.json()
                    answers = data.get('Answer', [])
                    for ans in answers:
                        ip = ans.get('data', '').strip()
                        if ip and is_public_ip(ip):
                            entry = format_ip(ip)
                            if entry not in ip_set:
                                ip_set.add(entry)
                                count += 1
                                if count >= 30:
                                    break
                    print(f"[requests] {url} 抓取到 {count} 个 IP（最多30条）")
                except Exception as e:
                    print(f"[requests] 解析JSON失败: {url} 错误: {e}")

            # cf.090227.xyz 抓取IP+运营商 格式，限制30条
            elif 'cf.090227.xyz' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = cols[1].get_text(strip=True)
                        carrier = cols[0].get_text(strip=True)
                        if is_public_ip(ip):
                            # 格式 IP#运营商
                            entry = f"{format_ip(ip)}#{carrier}" if carrier else format_ip(ip)
                            if entry not in ip_set:
                                ip_set.add(entry)
                                count += 1
                                if count >= 30:
                                    break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多30条）")

            # addressesapi 和 ipdb.api 简单抓取全部IP，不限数量
            elif any(x in url for x in ['addressesapi.090227.xyz', 'ipdb.api.030101.xyz']):
                text = response.text
                ipv4_matches = re.findall(ipv4_pattern, text)
                ipv6_matches = re.findall(ipv6_pattern, text)
                for ip in ipv4_matches + ipv6_matches:
                    if is_public_ip(ip):
                        entry = format_ip(ip)
                        if entry not in ip_set:
                            ip_set.add(entry)
                            count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP（不限数量）")

            else:
                # 其他地址尝试通用方式解析
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font', 'span', 'td', 'code'])
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
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

# ======= 合并、去重、排序、写入 =======
def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    # 解析格式 IP#运营商，统一提取IP部分用于排序
    def extract_ip(entry):
        return entry.split('#')[0].strip('[]')

    existing_ips_clean = set(extract_ip(ip) for ip in existing_ips)
    new_ips_clean = set(extract_ip(ip) for ip in new_ips)

    removed_ips = existing_ips_clean - new_ips_clean
    added_ips = new_ips_clean - existing_ips_clean

    # 先排序：带运营商的放前面，再按IP版本排序，IPv4排在IPv6前，最后按IP排序
    def sort_key(entry):
        ip_part = extract_ip(entry)
        ip_obj = ipaddress.ip_address(ip_part)
        has_carrier = 0 if '#' in entry else 1  # 带运营商的排前（0），无运营商的排后（1）
        return (has_carrier, ip_obj.version, ip_obj)

    sorted_ips = sorted(new_ips, key=sort_key)

    with open(filename, 'w') as f:
        for entry in sorted_ips:
            ip_part = extract_ip(entry)
            ip_obj = ipaddress.ip_address(ip_part)
            if ip_obj.version == 6:
                # IPv6加括号
                if '#' in entry:
                    carrier = entry.split('#')[1]
                    f.write(f'[{ip_part}]#{carrier}\n')
                else:
                    f.write(f'[{ip_part}]\n')
            else:
                f.write(f"{entry}\n")

    print(f"共更新了 {len(sorted_ips)} 个 IP")
    print(f"新增 IP: {len(added_ips)} 个")
    print(f"删除 IP: {len(removed_ips)} 个")

if __name__ == '__main__':
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

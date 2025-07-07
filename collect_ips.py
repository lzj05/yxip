import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
import json

# IP 正则
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

# 运营商优先级（移动 > 联通 > 电信 > 其他）
carrier_priority = {
    '移动': 1,
    'CMCC': 1,
    '联通': 2,
    '电信': 3
}

# 判断公网 IP
def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False

# 格式化 IP
def format_ip(ip, carrier=None):
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version == 6:
        return f'[{ip}]'
    else:
        return f"{ip}#{carrier}" if carrier else ip

# 获取运营商优先级
def get_carrier_priority(entry):
    if '#' in entry:
        carrier = entry.split('#')[1]
        for key in carrier_priority:
            if key in carrier:
                return carrier_priority[key]
        return 4  # 未知运营商
    else:
        return 5  # 没有运营商

# 通用请求函数（带重试）
def safe_request(url, method='GET', retries=3, **kwargs):
    for attempt in range(retries):
        try:
            if method == 'GET':
                return requests.get(url, timeout=15, **kwargs)
            elif method == 'POST':
                return requests.post(url, timeout=15, **kwargs)
        except Exception as e:
            if attempt == retries - 1:
                print(f"[requests] 请求失败: {url} 错误: {e}")
    return None

# 抓取 IP
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
        'https://api.hostmonit.com/get_optimization_ip',
        'https://api.hostmonit.com/get_optimization_ip?v6'
    ]

    ip_set = set()
    carrier_ip_count = {}

    for url in urls:
        try:
            if 'api.hostmonit.com/get_optimization_ip' in url:
                if url.endswith('?v6'):
                    payload = {"key": "iDetkOys", "type": "v6"}
                else:
                    payload = {"key": "iDetkOys"}

                response = safe_request(url.split('?')[0], method='POST', json=payload)
                if not response:
                    continue

                data = response.json()
                ip_list = data.get('data', [])
                count = 0

                for entry_data in ip_list:
                    ip = entry_data.get('ip', '').strip()
                    colo = entry_data.get('colo', '').strip()
                    if ip and is_public_ip(ip):
                        entry = f"{ip}#{colo}" if colo else ip
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.version == 6:
                            entry = f'[{ip}]'
                        if entry not in ip_set:
                            ip_set.add(entry)
                            count += 1

                print(f"[requests] {url} 抓取到 {count} 个 IP（不限数量）")
                continue

            response = safe_request(url)
            if not response:
                continue

            count = 0

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
                                ip_obj = ipaddress.ip_address(ip)
                                entry = format_ip(ip, carrier if ip_obj.version == 4 else None)
                                if entry not in ip_set:
                                    ip_set.add(entry)
                                    carrier_ip_count[carrier] = carrier_ip_count.get(carrier, 0) + 1
                                    count += 1
                print(f"[requests] {url} 抓取到 {count} 个 IP（每运营商最多5个）")

            elif 'dot.lzj.x10.bz' in url:
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

            elif 'cf.090227.xyz' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                mobile_count = 0
                telecom_count = 0
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        carrier = cols[0].get_text(strip=True)
                        ip = cols[1].get_text(strip=True)
                        if is_public_ip(ip):
                            ip_obj = ipaddress.ip_address(ip)
                            entry = format_ip(ip, carrier if ip_obj.version == 4 else None)
                            if entry not in ip_set:
                                if '移动' in carrier and mobile_count < 5:
                                    ip_set.add(entry)
                                    mobile_count += 1
                                    count += 1
                                elif '电信' in carrier and telecom_count < 10:
                                    ip_set.add(entry)
                                    telecom_count += 1
                                    count += 1
                                if count >= 30:
                                    break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多30条，电信最多10条，移动最多5条）")

            else:
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

        except Exception as e:
            print(f"[requests] 抓取失败: {url} 错误: {e}")

    return ip_set

# 写入文件
def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    def extract_ip(entry):
        return entry.split('#')[0].strip('[]')

    existing_ips_clean = set(extract_ip(ip) for ip in existing_ips)
    new_ips_clean = set(extract_ip(ip) for ip in new_ips)

    removed_ips = existing_ips_clean - new_ips_clean
    added_ips = new_ips_clean - existing_ips_clean

    def sort_key(entry):
        ip_part = extract_ip(entry)
        ip_obj = ipaddress.ip_address(ip_part)
        priority = get_carrier_priority(entry)
        return (priority, ip_obj.version, ip_obj)

    sorted_ips = sorted(new_ips, key=sort_key)

    with open(filename, 'w') as f:
        for entry in sorted_ips:
            ip_part = extract_ip(entry)
            ip_obj = ipaddress.ip_address(ip_part)
            if ip_obj.version == 6:
                f.write(f'[{ip_part}]\n')
            else:
                f.write(f"{entry}\n")

    print(f"共更新了 {len(sorted_ips)} 个 IP")
    print(f"新增 IP: {len(added_ips)} 个")
    print(f"删除 IP: {len(removed_ips)} 个")

if __name__ == '__main__':
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

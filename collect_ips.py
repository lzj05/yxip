import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
import json

# IP 正则
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

# 运营商优先级（移动 > 联通 > 电信 > 多线 > Default > 其他）
carrier_priority = {
    '移动': 1,
    'CMCC': 1, # 移动
    '联通': 2,
    '电信': 3,
    '多线': 4,
    'Default': 5, # 新增 Default 优先级
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
        # 遍历 carrier_priority，检查是否包含关键字
        for key, priority in carrier_priority.items():
            if key in carrier: # 检查运营商名称是否包含已定义的关键字
                return priority
        return 6  # 未知运营商（排在 Default 之后）
    else:
        return 7  # 没有运营商信息（排在所有带运营商的IP之后）

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

# 抓取 IP (此部分基本不变，只在提取运营商信息时可能需要考虑“Default”来源，这里只展示与上次修改有差异的部分)
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

    cf_telecom_count = 0
    cf_mobile_count = 0
    CF_TELECOM_LIMIT = 10
    CF_MOBILE_LIMIT = 5

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
                ip_list = data.get('info', [])
                count = 0

                for item in ip_list:
                    ip = item.get('ip', '').strip()
                    colo = item.get('colo', '').strip()
                    if ip and is_public_ip(ip):
                        extracted_carrier = None
                        if 'CMCC' in colo or '移动' in colo:
                            extracted_carrier = '移动'
                        elif 'CU' in colo or '联通' in colo:
                            extracted_carrier = '联通'
                        elif 'CT' in colo or '电信' in colo:
                            extracted_carrier = '电信'
                        elif 'Multi' in colo or '多线' in colo:
                            extracted_carrier = '多线'
                        elif 'Default' in colo: # 检查是否包含“Default”
                            extracted_carrier = 'Default'
                        
                        entry = format_ip(ip, extracted_carrier if extracted_carrier else colo)
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
                
                temp_ips_by_carrier = {'电信': [], '移动': [], '其他': []} 
                
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        carrier = cols[0].get_text(strip=True)
                        ip = cols[1].get_text(strip=True)
                        
                        if is_public_ip(ip):
                            ip_obj = ipaddress.ip_address(ip)
                            formatted_entry = format_ip(ip, carrier if ip_obj.version == 4 else None)

                            if '电信' in carrier and cf_telecom_count < CF_TELECOM_LIMIT:
                                temp_ips_by_carrier['电信'].append(formatted_entry)
                            elif '移动' in carrier and cf_mobile_count < CF_MOBILE_LIMIT:
                                temp_ips_by_carrier['移动'].append(formatted_entry)
                            else:
                                temp_ips_by_carrier['其他'].append(formatted_entry)

                for entry in temp_ips_by_carrier['电信']:
                    if '电信' in entry and cf_telecom_count < CF_TELECOM_LIMIT and entry not in ip_set:
                        ip_set.add(entry)
                        cf_telecom_count += 1
                        count += 1
                
                for entry in temp_ips_by_carrier['移动']:
                    if '移动' in entry and cf_mobile_count < CF_MOBILE_LIMIT and entry not in ip_set:
                        ip_set.add(entry)
                        cf_mobile_count += 1
                        count += 1

                for entry in temp_ips_by_carrier['其他']:
                    if entry not in ip_set:
                        ip_set.add(entry)
                        count += 1

                print(f"[requests] {url} 抓取到 {count} 个 IP (电信最多{CF_TELECOM_LIMIT}条, 移动最多{CF_MOBILE_LIMIT}条, 其他不限)")

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

# 写入文件 (此部分无需改变)
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

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

# ======= 格式化 IP =======
def format_ip(ip):
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.version == 6:
        return f'[{ip}]'  # IPv6 加括号
    return ip

# ======= requests 抓取 =======
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

    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            count = 0
            unlimited = ('dot.lzj.x10.bz' in url) or ('api.uouin.com' in url)

            # 处理无限制 URL
            if unlimited:
                try:
                    data = response.json()
                    answers = data.get("Answer", [])
                    for ans in answers:
                        ip = ans.get("data", "").strip()
                        if ip and is_public_ip(ip):
                            entry = f"{format_ip(ip)}#未知{format_ip(ip)}"
                            ip_set.add(entry)
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
                                entry = f"{format_ip(ip)}#未知{format_ip(ip)}"
                                ip_set.add(entry)
                    print(f"[requests] {url} 抓取到 {len(ip_set)} 个 IP（不限制数量）")

            # 处理 cf.090227.xyz 网站
            elif 'cf.090227.xyz' in url:
                soup = BeautifulSoup(response.text, 'html.parser')
                rows = soup.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        carrier = cols[0].get_text(strip=True)
                        ip = cols[1].get_text(strip=True)
                        if re.match(ipv4_pattern, ip) and is_public_ip(ip):
                            entry = f"{format_ip(ip)}#{carrier}{format_ip(ip)}"
                            if entry not in ip_set:
                                ip_set.add(entry)
                                count += 1
                                if count >= 30:
                                    break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多 30 个）")

            # 处理 addressesapi 和 ipdb 网站
            elif 'addressesapi.090227.xyz' in url or 'ipdb.api.030101.xyz' in url:
                carrier = '未知'
                if 'ct' in url:
                    carrier = '电信'
                elif 'cmcc-ipv6' in url or 'cmcc' in url:
                    carrier = '移动'
                text = response.text
                ipv4_matches = re.findall(ipv4_pattern, text)
                ipv6_matches = re.findall(ipv6_pattern, text)
                for ip in ipv4_matches + ipv6_matches:
                    if is_public_ip(ip):
                        entry = f"{format_ip(ip)}#{carrier}{format_ip(ip)}"
                        ip_set.add(entry)
                print(f"[requests] {url} 抓取到 {len(ipv4_matches) + len(ipv6_matches)} 个 IP（不限制数量）")

            # 其它网站（限制最多 30 个）
            else:
                soup = BeautifulSoup(response.text, 'html.parser')
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font', 'span', 'td', 'code'])
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            entry = f"{format_ip(ip)}#未知{format_ip(ip)}"
                            if entry not in ip_set:
                                ip_set.add(entry)
                                count += 1
                                if count >= 30:
                                    break
                    if count >= 30:
                        break
                print(f"[requests] {url} 抓取到 {count} 个 IP（最多 30 个）")

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

    removed_ips = existing_ips - new_ips
    added_ips = new_ips - existing_ips

    def ip_sort_key(ip):
        ip_only = ip.split('#')[0].strip('[]')
        carrier = ip.split('#')[1].replace(ip_only, '')

        has_carrier = carrier != '未知'
        ip_obj = ipaddress.ip_address(ip_only)

        return (
            0 if has_carrier else 1,   # 优先有运营商
            ip_obj.version,            # IPv4 优先
            ip_obj                     # IP 从小到大
        )

    sorted_ips = sorted(new_ips, key=ip_sort_key)

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")

    print(f"共更新了 {len(sorted_ips)} 个 IP")
    print(f"新增 IP: {len(added_ips)} 个")
    print(f"删除 IP: {len(removed_ips)} 个")

# ======= 主程序 =======
if __name__ == '__main__':
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

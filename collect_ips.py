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
            soup = BeautifulSoup(response.text, 'html.parser')

            count = 0

            if 'cf.090227.xyz' in url:
                # 特殊处理该网址，按表格第二列td取IP
                rows = soup.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 2:
                        ip = cols[1].get_text(strip=True)
                        if re.match(ipv4_pattern, ip) and is_public_ip(ip):
                            if ip not in ip_set:
                                ip_set.add(ip)
                                count += 1
                                if count >= 30:
                                    break
            else:
                # 其他网址用常规方式查找IP
                elements = soup.find_all(['tr', 'li', 'p', 'div', 'font', 'span', 'td', 'code'])
                for element in elements:
                    text = element.get_text()
                    ipv4_matches = re.findall(ipv4_pattern, text)
                    ipv6_matches = re.findall(ipv6_pattern, text)
                    for ip in ipv4_matches + ipv6_matches:
                        if is_public_ip(ip):
                            if ip not in ip_set:
                                ip_set.add(ip)
                                count += 1
                                if count >= 30:
                                    break
                    if count >= 30:
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

    # 去掉可能的方括号
    cleaned_ips = set(ip.strip('[]') for ip in all_ips)

    # 排序，IPv4优先，避免不同版本IP比较报错
    def ip_sort_key(ip):
        ip_obj = ipaddress.ip_address(ip)
        return (ip_obj.version, ip_obj)

    sorted_ips = sorted(cleaned_ips, key=ip_sort_key)

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(ip + '\n')

    print(f"总共写入 {len(sorted_ips)} 个 IP 到文件 {filename}")

if __name__ == '__main__':
    new_ips = fetch_ips_requests()
    update_ip_file(new_ips)

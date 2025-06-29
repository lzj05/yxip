import requests
import re
import os
import ipaddress

# 静态网页列表
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz',
    'https://cf.090227.xyz/',
]

# API 请求地址
api_urls = [
    'https://www.nslookup.io/api/v1/domains/bpb.yousef.isegaro.com/dns-records'
]

# IP 正则
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False

def fetch_ips_requests():
    ip_set = set()
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"[requests] 请求失败: {url} 错误: {e}")
            continue

        text = response.text
        ips = re.findall(ipv4_pattern, text) + re.findall(ipv6_pattern, text)
        count = 0
        for ip in ips:
            if is_public_ip(ip):
                ip_set.add(ip)
                count += 1
        print(f"[requests] {url} 抓取到 {count} 个 IP")
    return ip_set

def fetch_ips_from_api():
    ip_set = set()
    for api_url in api_urls:
        try:
            response = requests.get(api_url, timeout=10)
            response.raise_for_status()
            data = response.json()

            count = 0
            for record in data.get('records', []):
                ip = record.get('value')
                if ip and is_public_ip(ip):
                    ip_set.add(ip)
                    count += 1

            print(f"[api] {api_url} 抓取到 {count} 个 IP")
        except Exception as e:
            print(f"[api] API 抓取出错: {e}")
    return ip_set

def load_existing_ips(filename='ip.txt'):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as f:
        return set(line.strip('[] \n') for line in f if line.strip())

def save_ips(ips, filename='ip.txt'):
    ipv4s = sorted(ip for ip in ips if ':' not in ip)
    ipv6s = sorted(ip for ip in ips if ':' in ip)
    with open(filename, 'w') as f:
        for ip in ipv4s + ipv6s:
            if ':' in ip:
                f.write(f'[{ip}]\n')
            else:
                f.write(ip + '\n')

def main():
    existing_ips = load_existing_ips()

    ips_requests = fetch_ips_requests()
    ips_api = fetch_ips_from_api()

    all_new_ips = ips_requests.union(ips_api)

    new_ips = all_new_ips - existing_ips

    if new_ips:
        combined_ips = existing_ips.union(new_ips)
        save_ips(combined_ips)
        print(f"✅ 新增 {len(new_ips)} 个公网 IP，当前总计 {len(combined_ips)} 个公网 IP，已保存到 ip.txt")
    else:
        print("⚙️ 无新增公网 IP，文件保持不变。")

if __name__ == "__main__":
    main()

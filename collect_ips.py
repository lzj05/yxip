import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# 要爬的链接列表（动态页面用selenium，其他用requests）
urls_requests = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

urls_selenium = [
    'https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/#cloudflare'
]

ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

# 读取旧文件
old_ips = []
if os.path.exists('ip.txt'):
    with open('ip.txt', 'r') as f:
        for line in f:
            ip = line.strip()
            if ip.startswith('[') and ip.endswith(']'):
                ip = ip[1:-1]
            if ip:
                old_ips.append(ip)
old_ips_set = set(old_ips)

new_ips_set = set()

def extract_ips_from_text(text):
    ips = set()
    for ip in re.findall(ipv4_pattern, text):
        try:
            ip_obj = ipaddress.ip_address(ip)
            ips.add(str(ip_obj))
        except ValueError:
            pass
    for ip in re.findall(ipv6_pattern, text):
        try:
            ip_obj = ipaddress.ip_address(ip)
            ips.add(str(ip_obj))
        except ValueError:
            pass
    return ips

# 用requests爬普通页面
for url in urls_requests:
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, 'html.parser')
        elements = soup.find_all(['tr', 'li', 'p', 'div'])
        for el in elements:
            text = el.get_text()
            ips = extract_ips_from_text(text)
            new_ips_set.update(ips)
        print(f"[requests] {url} 抓取到 {len(new_ips_set)} 个 IP")
    except Exception as e:
        print(f"[requests] {url} 请求失败: {e}")

# 用selenium爬动态页面
options = Options()
options.headless = True
driver = webdriver.Chrome(options=options)

for url in urls_selenium:
    try:
        driver.get(url)
        driver.implicitly_wait(8)  # 等待页面加载
        html = driver.page_source
        soup = BeautifulSoup(html, 'html.parser')
        text = soup.get_text()
        ips = extract_ips_from_text(text)
        new_ips_set.update(ips)
        print(f"[selenium] {url} 抓取到 {len(ips)} 个 IP")
    except Exception as e:
        print(f"[selenium] {url} 请求失败: {e}")

driver.quit()

# 取交集，保留旧文件顺序
final_ips = [ip for ip in old_ips if ip in new_ips_set]

ipv4_list = sorted([ip for ip in final_ips if ':' not in ip])
ipv6_list = sorted([ip for ip in final_ips if ':' in ip])

# 写入文件
with open('ip.txt', 'w') as f:
    for ip in ipv4_list:
        f.write(ip + '\n')
    for ip in ipv6_list:
        f.write(f'[{ip}]\n')

print(f"\n抓取新 IP 总数：{len(new_ips_set)}")
print(f"最终写入文件 IP 数量（交集，旧文件与新抓取）：{len(final_ips)}")

import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress

# 目标URL列表
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

# 正则表达式：同时支持 IPv4 和 IPv6（简写 :: 也支持）
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b|\[([A-Fa-f0-9:]+)\]'

# 删除旧文件
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

ip_set = set()

for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"请求失败: {url} 错误信息: {e}")
        continue

    soup = BeautifulSoup(response.text, 'html.parser')
    elements = soup.find_all(['tr', 'li', 'p', 'div'])

    for element in elements:
        element_text = element.get_text()
        ip_matches = re.findall(ip_pattern, element_text)

        for ip in ip_matches:
            ip = ip.strip('[]')  # 去除方括号

            try:
                ip_obj = ipaddress.ip_address(ip)

                # 用 ipaddress 判断内网/私有IP
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
                    # 过滤：私有地址、回环地址、本地链路地址、保留地址、组播地址
                    continue

                ip_set.add(ip_obj)

            except ValueError:
                continue  # 非法 IP，跳过

# 写入文件
if ip_set:
    with open('ip.txt', 'w') as file:
        for ip in sorted(ip_set, key=lambda x: (x.version, str(x))):
            if ip.version == 6:
                file.write(f'[{ip}]\n')
            else:
                file.write(f'{ip}\n')
    print(f'成功抓取 {len(ip_set)} 个唯一公网 IP 地址，已保存到 ip.txt 文件中。')
else:
    print('没有找到任何公网 IP 地址。')

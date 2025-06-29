import requests
from bs4 import BeautifulSoup
import re
import os

# 目标URL列表
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz'
]

# 正则表达式用于匹配IP地址
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# 检查ip.txt文件是否存在,如果存在则删除它
if os.path.exists('ip.txt'):
    os.remove('ip.txt')

# 用集合存储IP，自动去重
ip_set = set()

# 请求网页并提取IP
for url in urls:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # 自动抛出请求异常
    except requests.RequestException as e:
        print(f"请求失败: {url} 错误信息: {e}")
        continue  # 如果请求失败，跳过这个网址

    soup = BeautifulSoup(response.text, 'html.parser')

    # 自动提取所有可能包含IP的元素（tr、li、p、div）
    elements = soup.find_all(['tr', 'li', 'p', 'div'])

    for element in elements:
        element_text = element.get_text()
        ip_matches = re.findall(ip_pattern, element_text)

        for ip in ip_matches:
            ip_set.add(ip)

# 写入文件
if ip_set:
    with open('ip.txt', 'w') as file:
        for ip in sorted(ip_set):  # 排序后写入
            file.write(ip + '\n')
    print(f'成功抓取 {len(ip_set)} 个唯一IP地址，已保存到 ip.txt 文件中。')
else:
    print('没有找到任何IP地址。')

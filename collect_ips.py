import requests
from bs4 import BeautifulSoup
import re
import os
import ipaddress
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import tempfile
import shutil
import time

# 目标URL列表（静态页面）
urls = [
    'https://api.uouin.com/cloudflare.html',
    'https://ip.164746.xyz',
]

# IP正则
ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ipv6_pattern = r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b'

def is_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except:
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

        soup = BeautifulSoup(response.text, 'html.parser')
        elements = soup.find_all(['tr', 'li', 'p', 'div'])
        for element in elements:
            text = element.get_text()
            ips = re.findall(ipv4_pattern, text) + re.findall(ipv6_pattern, text)
            for ip in ips:
                if is_public_ip(ip):
                    ip_set.add(ip)
        print(f"[requests] {url} 抓取到 {len(ip_set)} 个 IP")
    return ip_set

def create_chrome_driver():
    user_data_dir = tempfile.mkdtemp()
    options = Options()
    options.add_argument(f'--user-data-dir={user_data_dir}')
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    driver = webdriver.Chrome(options=options)
    return driver, user_data_dir

def fetch_ips_selenium_nslookup():
    url = "https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/"
    ip_set = set()
    driver, user_data_dir = create_chrome_driver()
    try:
        driver.get(url)

        wait = WebDriverWait(driver, 15)

        # 等待标签区加载出来（可根据页面结构调整）
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "ul.nav.nav-tabs")))

        # 找到“Cloudflare”标签按钮，点击
        tabs = driver.find_elements(By.CSS_SELECTOR, "ul.nav.nav-tabs li a")
        clicked = False
        for tab in tabs:
            if "Cloudflare" in tab.text:
                tab.click()
                clicked = True
                break

        if not clicked:
            print("未找到 Cloudflare 标签，可能页面结构变化")
            return ip_set

        # 点击后等待该面板加载 IP 表格（调整选择器等待具体元素）
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "div#cloudflare .table-responsive")))

        time.sleep(3)  # 等待额外数据加载，防止异步未完成

        page_source = driver.page_source
        ips = re.findall(ipv4_pattern, page_source) + re.findall(ipv6_pattern, page_source)
        for ip in ips:
            if is_public_ip(ip):
                ip_set.add(ip)
        print(f"[selenium] {url} 抓取到 {len(ip_set)} 个 IP")
    except Exception as e:
        print(f"[selenium] Selenium 抓取出错: {e}")
    finally:
        driver.quit()
        shutil.rmtree(user_data_dir)
    return ip_set

def load_existing_ips(filename='ip.txt'):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as f:
        return set(line.strip("[]\n ") for line in f if line.strip())

def save_ips(ips, filename='ip.txt'):
    ipv4s = sorted([ip for ip in ips if ':' not in ip])
    ipv6s = sorted([ip for ip in ips if ':' in ip])
    with open(filename, 'w') as f:
        for ip in ipv4s + ipv6s:
            if ':' in ip:
                f.write(f'[{ip}]\n')
            else:
                f.write(ip + '\n')

def main():
    existing_ips = load_existing_ips()

    ips_requests = fetch_ips_requests()
    ips_selenium = fetch_ips_selenium_nslookup()

    all_new_ips = ips_requests.union(ips_selenium)

    new_ips = all_new_ips - existing_ips

    if new_ips:
        combined_ips = existing_ips.union(new_ips)
        save_ips(combined_ips)
        print(f"新增 {len(new_ips)} 个公网 IP，当前总计 {len(combined_ips)} 个公网 IP，已保存到 ip.txt")
    else:
        print("无新增公网 IP，文件保持不变。")

if __name__ == "__main__":
    main()

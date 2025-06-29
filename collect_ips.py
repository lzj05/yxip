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
import time

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
        'https://cf.090227.xyz/'
    ]
    ip_set = set()
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            elements = soup.find_all(['tr', 'li', 'p', 'div', 'font'])
            count = 0
            for element in elements:
                text = element.get_text()
                ipv4_matches = re.findall(ipv4_pattern, text)
                ipv6_matches = re.findall(ipv6_pattern, text)
                for ip in ipv4_matches + ipv6_matches:
                    if is_public_ip(ip):
                        ip_set.add(ip)
                        count += 1
            print(f"[requests] {url} 抓取到 {count} 个 IP")
        except Exception as e:
            print(f"[requests] 抓取失败: {url} 错误: {e}")
    return ip_set

# ======= Selenium 抓取 =======
def fetch_ips_selenium():
    url = 'https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/#cloudflare'
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--user-data-dir=/tmp/selenium")
    ip_set = set()

    try:
        driver = webdriver.Chrome(options=chrome_options)
        driver.get(url)
        wait = WebDriverWait(driver, 10)

        # 点击 Cloudflare tab
        cloudflare_tab = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(),'Cloudflare')]")))
        cloudflare_tab.click()

        time.sleep(3)
        elements = driver.find_elements(By.XPATH, "//font")
        for element in elements:
            ip = element.text.strip()
            if ip and is_public_ip(ip):
                ip_set.add(ip)

        print(f"[selenium] Cloudflare 抓取到 {len(ip_set)} 个 IP")
    except Exception as e:
        print(f"[selenium] Selenium 抓取出错: {e}")
    finally:
        driver.quit()

    return ip_set

# ======= 合并、去重、排序、写入 =======
def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    all_ips = existing_ips.u

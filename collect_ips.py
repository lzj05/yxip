def update_ip_file(new_ips):
    filename = 'ip.txt'
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            existing_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_ips = set()

    cleaned_ips = set(new_ips)

    # 分开 IPv4 和 IPv6 排序
    ipv4_list = []
    ipv6_list = []

    for ip in cleaned_ips:
        ip_only = ip.split('#')[0].strip('[]')
        try:
            ip_obj = ipaddress.ip_address(ip_only)
            if ip_obj.version == 4:
                ipv4_list.append(ip)
            else:
                ipv6_list.append(ip)
        except ValueError:
            continue  # 忽略无效 IP

    ipv4_sorted = sorted(ipv4_list, key=lambda ip: ipaddress.ip_address(ip.split('#')[0].strip('[]')))
    ipv6_sorted = sorted(ipv6_list, key=lambda ip: ipaddress.ip_address(ip.split('#')[0].strip('[]')))

    sorted_ips = ipv4_sorted + ipv6_sorted

    new_ip_count = len(cleaned_ips)
    removed_ips = existing_ips - cleaned_ips
    removed_ip_count = len(removed_ips)

    with open(filename, 'w') as f:
        for ip in sorted_ips:
            f.write(f"{ip}\n")

    print(f"共更新 {new_ip_count} 个 IP")
    print(f"删除了 {removed_ip_count} 个 IP")

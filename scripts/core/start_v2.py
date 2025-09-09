# start.py的关键修改部分，用于支持新架构

# 修改merge_all_expanded_results函数
async def merge_all_expanded_results(report_folder: str, root_domain: str, redirect_domains: set = None, filter_domains: set = None, body_info_domains: set = None):
    """
    合并所有扩展结果，区分主域名资产和扩展资产
    - 主域名资产：保存到 ips.txt, root_domains.txt, urls.txt
    - 扩展资产：保存到 expand_ips.txt, expand_urls.txt
    """
    if filter_domains is None:
        filter_domains = set()
    
    tuozhan_path = os.path.join(report_folder, "tuozhan")
    all_dir = os.path.join(tuozhan_path, "all_tuozhan")
    os.makedirs(all_dir, exist_ok=True)

    existing_report_folder = f"./output/{root_domain}"
    existing_urls_raw = await read_lines_from_file(os.path.join(existing_report_folder, "input/urls.txt"))
    existing_urls_hosts = {strip_url_scheme(u) for u in existing_urls_raw}

    a_record_path = f"{existing_report_folder}/input/a_records.txt"
    existing_ips = await read_lines_from_file(a_record_path)
    
    # 加载动态过滤IP列表
    filtered_ips = load_filter_ips(str(DYNAMIC_IP_FILTER_FILE))

    # 保存来源映射
    source_host_map = defaultdict(set)
    
    # 区分主域名资产和扩展资产
    domain_ips = []  # 主域名的IP
    domain_subdomains = []  # 主域名的子域名
    expand_ips = []  # 扩展IP
    expand_domains = []  # 扩展域名
    expand_urls = []  # 扩展URL

    # 1. 处理 fofa 子目录下所有 txt 文件
    for subfolder in ["fofa"]:
        full_path = os.path.join(tuozhan_path, subfolder)
        if not os.path.exists(full_path):
            continue

        for fname in os.listdir(full_path):
            if not fname.endswith(".txt"):
                continue

            file_path = os.path.join(full_path, fname)
            if "hunter" in fname:
                # Hunter格式: IP,端口,域名,Web标题,...
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("ip,port,domain"):
                            continue
                        parts = line.split(",", 4)
                        if len(parts) >= 3:
                            ip, port, domain = parts[0], parts[1], parts[2]
                            if ip and is_ip(ip):
                                expand_ips.append((ip, f"Hunter:{fname}"))
                            if domain and not is_ip(domain):
                                if root_domain in domain:
                                    # 属于主域名的子域名
                                    domain_subdomains.append((domain, f"Hunter:{fname}"))
                                else:
                                    # 扩展域名
                                    expand_domains.append((domain, f"Hunter:{fname}"))
            elif "fofa" in fname:
                # FOFA格式处理...
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # 简单处理，根据实际格式调整
                        if is_ip(line):
                            expand_ips.append((line, f"FOFA:{fname}"))
                        elif '.' in line:
                            if root_domain in line:
                                domain_subdomains.append((line, f"FOFA:{fname}"))
                            else:
                                expand_domains.append((line, f"FOFA:{fname}"))

    # 2. 处理跳转发现的域名
    if redirect_domains:
        for domain in redirect_domains:
            if domain and domain != root_domain and '.' in domain:
                if domain not in filter_domains:
                    expand_domains.append((domain, "URL跳转发现"))

    # 3. 处理body中提取的域名
    if body_info_domains:
        for domain in body_info_domains:
            if domain != root_domain:
                root = extract_root_domain(domain)
                if root and root == domain:
                    # 是主域名
                    expand_domains.append((domain, "URL BODY INFO"))
                else:
                    # 是URL或子域名
                    if domain.startswith('http'):
                        expand_urls.append((domain, "URL BODY INFO"))
                    else:
                        expand_domains.append((domain, "URL BODY INFO"))

    # 4. 写入主域名资产文件
    # ips.txt - 主域名的IP（从现有a_records.txt复制）
    ips_path = os.path.join(all_dir, "ips.txt")
    with open(ips_path, "w") as f:
        if existing_ips:
            f.write("# 主域名IP地址\n")
            for ip in existing_ips:
                f.write(f"{ip}\n")
        else:
            f.write("# 暂无主域名IP\n")

    # root_domains.txt - 扩展主域名（只保存域名本身）
    roots_path = os.path.join(all_dir, "root_domains.txt")
    unique_expand_domains = list(set([d for d, _ in expand_domains]))
    with open(roots_path, "w") as f:
        if unique_expand_domains:
            f.write("# 扩展发现的主域名\n")
            for domain in sorted(unique_expand_domains):
                if domain != root_domain:  # 排除自身
                    f.write(f"{domain}\n")
        else:
            f.write("# 暂无扩展主域名\n")

    # urls.txt - 主域名的子域名
    urls_path = os.path.join(all_dir, "urls.txt")
    unique_subdomains = list(set([d for d, _ in domain_subdomains]))
    with open(urls_path, "w") as f:
        if unique_subdomains:
            f.write("# 主域名的子域名\n")
            for subdomain in sorted(unique_subdomains):
                f.write(f"{subdomain}\n")
        else:
            f.write("# 暂无子域名\n")

    # 5. 写入扩展资产文件
    # expand_ips.txt - 扩展IP
    expand_ips_path = os.path.join(all_dir, "expand_ips.txt")
    unique_expand_ips = list(set([ip for ip, _ in expand_ips]))
    with open(expand_ips_path, "w") as f:
        if unique_expand_ips:
            f.write("# 扩展发现的IP地址\n")
            for ip in sorted(unique_expand_ips):
                if ip not in filtered_ips:  # 过滤已知IP
                    f.write(f"{ip}\n")
        else:
            f.write("# 暂无扩展IP\n")

    # expand_urls.txt - 扩展URL
    expand_urls_path = os.path.join(all_dir, "expand_urls.txt")
    unique_expand_urls = list(set([url for url, _ in expand_urls]))
    with open(expand_urls_path, "w") as f:
        if unique_expand_urls:
            f.write("# 扩展发现的URL\n")
            for url in sorted(unique_expand_urls):
                f.write(f"{url}\n")
        else:
            f.write("# 暂无扩展URL\n")

    # 6. 输出统计信息
    print(f"\n[拓展统计] {root_domain}")
    print(f"  - 主域名IP: {len(existing_ips)} 个")
    print(f"  - 主域名子域名: {len(unique_subdomains)} 个")
    print(f"  - 扩展主域名: {len(unique_expand_domains)} 个")
    print(f"  - 扩展IP: {len(unique_expand_ips)} 个")
    print(f"  - 扩展URL: {len(unique_expand_urls)} 个")
    
    return {
        'domain_ips': len(existing_ips),
        'domain_subdomains': len(unique_subdomains),
        'expand_domains': len(unique_expand_domains),
        'expand_ips': len(unique_expand_ips),
        'expand_urls': len(unique_expand_urls)
    }
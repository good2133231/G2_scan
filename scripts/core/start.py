import sys
import ipaddress
import os
import json
import subprocess
from pathlib import Path
import httpx
import time
from urllib.parse import urlparse
from collections import defaultdict
from tld import get_fld
from rapiddns import RapidDns
from tqdm import tqdm
import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
from itertools import islice
from functools import partial
import shutil
import tldextract
import re
import signal
import requests
from datetime import datetime
import random
import base64
import configparser
import aiofiles
# ------------------------------------
# 命令模板和配置
if '-small' in sys.argv:
    print("[*] 使用测试环境命令模板")
    AFROG_CMD_TEMPLATE = "./tools/scanner/afrog -T {target_file} -c 100 -rl 300 -timeout 2 -s spring -doh -json {output_file}"
    FSCAN_CMD_TEMPLATE = "./tools/scanner/fscan -hf {target_file} -p 80 -np -nobr -t 600 -o {output_file}"
    DEBUG_FSCAN = True
else:
    print("[*] 使用正式环境命令模板")
    AFROG_CMD_TEMPLATE = "./tools/scanner/afrog -T {target_file} -c 100 -rl 300 -timeout 2 -S high,info -doh -json {output_file}"
    FSCAN_CMD_TEMPLATE = "./tools/scanner/fscan -hf {target_file} -p all -np -nobr -t 600  -o {output_file}"
    DEBUG_FSCAN = True
ONLY_DOMAIN_MODE = '-test' in sys.argv
RESULT_JSON_PATH = "temp/result_all.json"

if ONLY_DOMAIN_MODE:

    print("[*] 仅处理域名模式 (-test)，将跳过安全扫描任务")
SKIP_CURRENT_DOMAIN = False

CDN_LIST_PATH = "config/filters/cdn.txt"
CDN_DYNAMIC_PATH = "config/filters/cdn_动态添加_一年清一次.txt"
DYNAMIC_FILTER_FILE = Path("config/filters/filter_domains-动态.txt")
new_filtered_domains = set()

black_titles = {
        "Just a moment...",
        "Attention Required! | Cloudflare",
        "安全验证",  # 可根据你业务添加更多无效标题
}
# 1. 读取已有的动态过滤域名
# ✅ 同步读取方式，最简单稳定（推荐用于非async程序）
if DYNAMIC_FILTER_FILE.exists():
    with open(DYNAMIC_FILTER_FILE, mode='r', encoding='utf-8') as f:
        for line in f:
            line = line.strip().strip('"').strip("'").lower()
            if line:
                new_filtered_domains.add(line)


#过滤
FILTER_DOMAIN_PATH = "config/filters/filter-domain.txt"
BLACKLIST_FILE_PATH = "config/filters/fofa_query_blacklist.txt"


hunter_proxies = "socks5h://127.0.0.1:7891"
config_path = Path("config/api/config.ini")
config = configparser.ConfigParser()
config.read(config_path, encoding='utf-8')

TEST_EMAIL = config['DEFAULT'].get('TEST_EMAIL')
TEST_KEY = config['DEFAULT'].get('TEST_KEY')
HUNTER_API_KEY = ""

dns_cache = {}
reverse_lookup_semaphore = None  # 将在异步上下文中初始化

def handle_sigint(signum, frame):
    global SKIP_CURRENT_DOMAIN
    print("\n[!] 收到 Ctrl+C，跳过当前域名，继续下一个...")
    SKIP_CURRENT_DOMAIN = True
def headers_lib():
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36"
    }
def handle_sigquit(signum, frame):
    print("\n[!] 收到 Ctrl+\\，终止整个程序")
    sys.exit(0)
def is_domain_resolvable(domain):
    if domain in dns_cache:
        return dns_cache[domain]
    try:
        socket.gethostbyname(domain)
        dns_cache[domain] = True
        return True
    except Exception:
        dns_cache[domain] = False
        return False
# ------------------------------------
async def reverse_lookup_ip_async(ip):
    print("[>] 使用 dnsdblookup 反查域名接口")
    try:
        url_d = f"https://dnsdblookup.com/{ip}/"
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.get(url_d, headers=headers_lib())
        site = re.findall(r'<span class="date">(.*?)</span><a href="/(.*?)/" target="_blank">(.*?)</a>', res.text, re.S)

        domains = [domain for _, _, domain in site]

        # 去重，避免重复域名影响后续逻辑
        domains = list(set(domains))

        if domains:
            return ip, domains
        else:
            return ip, []

    except Exception as e:
        print(f"[!] dnsdblookup 反查失败: {e}")
        try:
            print("[>] 使用 RapidDns 反查域名接口")
            domains = RapidDns.sameip(ip)
            # 格式统一为扁平化字符串列表
            flat_domains = [item[0] if isinstance(item, list) else item for item in domains]
            return ip, list(set(flat_domains))

        except Exception as e:
            print(f"[!] RapidDns 反查失败: {ip}, 错误: {e}")
            print("[>] 使用 ip138 反查域名接口")
            try:
                url_d_138 = f"https://ip138.com/{ip}/"
                async with httpx.AsyncClient(timeout=5) as client:
                    res_138 = await client.get(url_d_138, headers=headers_lib())
                site_138 = re.findall(r'<span class="date">(.*?)</span><a href="/(.*?)/" target="_blank">(.*?)</a>', res_138.text, re.S)

                # 不做时间过滤，直接全部域名
                domains = [domain_138 for _, _, domain_138 in site_138]
                domains = list(set(domains))

                if domains:
                    return ip, domains
                else:
                    return ip, []
            except Exception as e:
                print(f"[!] ip138 反查失败: {e}")
                return ip, []


        return ip, []

    return ip, None

# 异步执行命令
async def run_cmd_async(cmd):
    if DEBUG_FSCAN:
        print(f"[cmd] 异步执行命令: {cmd}")
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    stdout_str = stdout.decode(errors='ignore').strip()
    stderr_str = stderr.decode(errors='ignore').strip()

    if proc.returncode != 0:
        print(f"[ERROR] 命令执行失败: {cmd}")
        print(f"[ERROR] 返回码: {proc.returncode}")
        print(f"[ERROR] stderr: {stderr_str}")
        return None, stderr_str  # 返回错误信息而不是退出

    # await finalize_report_directory(report_path, root)

    return stdout_str, stderr_str
# ------------------------------------
# 目录初始化
def init_dirs():
    for d in ["temp", "output/reports", "output/domains"]:
        os.makedirs(d, exist_ok=True)

# 载入过滤域名
def load_filter_domains(path):
    if os.path.exists(path):
        return {line.strip().lower() for line in open(path, encoding="utf-8") if line.strip()}
    return set()

# 载入CDN IP段
def load_cdn_ranges(path):
    ranges = []
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line:
                try:
                    net = ipaddress.ip_network(line if '/' in line else line + '/32', strict=False)
                    ranges.append(net)
                except ValueError:
                    print(f"[!] 无效CDN条目: {line}")
    return ranges

# 判断IP是否属于CDN
def is_cdn_ip(ip, cdn_ranges):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in cdn_ranges)
    except ValueError:
        return False

# ------------------------------------
# 多进程解析JSON块，增加  信息收集
def parse_json_lines_chunk(lines_chunk, cdn_ranges, existing_cdn_dyn_ips, filter_domains):
    domain_ip_map = defaultdict(set)
    url_title_list = []
    url_root_map = {}
    url_body_info_map = {}
    filtered_non_200_urls = []  # 新增，用于保存非200/301/302的url和状态码
    body_fqdn_filtered_set = set()
    body_domains_filtered_set = set()
    with open("config/wordlists/tlds.txt", "r", encoding="utf-8") as f:
        VALID_TLDS = set(line.strip().lower() for line in f if line.strip())
    seen_ips = set()
    for idx, line in enumerate(lines_chunk):
        try:
            item = json.loads(line)
            url = item.get("url", "").strip()

            title = item.get("title", "").strip()
            tls_info = item.get("tls", {})  
            cert = tls_info.get("subject_cn", "").strip()
            ico = item.get("favicon_md5", "").strip()
            ico_mmh3 = item.get("favicon", "").strip()
            hash_info = item.get("hash", {})
            bd_hash = hash_info.get("body_md5", "").strip()
            bd_mmh3 = hash_info.get("body_mmh3", "").strip()
            a_ips = item.get("a", [])

            try:
                parsed_url = urlparse(url)
                hostname = parsed_url.hostname
                # 判断是否是IP
                ipaddress.ip_address(hostname)
                root_domain = hostname  # 直接用 IP
            except ValueError:
                try:
                    root_domain = get_fld(url, fix_protocol=False).lower()
                except Exception as e:
                    if DEBUG_FSCAN:
                        print(f"[!] 提取主域名失败: {url} 错误: {e}")
                    continue
            url_root_map[url] = root_domain
            status_code = item.get("status_code")  # 确认实际字段
            if status_code is None:
                status_code = 0  # 或者默认一个值，防止报错
            # 特殊状态码单独处理
            if status_code in (403, 404):
                filtered_non_200_urls.append((url, status_code))
                continue  # 跳过正常流程，但记录特殊状态码
            elif status_code not in (200, 301, 302):
                # 其他非正常状态码也记录
                filtered_non_200_urls.append((url, status_code))
                continue  # 跳过后续正常流程
            url_title_list.append((url, title, cert, ico, bd_hash, tuple(sorted(a_ips)),ico_mmh3,bd_mmh3))

            for ip in a_ips:
                if is_cdn_ip(ip, cdn_ranges):
                    continue
                if ip in existing_cdn_dyn_ips:
                    continue
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)
                domain_ip_map[root_domain].add(ip)
            body_fqdn_list = item.get("body_fqdn", [])
            body_domains_list = item.get("body_domains", [])

            filtered_fqdn = []
            for fqdn in body_fqdn_list:
                if fqdn  and "cdn" not in fqdn and "img" not in fqdn:
                    try:
                        ext = tldextract.extract(fqdn)
                        if ext.domain and ext.suffix and ext.suffix.lower() in VALID_TLDS:
                            root_domain = f"{ext.domain}.{ext.suffix}".lower()
                            if root_domain not in filter_domains and root_domain not in new_filtered_domains:
                                if is_domain_resolvable(root_domain):
                                    filtered_fqdn.append(fqdn.lower())
                                    new_filtered_domains.add(root_domain)

                    except Exception:
                        pass

            filtered_domains = []
            for domain in body_domains_list:
                if domain  and "cdn" not in domain and "img" not in domain:
                    try:
                        ext = tldextract.extract(domain)
                        if ext.domain and ext.suffix and ext.suffix.lower() in VALID_TLDS:
                            root_domain = f"{ext.domain}.{ext.suffix}".lower()
                            if root_domain not in filter_domains and root_domain not in new_filtered_domains:
                                if is_domain_resolvable(root_domain):
                                    filtered_domains.append(domain.lower())
                                    new_filtered_domains.add(root_domain)

                    except Exception:
                        pass

            # 保存结果
            url_body_info_map[url] = {
                "body_fqdn": filtered_fqdn,
                "body_domains": filtered_domains
            }
            if new_filtered_domains:
                with open(DYNAMIC_FILTER_FILE, "a", encoding="utf-8") as f:
                    for dom in sorted(new_filtered_domains):
                        f.write(dom + "\n")

        except Exception as e:
            if DEBUG_FSCAN:
                print(f"[!] JSON解析异常 (第 {idx} 行): {e}")
            continue

    return domain_ip_map, url_title_list, url_root_map,url_body_info_map,filtered_non_200_urls

def chunked_iterable(iterable, size):
    """按size切分迭代器成小块"""
    it = iter(iterable)
    while True:
        chunk = list(islice(it, size))
        if not chunk:
            break
        yield chunk

# ------------------------------------
# 封装：确保 base_info 文件存在（如无则反查并写入）
async def ensure_base_info(root, report_path, valid_ips, urls, titles, filter_domains, existing_cdn_dyn_ips, url_body_info_map, folder):
    base_info_files = list(report_path.glob(f"base_info_{root}.txt"))

    if base_info_files:
        print(f"[i] base_info 文件存在，跳过写入 base_info")
        return None  # 已有文件，不需要反查
    else:
        print(f"[i] base_info 文件不存在，开始反查并写入 base_info")
        ip_domain_map = await resolve_and_filter_domains(valid_ips, filter_domains, existing_cdn_dyn_ips, folder)
        print("[✓] 完成反查域名")
        print(ip_domain_map)
        await write_base_report(root, report_path, valid_ips, urls, titles, ip_domain_map, url_body_info_map)
        return ip_domain_map
async def per_domain_flow_sync_async(root, ips, urls, titles, cdn_ranges, filter_domains, existing_cdn_dyn_ips, url_body_info_map):
    print(f"\n[>] 执行域名流程: {root}")
    folder = prepare_domain_folder(root)
    valid_ips = write_valid_ips(folder, ips, cdn_ranges, existing_cdn_dyn_ips)
    write_urls(folder, urls)
    mark_classification_complete(folder)

    # 报告目录设置
    base_report_root = Path("output/reports/scan")
    standard_dir = base_report_root / root
    finish_dir = base_report_root / f"{root}_finish"
    exp_dir = base_report_root / f"{root}_vul"

    if finish_dir.exists():
        print(f"[i] 发现已有完成报告目录: {finish_dir}")
        return  # 已完成，跳过处理
    elif exp_dir.exists():
        report_path = exp_dir
        print(f"[i] 发现已有漏洞报告目录: {report_path}")
    elif standard_dir.exists():
        report_path = standard_dir
        print(f"[i] 使用已有扫描中目录: {report_path}")
    else:
        report_path = standard_dir
        report_path.mkdir(parents=True, exist_ok=True)
        print(f"[+] 创建新报告目录: {report_path}")

    # 获取目录下已有文件
    files = list(report_path.iterdir())

    if not files:
        print(f"[+] 报告目录为空，开始正常扫描")
        print(f"[*] 有效IP列表: {valid_ips}")
        print(f"当前域名: {root}")

        ip_domain_map,cdn_ip_to_remove = await resolve_and_filter_domains(valid_ips, filter_domains, existing_cdn_dyn_ips, folder)
        print("[✓] 完成反查域名")
        valid_ips = [ip for ip in valid_ips if ip not in cdn_ip_to_remove]

        await write_base_report(root, report_path, valid_ips, urls, titles, ip_domain_map, url_body_info_map)
        await write_representative_urls(folder, titles, urls)
        if not ONLY_DOMAIN_MODE:
            await run_security_scans(root, folder, report_path)

    else:
        ip_domain_map = await ensure_base_info(
            root, report_path, valid_ips, urls, titles,
            filter_domains, existing_cdn_dyn_ips, url_body_info_map, folder
        )

        base_info_files = list(report_path.glob(f"base_info_{root}.txt"))

        has_scan_done = any(f.name == "扫描完成.txt" for f in files)
        if base_info_files and has_scan_done:
            print(f"[✓] 目标 {root} 已完成扫描（存在 base_info 和 扫描完成.txt），跳过。")
            return

        elif base_info_files:
            print(f"[+] 只有 base_info 文件，准备处理")

            if ONLY_DOMAIN_MODE:
                print(f"[i] 跳过 run_security_scans，因启用了 --test")
                return

            await run_security_scans(root, folder, report_path)


def prepare_domain_folder(root):
    folder = Path("output/domains") / root
    folder.mkdir(parents=True, exist_ok=True)
    print(f"[✓] 创建域名目录: {folder}")
    return folder
def natural_sort_key(s):
    # 分割字符串，数字转int，字母小写
    return [int(text) if text.isdigit() else text.lower() for text in re.split(r'(\d+)', s)]

def write_valid_ips(folder, ips, cdn_ranges, existing_cdn_dyn_ips):
    valid_ips = []

    # 先读取 all_a_records.txt（如果存在）里的历史 IP
    all_a_records_path = folder / "all_a_records.txt"
    if all_a_records_path.exists():
        with open(all_a_records_path, "r") as f:
            existing_all_ips = set(line.strip() for line in f if line.strip())
    else:
        existing_all_ips = set()

    with open(folder / "a_records.txt", "w") as a, open(all_a_records_path, "a") as all_a:
        for ip in sorted(ips):
            if is_cdn_ip(ip, cdn_ranges) or ip in existing_cdn_dyn_ips:
                print(f"[-] CDN跳过: {ip}")
                continue
            if ip in existing_all_ips:
                print(f"[!] 已存在于 all_a_records.txt 中，跳过: {ip}")
                continue
            a.write(ip + "\n")
            all_a.write(ip + "\n")
            valid_ips.append(ip)

    return valid_ips


def write_urls(folder, urls):
    with open(folder / "urls.txt", "w") as u:
        for url in urls:
            u.write(url + "\n")


def mark_classification_complete(folder):
    try:
        with open(folder / "finish.txt", "w", encoding="utf-8") as f:
            f.write("分类完成")
        print(f"[✓] 标记分类完成: {folder}/finish.txt")
    except Exception as e:
        print(f"[!] 写入 finish.txt 失败: {e}")


def create_report_folder(root):
    report_folder = Path("output/reports/scan") / root
    report_folder.mkdir(parents=True, exist_ok=True)
    print(f"[✓] 创建报告目录: {report_folder}")
    return report_folder

def update_a_records_after_scan(cdn_ip_to_remove, a_record_file):
    path = a_record_file / "a_records.txt"
    if not path.exists():
        print(f"[!] 未找到文件: {a_record_file}")
        return

    with open(path, "r") as f:
        lines = f.readlines()

    new_lines = [line for line in lines if line.strip() not in cdn_ip_to_remove]

    with open(path, "w") as f:
        f.writelines(new_lines)

    print(f"[✓] 已从 a_records.txt 中移除 {cdn_ip_to_remove} ")


CDN_KEYWORDS = [
    "cloudfront.net", "r.cloudfront.net",
    "cloudflare.com", "cloudflare.net",
    "akamai", "akamaiedge.net", "akamaized.net", "akamaitechnologies.com",
    "fastly.net", "fastlylb.net",
    "googleusercontent.com", ".gws",
    "dnsv1.com", "tcdn.qq.com",
    "baidubce.com",
    "alicdn.com", "aliyun.com",
    "wscdns.com", "wscloudcdn.com",
    "edgecastcdn.net",
    "cdnetworks.net", "cdngc.net",
    "incapdns.net", "impervadns.net"
]

def is_cdn_domain(domain: str) -> bool:
    return any(keyword in domain.lower() for keyword in CDN_KEYWORDS)
def is_cdn_ip_new(ip, domains):
    # print(f"[+] 判断IP: {ip} 是否是CDN节点")
    
    # 条件1：域名数量过多，直接判定为CDN
    if len(domains) > 45:
        print(f"[-] 域名数量大于45), 直接判定为CDN")
        return True

    # 随机选一个域名做测试
    test_domain = random.choice(domains)
    # print(f"[+] 选取的测试域名: {test_domain}")

    try:
        # 正向解析：域名 -> IP列表
        ips = socket.gethostbyname_ex(test_domain)[2]
        # print(f"[+] 正向解析 {test_domain} 得到IP列表: {ips}")
        
        if ip not in ips:
            # print(f"[-] 目标IP {ip} 不在域名解析的IP列表中，判定为CDN")
            return True

        if len(ips) > 4:
            # print(f"[-] 正向解析IP列表数量超过4 ({len(ips)}), 判定为CDN")
            return True

    except Exception as e:
        # print(f"[-] 解析异常: {e}，判定为CDN")
        return True

    print(f"[+] 通过所有判断 {ip} 非CDN节点")
    return False

async def resolve_and_filter_domains(valid_ips, filter_domains, existing_cdn_dyn_ips, folder):
    global reverse_lookup_semaphore
    if reverse_lookup_semaphore is None:
        reverse_lookup_semaphore = asyncio.Semaphore(3)  # 限制并发反查数量
    
    ip_domain_map = defaultdict(list)
    cdn_ip_to_remove = set()
    
    # 使用异步并发处理反查
    async def process_ip(ip):
        async with reverse_lookup_semaphore:
            return await reverse_lookup_ip_async(ip)
    
    # 并发执行所有IP反查
    tasks = [process_ip(ip) for ip in valid_ips]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"[!] IP {valid_ips[i]} 反查失败: {result}")
            continue
        
        ip_, domains = result
        if not domains:
            print(f"[!] {ip_} 反查无结果")
            continue

        if is_cdn_ip_new(ip_, domains):
            print(f"[!] {ip_} 识别为CDN IP，移除")
            cdn_ip_to_remove.add(ip_)
        else:
            ip_domain_map[ip_].extend(domains)

        is_cdn = False
        for d in domains:
            try:
                if isinstance(d, list):  # 修复点
                    d = d[0]
                domain_line = d.strip()
                match = re.search(r'([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', domain_line)
                if not match:
                    continue

                domain = match.group(0)

                if is_cdn_domain(domain):
                    print(f"[!] CDN 域名 {domain}，标记 CDN IP: {ip_}")
                    cdn_ip_to_remove.add(ip_)
                    is_cdn = True
                    break

                # 提取主域并判断是否被过滤
                ext = tldextract.extract(domain)
                root_domain = f"{ext.domain}.{ext.suffix}"
                if not any(fd in root_domain for fd in filter_domains):
                    ip_domain_map[ip_].append(domain)

            except Exception as e:
                if DEBUG_FSCAN:
                    print(f"[!] 域名字符串处理异常: {e}")

        if is_cdn:
            continue  # 避免记录任何域名
    # ✅ 写入 CDN IP 并更新 a_records
    new_cdn_ips = cdn_ip_to_remove - existing_cdn_dyn_ips
    if new_cdn_ips:
        with open(CDN_DYNAMIC_PATH, "a", encoding="utf-8") as f:
            for ip in new_cdn_ips:
                f.write(f"{ip}\n")
        existing_cdn_dyn_ips.update(new_cdn_ips)
        update_a_records_after_scan(cdn_ip_to_remove, folder)

    return ip_domain_map, cdn_ip_to_remove

def extract_root_domain(domain):
    ext = tldextract.extract(domain)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain
async def query_platform_by_hash(hash_value, platform="fofa", hash_type="icon_hash", size=100, proxies=None):
    """
    通用 hash/title 查询接口，支持 FOFA / Hunter，返回域名列表。
    :param hash_value: hash 值（icon_hash / body_hash）或标题内容
    :param platform: 平台标识 "fofa" / "hunter"
    :param hash_type: 查询类型 icon_hash / body_hash / cert / title (FOFA) 或 web.icon / web.title (Hunter)
    :param size: 最大返回数量（fofa 用，hunter 固定一页 100）
    :param proxies: 代理 URL 字符串，例如 "socks5h://127.0.0.1:7891" 或 "http://127.0.0.1:7890"
    """
    assert platform in {"fofa", "hunter"}, "platform 必须是 'fofa' 或 'hunter'"

    if platform == "fofa":
        query = f'{hash_type}="{hash_value}"'
        qbase64 = base64.b64encode(query.encode()).decode()
        url = (
            f"https://fofa.info/api/v1/search/all?"
            f"email={TEST_EMAIL}&key={TEST_KEY}&qbase64={qbase64}"
            f"&size={size}&fields=host"
        )

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url)
                r.raise_for_status()
                data = r.json()

                if data.get("error") is False:
                    results = data.get("results", [])
                    if not results:
                        # print(f"[!] FOFA 空结果: {hash_type}={hash_value}")
                        return []
                    first_item = results[0]
                    if isinstance(first_item, list):
                        return list(set(row[0] for row in results if row))
                    elif isinstance(first_item, str):
                        return list(set(results))
                    else:
                        print(f"[!] FOFA 未知结果格式: {type(first_item)}")
                        return []
                else:
                    print(f"[!] FOFA 错误: {data.get('errmsg')}")
                    return []

        except Exception as e:
            print(f"[!] 查询失败 (fofa): {e}")
            return []

    else:  # Hunter 查询
        if hash_type == "title":
            query = f'web.title="{hash_value}"'
        else:
            query = f'web.icon="{hash_value}"'
        start_time = time.strftime("%Y-%m-%d", time.localtime(time.time() - 30*24*3600))
        end_time = time.strftime("%Y-%m-%d", time.localtime())
        url = (
            f"https://hunter.qianxin.com/openApi/search?"
            f"api-key={HUNTER_API_KEY}&search={query}&start_time={start_time}&end_time={end_time}"
            f"&page=1&page_size=100&is_web=3"
        )

        try:
            async with httpx.AsyncClient(timeout=10, proxy=proxies) as client:
                r = await client.get(url)
                r.raise_for_status()
                data = r.json()

                if data.get("code") != 200:
                    print(f"[!] Hunter 错误: {data.get('message')}")
                    return []

                results = data.get("data", {}).get("arr", [])
                return list({r.get("domain") for r in results if r.get("domain")})

        except Exception as e:
            print(f"[!] 查询失败 (hunter): {e}")
            return []
def is_ip(string):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", string) is not None
def clean_line(line):
    return line.strip().strip('"').strip("'").lower()

async def read_lines_from_file(filepath):
    lines = set()
    if os.path.exists(filepath):
        async with aiofiles.open(filepath, mode='r') as f:
            async for line in f:
                line = clean_line(line)
                if line:
                    lines.add(line)
    return lines
async def write_lines_to_file(filepath, lines):
    if not lines:
        return
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    async with aiofiles.open(filepath, mode='a') as f:
        for line in sorted(lines):
            await f.write(line + '\n')
def parse_url(line):
    line = clean_line(line)
    if not line:
        return None, None
    if line.startswith('http://') or line.startswith('https://'):
        parsed = urlparse(line)
        hostname = parsed.hostname
        return line, hostname
    else:
        return None, line  # treat as domain or IP
def strip_url_scheme(url: str) -> str:
    """去掉 http:// 或 https://，只返回 host"""
    url = url.strip()
    if url.startswith("http://") or url.startswith("https://"):
        parsed = urlparse(url)
        return parsed.hostname or url  # fallback
    return url

async def merge_all_expanded_results(report_folder: str, root_domain: str):
    tuozhan_path = os.path.join(report_folder, "tuozhan")
    all_dir = os.path.join(tuozhan_path, "all_tuozhan")
    os.makedirs(all_dir, exist_ok=True)

    existing_report_folder = f"./domains/{root_domain}"
    existing_urls_raw = await read_lines_from_file(os.path.join(existing_report_folder, "urls.txt"))
    existing_urls_hosts = {strip_url_scheme(u) for u in existing_urls_raw}

    a_record_path = f"{existing_report_folder}/a_records.txt"
    existing_ips = await read_lines_from_file(a_record_path)

    # 保存来源映射: {来源: set(域名/IP)}
    source_host_map = defaultdict(set)

    # ✅ 1. 处理 fofa 子目录下所有 txt 文件
    for subfolder in ["fofa"]:
        full_path = os.path.join(tuozhan_path, subfolder)
        if not os.path.exists(full_path):
            continue

        for fname in os.listdir(full_path):
            if not fname.endswith(".txt"):
                continue

            file_path = os.path.join(full_path, fname)
            current_source = None
            domains = []

            async with aiofiles.open(file_path, mode='r') as f:
                async for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("# 来源:"):
                        current_source = line.replace("# 来源:", "").strip()
                        continue
                    domain = clean_line(line)
                    if not domain:
                        continue
                    host = strip_url_scheme(domain)
                    if not host:
                        continue

                    if is_ip(host):
                        if host not in existing_ips:
                            source_host_map[current_source].add(host)
                    else:
                        if host not in existing_urls_hosts:
                            source_host_map[current_source].add(host)

    # ✅ 2. 合并 root domains
    merged_roots = set()
    ip_re_path = os.path.join(tuozhan_path, "ip_re", "ip_domain_summary.txt")
    if os.path.exists(ip_re_path):
        async with aiofiles.open(ip_re_path, mode='r') as f:
            async for line in f:
                domain = clean_line(line)
                if not domain or is_ip(domain):
                    continue
                root = extract_root_domain(domain)
                if root and root not in existing_urls_hosts:
                    merged_roots.add(root)

    # ✅ 3. 写入 urls.txt，按来源分块组织，跳过无内容的来源
    urls_txt_path = os.path.join(all_dir, "urls.txt")
    async with aiofiles.open(urls_txt_path, "w") as f:
        for source, hosts in sorted(source_host_map.items()):
            if not hosts:
                continue
            await f.write(f"# 来源: {source}\n")
            for host in sorted(hosts):
                await f.write(f"{host}\n")

    # ✅ 写入 IP、root_domain（保持旧逻辑）
    merged_ips = set()
    for hosts in source_host_map.values():
        for h in hosts:
            if is_ip(h):
                merged_ips.add(h)

    await write_lines_to_file(os.path.join(all_dir, "ip.txt"), merged_ips)
    await write_lines_to_file(os.path.join(all_dir, "root_domains.txt"), merged_roots)

async def load_fofa_query_blacklist() -> set[str]:
    try:
        async with aiofiles.open(BLACKLIST_FILE_PATH, mode='r') as f:
            content = await f.read()
        return set(line.strip() for line in content.splitlines() if line.strip())
    except FileNotFoundError:
        return set()

async def save_fofa_query_blacklist(blacklist: set[str]):
    os.makedirs(os.path.dirname(BLACKLIST_FILE_PATH), exist_ok=True)
    async with aiofiles.open(BLACKLIST_FILE_PATH, mode='w') as f:
        for item in sorted(blacklist):
            await f.write(f"{item}\n")

async def write_expanded_reports(report_folder, ico_mmh3_set=None, body_mmh3_set=None, domain_list=None, use_hunter=False, hunter_proxies=None, hunter_ico_md5_list=None, cert_root_domains=None, cert_root_domain_map=None, ico_md5_url_map=None, ico_mmh3_url_map=None, body_md5_url_map=None, body_mmh3_url_map=None, title_set=None, title_url_map=None, enable_fofa: bool = True):

    tuozhan_dir = Path(report_folder) / "tuozhan"
    fofa_dir = tuozhan_dir / "fofa"
    ip_re_dir = tuozhan_dir / "ip_re"
    all_tuozhan_dir = tuozhan_dir / "all_tuozhan"
    tuozhan_dir.mkdir(parents=True, exist_ok=True)
    fofa_dir.mkdir(parents=True, exist_ok=True)
    ip_re_dir.mkdir(parents=True, exist_ok=True)
    all_tuozhan_dir.mkdir(parents=True, exist_ok=True)
    updated_blacklist = set()
    fofa_blacklist = await load_fofa_query_blacklist()

    if use_hunter:
        hunter_dir = tuozhan_dir / "hunter"
        hunter_dir.mkdir(parents=True, exist_ok=True)

    if ico_mmh3_set:
        for hash_value in sorted(ico_mmh3_set):
            if use_hunter:
                if not hunter_ico_md5_list:
                    print(f"[!] Hunter 查询需要传入 ico md5 列表，当前为空，跳过 icon_hash={hash_value}")
                    continue
                for md5_hash in hunter_ico_md5_list:
                    print(f"[+] 查询 HUNTER icon md5={md5_hash}")
                    try:
                        domains = await query_platform_by_hash(
                            md5_hash,
                            platform="hunter",
                            hash_type="icon_md5",
                            proxies=hunter_proxies
                        )
                        updated_blacklist.add(md5_hash)
                    except Exception as e:
                        print(f"[!] Hunter 查询失败: {e}")
                        continue
                    if not domains:
                        continue
                    file_path = hunter_dir / f"icon_md5_hunter_{md5_hash}.txt"
                    with open(file_path, "w", encoding="utf-8") as f:
                        if ico_md5_url_map and md5_hash in ico_md5_url_map:
                            for src in sorted(ico_md5_url_map[md5_hash]):
                                f.write(f"# 来源: {src}\n")
                        for domain in domains:
                            f.write(f"{domain}\n")
            else:
                if enable_fofa:
                    if hash_value in fofa_blacklist:
                        print(f"[!] 跳过 FOFA 查询 (黑名单): icon_hash={hash_value}")
                        continue
                    print(f"[+] 查询 FOFA icon_hash={hash_value}")
                    try:
                        domains = await query_platform_by_hash(
                            hash_value,
                            platform="fofa",
                            hash_type="icon_hash"
                        )
                        updated_blacklist.add(hash_value)
                    except Exception as e:
                        print(f"[!] FOFA 查询失败: {e}")
                        continue
                    if not domains:
                        continue
                    file_path = fofa_dir / f"icon_hash_{hash_value}.txt"
                    with open(file_path, "w", encoding="utf-8") as f:
                        if ico_mmh3_url_map and hash_value in ico_mmh3_url_map:
                            for src in sorted(ico_mmh3_url_map[hash_value]):
                                f.write(f"# 来源: {src}\n")
                        for domain in domains:
                            f.write(f"{domain}\n")

    if body_mmh3_set and enable_fofa:
        for hash_value in sorted(body_mmh3_set):
            if hash_value in fofa_blacklist:
                print(f"[!] 跳过 FOFA 查询 (黑名单): body_hash={hash_value}")
                continue
            print(f"[+] 查询 FOFA body_hash={hash_value}")
            try:
                domains = await query_platform_by_hash(
                    hash_value,
                    platform="fofa",
                    hash_type="body_hash"
                )
                updated_blacklist.add(hash_value)
            except Exception as e:
                print(f"[!] FOFA 查询失败: {e}")
                continue
            if not domains:
                continue
            file_path = fofa_dir / f"body_hash_{hash_value}.txt"
            with open(file_path, "w", encoding="utf-8") as f:
                if body_mmh3_url_map and hash_value in body_mmh3_url_map:
                    for src in sorted(body_mmh3_url_map[hash_value]):
                        f.write(f"# 来源: {src}\n")
                for domain in domains:
                    f.write(f"{domain}\n")

    if cert_root_domains and enable_fofa:
        for domain in sorted(cert_root_domains):
            if domain in fofa_blacklist:
                print(f"[!] 跳过 FOFA 查询 (黑名单): cert={domain}")
                continue
            print(f"[+] 查询 FOFA cert={domain}")
            try:
                domains = await query_platform_by_hash(
                    domain,
                    platform="fofa",
                    hash_type="cert"
                )
                updated_blacklist.add(domain)
            except Exception as e:
                print(f"[!] FOFA 查询失败: cert={domain} 错误: {e}")
                continue
            if not domains:
                continue
            file_path = fofa_dir / f"cert_{domain}.txt"
            with open(file_path, "w", encoding="utf-8") as f:
                if cert_root_domain_map and domain in cert_root_domain_map:
                    for src in sorted(cert_root_domain_map[domain]):
                        f.write(f"# 来源: {src}\n")
                for d in domains:
                    f.write(f"{d}\n")

    # 添加标题搜索功能
    if title_set and enable_fofa:
        for title in sorted(title_set):
            if title in fofa_blacklist:
                print(f"[!] 跳过 FOFA 查询 (黑名单): title={title}")
                continue
            print(f"[+] 查询 FOFA title={title}")
            try:
                domains = await query_platform_by_hash(
                    title,
                    platform="fofa",
                    hash_type="title"
                )
                updated_blacklist.add(title)
            except Exception as e:
                print(f"[!] FOFA 查询失败: title={title} 错误: {e}")
                continue
            if not domains:
                continue
            file_path = fofa_dir / f"title_{title[:50]}.txt"  # 限制文件名长度
            with open(file_path, "w", encoding="utf-8") as f:
                if title_url_map and title in title_url_map:
                    for src in sorted(title_url_map[title]):
                        f.write(f"# 来源: {src}\n")
                for domain in domains:
                    f.write(f"{domain}\n")

    # Hunter 标题搜索
    if use_hunter and title_set:
        hunter_dir = tuozhan_dir / "hunter"
        hunter_dir.mkdir(parents=True, exist_ok=True)
        
        for title in sorted(title_set):
            print(f"[+] 查询 HUNTER title={title}")
            try:
                domains = await query_platform_by_hash(
                    title,
                    platform="hunter",
                    hash_type="title",
                    proxies=hunter_proxies
                )
                updated_blacklist.add(title)
            except Exception as e:
                print(f"[!] Hunter 查询失败: title={title} 错误: {e}")
                continue
            if not domains:
                continue
            file_path = hunter_dir / f"title_hunter_{title[:50]}.txt"
            with open(file_path, "w", encoding="utf-8") as f:
                if title_url_map and title in title_url_map:
                    for src in sorted(title_url_map[title]):
                        f.write(f"# 来源: {src}\n")
                for domain in domains:
                    f.write(f"{domain}\n")

    if domain_list:
        root_domains = {extract_root_domain(d) for d in domain_list if d}
        if root_domains:
            out_file = ip_re_dir / "ip_domain_summary.txt"
            with open(out_file, "w", encoding="utf-8") as f:
                for domain in sorted(root_domains):
                    f.write(f"{domain}\n")

    print("[+] 完成查询,开始汇总写入文件")
    await save_fofa_query_blacklist(fofa_blacklist.union(updated_blacklist))



async def write_base_report(root: str, report_folder: Path, valid_ips: set[str], urls: list[str], titles: dict, ip_domain_map: dict[str, list[str]], url_body_info_map: dict[str, dict]):

    all_icos = set()
    all_body_hashes = set()
    all_certs = set()
    all_icos_mmh3 = set()
    all_body_mmh3 = set()
    all_reverse_domains = []
    all_titles = set()

    ico_md5_url_map = defaultdict(set)
    ico_mmh3_url_map = defaultdict(set)
    body_md5_url_map = defaultdict(set)
    body_mmh3_url_map = defaultdict(set)
    cert_root_url_map = defaultdict(set)
    title_url_map = defaultdict(set)

    repeat_map = defaultdict(list)

    indent1 = "  "
    indent2 = "    "

    out_path = report_folder / f"base_info_{root}.txt"
    with open(out_path, "w", encoding="utf-8") as out:
        out.write(f"{'='*30}\n[基础信息汇总] 域名: {root}\n{'='*30}\n")

        # === 1. 关联IP ===
        out.write("关联真实IP:\n")
        for ip in sorted(valid_ips):
            out.write(f"{indent1}- {ip}\n")

        # === 2. URL 标题信息 & hash 分类 ===
        out.write("\nURL和标题:\n")
        for url in urls:
            title, cert, ico, body_hash, url_ips, ico_mmh3, bd_mmh3 = titles.get(url, ("", "", "", "", (), "", ""))
            key = (body_hash, cert, ",".join(sorted(url_ips)), ico, ico_mmh3, bd_mmh3)
            repeat_map[key].append((url, title, cert, ico, body_hash, ico_mmh3, bd_mmh3))

        for url_list in repeat_map.values():
            for i, (url, title, cert, ico, body_hash, ico_mmh3, bd_mmh3) in enumerate(url_list):
                if i > 0:
                    continue
                out.write(f"{indent1}- {url} [{title}]\n")
                if ico:
                    all_icos.add(ico)
                    ico_md5_url_map[ico].add(url)
                if body_hash:
                    all_body_hashes.add(body_hash)
                    body_md5_url_map[body_hash].add(url)
                if ico_mmh3:
                    all_icos_mmh3.add(ico_mmh3)
                    ico_mmh3_url_map[ico_mmh3].add(url)
                if bd_mmh3:
                    all_body_mmh3.add(bd_mmh3)
                    body_mmh3_url_map[bd_mmh3].add(url)
                if cert and cert.strip():
                    root_domain = extract_root_domain(cert.strip("*."))  # <-- 需确保此函数存在
                    if root_domain:
                        all_certs.add(cert)
                        cert_root_url_map[root_domain].add(url)
                if title and title.strip() and title not in black_titles:
                    all_titles.add(title.strip())
                    title_url_map[title.strip()].add(url)

        # === 3. IP反查域名 ===
        out.write("\nIP反查域名:\n")
        for ip in sorted(valid_ips):
            if ip in ip_domain_map:
                out.write(f"{indent1}[IP] {ip}\n")
                for domain in ip_domain_map[ip]:
                    all_reverse_domains.append(domain)
                    out.write(f"{indent2}- {domain}\n")

        # === 4. URL body info 中抽取的域名 ===
        urls_for_root = [url for url in urls if url_body_info_map.get(url)]
        if urls_for_root:
            out.write(f"\n[URL BODY INFO - 域名(目前需要手动筛选): {root}]\n")
            url_domains_seen = {urlparse(url).hostname for url in urls_for_root if urlparse(url).hostname}
            domain_source_map = defaultdict(set)
            for url in urls_for_root:
                info = url_body_info_map.get(url, {})
                for d in info.get("body_fqdn", []) + info.get("body_domains", []):
                    if d not in url_domains_seen:
                        domain_source_map[d].add(url)

            for domain, source_urls in domain_source_map.items():
                if len(source_urls) == 1:
                    out.write(f"{indent1}{domain} [来源: {next(iter(source_urls))}]\n")
                else:
                    out.write(f"{indent1}{domain} [来源数量: {len(source_urls)}]\n")

        # === 5. hash / cert 汇总 ===
        out.write(f"\n{'='*30}\n资源汇总:\n{'='*30}\n")
        out.write("\n证书主域名:\n")
        for cert_domain in sorted(cert_root_url_map.keys()):
            out.write(f"{indent1}{cert_domain}\n")
        out.write("ico:\n")
        out.write(f"{indent1}md5:\n")
        for ico in sorted(all_icos):
            out.write(f"{indent2}{ico}\n")
        out.write(f"{indent1}mmh3_hash:\n")
        for h in sorted(all_icos_mmh3):
            out.write(f"{indent2}{h}\n")

        out.write("\nbody_hash:\n")
        out.write(f"{indent1}md5:\n")
        for h in sorted(all_body_hashes):
            out.write(f"{indent2}{h}\n")
        out.write(f"{indent1}mmh3_hash:\n")
        for h in sorted(all_body_mmh3):
            out.write(f"{indent2}{h}\n")



        out.write("\nasn信息(暂未实现):\n")

        # === 6. 重复页面聚类 ===
        out.write(f"\n{'='*30}\n重复网站:\n{'='*30}\n\n")
        indent3 = indent2 * 2
        for key, url_infos in repeat_map.items():
            if len(url_infos) > 1:
                main_url, main_title, *_ = url_infos[0]
                out.write(f"{indent1}- 重复于: {main_url}  标题: {main_title}\n")
                for url, title, *_ in url_infos:
                    out.write(f"{indent2}- {url}\n")
                    out.write(f"{indent3}标题: {title}\n")

    # === 7. 写入扩展查询结果（FOFA / hunter）===
    if all_reverse_domains or all_icos_mmh3 or all_body_mmh3 or cert_root_url_map or all_titles:
        await write_expanded_reports(
            report_folder=report_folder,
            ico_mmh3_set=all_icos_mmh3,
            body_mmh3_set=all_body_mmh3,
            domain_list=all_reverse_domains,
            use_hunter=False,
            hunter_proxies=None,
            hunter_ico_md5_list=all_icos,
            cert_root_domains=set(cert_root_url_map.keys()),
            cert_root_domain_map=cert_root_url_map,
            ico_md5_url_map=ico_md5_url_map,
            ico_mmh3_url_map=ico_mmh3_url_map,
            body_md5_url_map=body_md5_url_map,
            body_mmh3_url_map=body_mmh3_url_map,
            title_set=all_titles,
            title_url_map=title_url_map,
            enable_fofa=False

        )

        # === 8. 汇总 merge 报告 ===
        await merge_all_expanded_results(report_folder, root)


async def write_representative_urls(folder, titles, urls):
    repeat_map = defaultdict(list)
    for url in urls:
        title, cert, ico, body_hash, url_ips, ico_mmh3, bd_mmh3 = titles.get(url, ("", "", "", "", ()))
        a_str = ",".join(sorted(url_ips))
        key = (body_hash, cert, a_str, ico)
        repeat_map[key].append((url, title, cert, ico, body_hash, ico_mmh3, bd_mmh3))

    path = folder / "representative_urls.txt"
    with open(path, "w", encoding="utf-8") as f:
        for url_list in repeat_map.values():
            if url_list:
                url, title, *_ = url_list[0]
                if title in black_titles:
                    continue
                f.write(url + "\n")


async def run_security_scans(root, folder, report_folder):
    afrog_report = report_folder / f"afrog_report_{root}.json"
    fscan_report = report_folder / f"fscan_result_{root}.txt"
    afrog_target_file = folder / "representative_urls.txt"
    fscan_target_file = folder / "a_records.txt"
    if not afrog_target_file.exists() or os.path.getsize(afrog_target_file) == 0:
        empty_file = report_folder / "afrog目标为空.txt"
        empty_file.touch()  # 创建空文件
        print(f"[!] {afrog_target_file} 为空，已创建 {empty_file}，跳过afrog扫描")
    else:
        afrog_cmd = AFROG_CMD_TEMPLATE.format(target_file=str(afrog_target_file), output_file=str(afrog_report))
        result = await run_cmd_async(afrog_cmd)
        if result is None:
            print(f"[!] afrog扫描失败，跳过")
            return

    if not fscan_target_file.exists() or os.path.getsize(fscan_target_file) == 0:
        empty_file = report_folder / "fscan目标为空.txt"
        empty_file.touch()
        print(f"[!] {fscan_target_file} 为空，已创建 {empty_file}，跳过fscan扫描")
    else:
        fscan_cmd = FSCAN_CMD_TEMPLATE.format(target_file=str(fscan_target_file), output_file=str(fscan_report))
        result = await run_cmd_async(fscan_cmd)
        if result is None:
            print(f"[!] fscan扫描失败，跳过")
            return
    await finalize_report_directory(report_folder, root)


async def finalize_report_directory(report_folder, root):
    afrog_report = report_folder / f"afrog_report_{root}.json"
    
    # 检查afrog报告是否存在且有漏洞内容
    has_vulns = False
    if afrog_report.exists():
        try:
            with open(afrog_report, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content and content != "[]":  # 不是空数组
                    has_vulns = True
                    print(f"[+] 检测到afrog漏洞报告: {afrog_report}")
        except Exception as e:
            print(f"[!] 读取afrog报告失败: {e}")
    
    new_folder = report_folder.parent / (f"{root}_vul" if has_vulns else f"{root}_finish")

    # 如果新旧路径一致，则跳过
    if str(report_folder.resolve()) == str(new_folder.resolve()):
        print(f"[i] 当前目录名已是目标名，无需重命名: {report_folder}")
        scan_done_path = report_folder / "扫描完成.txt"
        scan_done_path.write_text("扫描已完成", encoding="utf-8")
        return

    try:
        if new_folder.exists():
            shutil.rmtree(new_folder)
        report_folder.rename(new_folder)
        print(f"[+] 重命名目录: {report_folder} -> {new_folder}")

        # 重命名成功后写入扫描完成标志
        scan_done_path = new_folder / "扫描完成.txt"
        scan_done_path.write_text("扫描已完成", encoding="utf-8")

    except Exception as e:
        print(f"[!] 重命名目录失败: {e}")


def save_non_200_urls_by_domain(non_200_urls_all, url_root_map):
    # 处理特殊状态码：403, 404等
    status_folders = [403, 404, 500, 502, 503]  # 扩展关注的状态码
    # 按域名和状态码分组： {domain: {status_code: [urls]}}
    domain_status_urls = defaultdict(lambda: defaultdict(list))

    for url, status_code in non_200_urls_all:
        if status_code in status_folders:
            root_domain = url_root_map.get(url)
            if root_domain:
                domain_status_urls[root_domain][status_code].append(url)

    # 写入文件，按状态码分别保存
    for domain, status_dict in domain_status_urls.items():
        domain_folder = Path("output/domains") / domain
        domain_folder.mkdir(parents=True, exist_ok=True)
        for status_code, urls in status_dict.items():
            file_path = domain_folder / f"{status_code}_urls.txt"  # 动态文件名
            with open(file_path, "w", encoding="utf-8") as f:  # 改为w模式避免重复
                f.write(f"# {status_code}状态码URL列表 - {domain}\n")
                f.write(f"# 总计: {len(urls)} 个URL\n\n")
                for u in urls:
                    f.write(u + "\n")


# ------------------------------------
# 主程序入口
# ------------------------------------
# 主程序入口
def main():
    init_dirs()
    filter_domains = load_filter_domains(FILTER_DOMAIN_PATH)
    cdn_ranges = load_cdn_ranges(CDN_LIST_PATH)
    existing_cdn_dyn_ips = {line.strip() for line in open(CDN_DYNAMIC_PATH, encoding="utf-8")} if os.path.exists(CDN_DYNAMIC_PATH) else set()

    if not os.path.exists(RESULT_JSON_PATH):
        print("[X] 结果文件不存在")
        return

    with open(RESULT_JSON_PATH, "r", encoding="utf-8") as f:
        lines = f.readlines()

    print("[*] 开始多进程解析 JSON 记录...")
    cpu_count = min(multiprocessing.cpu_count(), 8)  # 限制最大进程数
    chunk_size = max(500, len(lines) // (cpu_count * 2))  # 动态调整chunk大小
    chunks = list(chunked_iterable(lines, chunk_size))
    
    print(f"[*] 使用 {cpu_count} 个进程，{len(chunks)} 个chunk，每个chunk约 {chunk_size} 行")

    worker = partial(parse_json_lines_chunk,
                     cdn_ranges=cdn_ranges,
                     existing_cdn_dyn_ips=existing_cdn_dyn_ips,
                     filter_domains=filter_domains)

    pool = multiprocessing.Pool(cpu_count)

    domain_ip_map = defaultdict(set)
    url_title_list = []
    url_root_map = {}
    url_body_info_map = {}  # ✅ 新增
    non_200_urls_all = []  # 新增，存储所有非200/301/302 url

    with tqdm(total=len(chunks), desc="处理记录") as pbar:
        for dmap, titles, urlmap, url_body_info, non_200_urls in pool.imap_unordered(worker, chunks):
            for k, v in dmap.items():
                domain_ip_map[k].update(v)
            url_title_list.extend(titles)
            url_root_map.update(urlmap)
            url_body_info_map.update(url_body_info)  # ✅ 合并过滤后数据
            non_200_urls_all.extend(non_200_urls)

            pbar.update(1)

    pool.close()
    pool.join()
    # 准备按域名分组 urls 和 titles
    domain_urls_map = defaultdict(set)
    domain_titles_map = {}
    for url, root_domain in url_root_map.items():
        domain_urls_map[root_domain].add(url)

    for url, title, cert, ico, body, url_ips,ico_mmh3,bd_mmh3 in url_title_list:
        domain_titles_map[url] = (title, cert, ico, body, url_ips,ico_mmh3,bd_mmh3)

    #403
    save_non_200_urls_by_domain(non_200_urls_all, url_root_map)


    
    # 异步任务放到 asyncio.run 中执行
    asyncio.run(run_domain_tasks(domain_ip_map, domain_urls_map, domain_titles_map, cdn_ranges, filter_domains, existing_cdn_dyn_ips, url_body_info_map))


async def run_domain_tasks(domain_ip_map, domain_urls_map, domain_titles_map, cdn_ranges, filter_domains, existing_cdn_dyn_ips, url_body_info_map):
    global SKIP_CURRENT_DOMAIN
    print("[*] 开始逐个执行域名流程...")
    sorted_domains = sorted(domain_urls_map.keys(), key=natural_sort_key)

    for domain in sorted_domains:
        if SKIP_CURRENT_DOMAIN:
            print(f"[!] 跳过域名: {domain}")
            SKIP_CURRENT_DOMAIN = False
            continue

        try:
            ips = domain_ip_map[domain]
            urls = sorted(domain_urls_map.get(domain, []))
            titles = {u: domain_titles_map.get(u, ("", "", "", "", ())) for u in urls}
            await per_domain_flow_sync_async(domain, ips, urls, titles, cdn_ranges, filter_domains, existing_cdn_dyn_ips, url_body_info_map)
        except asyncio.CancelledError:
            print(f"[!] 当前任务被取消: {domain}")
            continue
        except Exception as e:
            print(f"[!] 执行 {domain} 出错: {e}")


# ------------------------------------
if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_sigint)   # Ctrl+C
    signal.signal(signal.SIGQUIT, handle_sigquit) # Ctrl+\
    main()

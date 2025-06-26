import random
import socket

def is_cdn_ip(ip, domains):
    print(f"[+] 判断IP: {ip} 是否是CDN节点")
    
    # 条件1：域名数量过多，直接判定为CDN
    if len(domains) > 50:
        print(f"[-] 域名数量太多({len(domains)}), 直接判定为CDN")
        return True

    # 随机选一个域名做测试
    test_domain = random.choice(domains)
    print(f"[+] 选取的测试域名: {test_domain}")

    try:
        # 正向解析：域名 -> IP列表
        ips = socket.gethostbyname_ex(test_domain)[2]
        print(f"[+] 正向解析 {test_domain} 得到IP列表: {ips}")
        
        if ip not in ips:
            print(f"[-] 目标IP {ip} 不在域名解析的IP列表中，判定为CDN")
            return True

        if len(ips) > 4:
            print(f"[-] 正向解析IP列表数量超过4 ({len(ips)}), 判定为CDN")
            return True

    except Exception as e:
        print(f"[-] 解析异常: {e}，判定为CDN")
        return True

    print("[+] 通过所有判断，非CDN节点")
    return False

jieguo = is_cdn_ip("49.7.106.195", ["58cdn.com.cn"])
print(f"最终判断结果: {'CDN节点' if jieguo else '非CDN节点'}")

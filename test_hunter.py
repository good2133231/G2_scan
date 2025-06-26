import base64
import httpx
import asyncio

# 代理设置（SOCKS5）
proxies = {
    "http://": "socks5h://127.0.0.1:7891",
    "https://": "socks5h://127.0.0.1:7891"
}

# 替换为你的 Hunter API Key
API_KEY = '0005785352cfcbf29bfff44cf7ec447f0c7bf06e9589726a3c33be73dfc110b3'

# 查询语句，例如 icon hash
query = 'web.icon="09bfc6bfbfb19229ac65945b3fb3d0ac"'
query_base64 = base64.urlsafe_b64encode(query.encode()).decode().rstrip('=')

# Hunter API 地址
url = 'https://hunter.qianxin.com/openApi/search'

# 查询参数
params = {
    'api-key': API_KEY,
    'search': query_base64,
    'page': 1,
    'page_size': 10,
    'is_web': '3'  # 全部资产
}

async def hunter_query():
    try:
        async with httpx.AsyncClient(proxy="socks5h://127.0.0.1:7891", timeout=10) as client:
            response = await client.get(url, params=params)
            response.raise_for_status()
            data = response.json()

            if data.get('code') == 200:
                print(f"[+] 查询成功，共 {data['data']['total']} 条结果，展示前 10 条：\n")
                for item in data['data']['arr']:
                    print(f"- URL: {item['url']}")
                    print(f"  IP: {item['ip']}")
                    print(f"  端口: {item['port']}")
                    print(f"  协议: {item['protocol']}")
                    print(f"  标题: {item['web_title']}")
                    print('-' * 50)
            else:
                print(f"[!] 查询失败：{data.get('message')}")

    except httpx.RequestError as e:
        print(f"[!] 请求错误：{e}")

# 运行异步主函数
asyncio.run(hunter_query())

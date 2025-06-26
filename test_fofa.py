import base64
import httpx
import asyncio

# 可用环境变量或配置文件管理
FOFA_EMAIL = "onlyctfer@tutanota.com"
FOFA_KEY = "0c29b33737d6ad37305708b2fb56e670"

async def query_fofa_by_mmh3(mmh3_hash, size=100, hash_type="icon_hash"):
    """
    通用 FOFA 查询接口，支持 icon_hash 与 body_hash 查询
    :param mmh3_hash: MMH3 整数值
    :param size: 返回结果数量限制
    :param hash_type: 'icon_hash' 或 'body_hash'
    """
    assert hash_type in {"icon_hash", "body_hash"}, "hash_type 必须是 'icon_hash' 或 'body_hash'"

    query = f'{hash_type}="{mmh3_hash}"'
    qbase64 = base64.b64encode(query.encode()).decode()
    url = (
        f"https://fofa.info/api/v1/search/all?"
        f"email={FOFA_EMAIL}&key={FOFA_KEY}&qbase64={qbase64}&size={size}&fields=host"
    )

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(url)
            r.raise_for_status()
            data = r.json()

            if data.get("error") is False:
                results = data.get("results", [])
                print(f"[DEBUG] FOFA results for {hash_type}={mmh3_hash}:", results)

                if results and isinstance(results[0], list):
                    return list(set(row[0] for row in results if row))
                elif results and isinstance(results[0], str):
                    return list(set(results))
                else:
                    print(f"[!] 未知结果格式: {type(results)}")
            else:
                print(f"[!] FOFA 返回错误信息: {data.get('errmsg')}")
    except Exception as e:
        print(f"[!] FOFA 查询失败: {e}")
    return []


async def main():
    test_hash = "1482289514"  # 替换为真实的 mmh3 hash
    result = await query_fofa_by_mmh3(test_hash, hash_type="body_hash")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())

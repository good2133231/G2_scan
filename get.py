import re

files = [
    "0067.cc_finish",
    "103.180.121.121_finish",
    "1inch.io_finish",
    "300onlinefitness.com_finish",
    "50x.com_finish",
    "58cdn.com.cn_finish",
    "5loyalty.com_finish",
    "8v.com_finish",
    "91pme.com_finish",
    "abstradex.xyz_vul",
    "abtrade.pro_finish",
    "acala.network_finish",
    "acats.com_finish",
    "account.gov.uk_finish",
    "ace.io_finish",
    "acetoptrade.com_finish",
    "adopstests.com_finish",
    "aevo.xyz_finish",
    "aftershipstatus.com_finish",
    "aibit.com_finish"
]

def natural_sort_key(s):
    # 分割字符串为数字和非数字部分，数字转int，非数字小写
    return [int(text) if text.isdigit() else text.lower() for text in re.split('(\d+)', s)]

sorted_files = sorted(files, key=natural_sort_key)

for f in sorted_files:
    print(f)

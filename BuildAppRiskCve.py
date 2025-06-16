# coding: utf-8
# 拉取指定月份微软 MSRC 应用程序类漏洞

###########################################################################
#初次运行会创建表msrc_app_vuln，爬取msrc的应用程序漏洞库（按月份--在第15行修改）
###########################################################################

import requests
import json
import pymysql
import datetime
import re
import itertools

# 你可以在这里手动调整月份
THIS_MONTH_ID = "2025-May"
TODAY = datetime.datetime.now().strftime("%Y-%m-%d")
MSRC_API = f"https://api.msrc.microsoft.com/cvrf/{THIS_MONTH_ID}?api-Version=2024"

# 可选 API-Key（不强制）
API_KEY = ""

# 关键词判断哪些产品是“应用程序类”
APP_KEYWORDS = ['Office', 'Teams', 'Skype', 'Visual Studio', 'Edge', 'Microsoft 365', 'Outlook']

# 数据库配置
DB_CONF = dict(
    host="localhost",
    port=3306,
    user="root",
    password="040611",
    db="threat_perception",
    charset="utf8mb4"
)

def normalize_kb(remediations):
    kbs = []
    for item in remediations:
        try:
            desc = item["Description"]["Value"]
            if "KB" in desc:
                m = re.search(r'KB\d{5,}', desc)
                if m:
                    kbs.append(m.group())
        except:
            pass
    return ",".join(sorted(set(kbs)))

def get_cvrf_data():
    headers = {'Accept': 'application/json'}
    if API_KEY:
        headers["api-key"] = API_KEY
    resp = requests.get(MSRC_API, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"MSRC 接口请求失败：{resp.status_code}")
    return resp.json()

#提取修复前版本的辅助函数
def extract_fixed_before(remediations, title):
    """
    从漏洞标题 + Remediations 中提取 fixed_before_version 信息。
    目标匹配模式包括：
      - "Fixed in version 6.10"
      - "before 17.13"
      - "< 123.0.0.0"
    """
    patterns = [
        r'Fixed\s+in\s+version\s+([0-9][0-9A-Za-z\.\-_]+)',
        r'before\s+([0-9][0-9A-Za-z\.\-_]+)',
        r'<\s*([0-9][0-9A-Za-z\.\-_]+)'
    ]

    sources = []

    # 标题作为第一信息源
    if isinstance(title, str):
        sources.append(title)

    # 从 remediations 中提取描述字符串
    for d in remediations:
        desc = d.get("Description")
        if isinstance(desc, dict):
            value = desc.get("Value", "")
            if isinstance(value, str):
                sources.append(value)
        elif isinstance(desc, str):
            sources.append(desc)

    # 开始匹配
    for txt in sources:
        if not isinstance(txt, str):
            continue  # 确保是字符串
        for pat in patterns:
            m = re.search(pat, txt, re.IGNORECASE)
            if m:
                version = m.group(1)
                # print(f"[DEBUG] Extracted fixed_before_version: {version}")
                return version

    return ""

def main():
    data = get_cvrf_data()
    db = pymysql.connect(**DB_CONF)
    cur = db.cursor()

    # 创建表（如果不存在）
    cur.execute("""
    CREATE TABLE IF NOT EXISTS msrc_app_vuln (
      id INT AUTO_INCREMENT PRIMARY KEY,
      cve_id VARCHAR(32) NOT NULL UNIQUE,
      title VARCHAR(512),
      product_name VARCHAR(256),
      kb_list TEXT,
      cvss_score FLOAT,
      fixed_before_version VARCHAR(50),        -- NEW
      published DATE,
      inserted_at DATE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # 应用程序相关产品
    product_map = {p["ProductID"]: p["Value"] for p in data["ProductTree"]["FullProductName"]}
    app_products = {pid: name for pid, name in product_map.items()
                    if any(kw in name for kw in APP_KEYWORDS)}

    print(f"[+] 当前月 {THIS_MONTH_ID} 中应用程序类产品数：{len(app_products)}")

    count = 0
    for vuln in data["Vulnerability"]:
        if "ADV" in vuln["CVE"]:
            continue
        affected_products = set()
        for status in vuln.get("ProductStatuses", []):
            affected_products.update(status.get("ProductID", []))
        matched = affected_products & app_products.keys()
        if not matched:
            continue

        kbs = normalize_kb(vuln.get("Remediations", []))
        scores = [s.get("BaseScore", 0) for s in vuln.get("CVSSScoreSets", []) if s.get("BaseScore")]
        score = round(sum(scores) / len(scores), 1) if scores else 0

        fixed_before = extract_fixed_before(
            vuln.get("Remediations", []),
            vuln.get("Title", "")
        )

        for pid in matched:
            title_raw = vuln.get("Title")
            if isinstance(title_raw, dict):
                title = title_raw.get("Value", "无标题")
            elif isinstance(title_raw, str):
                title = title_raw
            else:
                title = "无标题"
            title = title[:500]
            cur.execute("""
                INSERT INTO msrc_app_vuln
                  (cve_id, title, product_name, kb_list, cvss_score,fixed_before_version, published, inserted_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                  title=VALUES(title), product_name=VALUES(product_name),
                  kb_list=VALUES(kb_list), cvss_score=VALUES(cvss_score),
                  fixed_before_version=VALUES(fixed_before_version),  -- NEW
                  published=VALUES(published), inserted_at=VALUES(inserted_at)
            """, (
                vuln["CVE"],
                title,
                app_products[pid],
                kbs,
                score,
                fixed_before,  # NEW
                TODAY,
                TODAY
            ))
            count += 1

    db.commit()
    cur.close()
    db.close()
    print(f"[√] 写入漏洞数：{count}")

if __name__ == "__main__":
    main()

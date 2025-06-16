# coding=utf-8
"""
AppRiskDetect.py
检测本机已安装应用程序版本，与 MSRC 漏洞库 (msrc_app_vuln) 精确比对，
将风险结果通过 MQ 上报。
Author: Joey_Aaron
"""

import threading
import json
import winreg
import re
import pymysql
import cryptography
import pythoncom
import wmi
from datetime import datetime
from packaging import version



from util.EncryptUtil import EncryptUtil





# ======================== 线程类 ============================
class AppRiskDetect(threading.Thread):

    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq      # 消息队列对象，须实现 produce_appRisk_info(json_str)
        self.__data = data  # 平台传下来的信息，如 {"mac":"E0:0A:F6:AA:BB:CC"}

    DB_CONF = dict(
        host="localhost",
        port=3306,
        user="root",
        password="040611",
        database="threat_perception",
        cursorclass=pymysql.cursors.DictCursor
    )

    @staticmethod
    def normalize_name(s: str) -> str:
        """去括号/特殊符号/大小写，方便模糊匹配"""
        return re.sub(r'[^a-z0-9]', '', re.sub(r'\([^)]*\)', '', s.lower()))

    @staticmethod
    def extract_version(display_name: str) -> str:
        """用简单正则从末尾抓连续数字+点的版本号"""
        m = re.search(r'([0-9]+(\.[0-9]+)+)$', display_name)
        return m.group(1) if m else ""

    @staticmethod
    def compare_version(v1: str, v2: str) -> int:
        """
        v1 < v2 → -1; v1 == v2 → 0; v1 > v2 → 1
        借助 packaging.version 处理 1.2b 之类
        """
        try:
            return (version.parse(v1) > version.parse(v2)) - (version.parse(v1) < version.parse(v2))
        except Exception:
            return -1  # 解析失败，默认认为旧版本

    @staticmethod
    def is_app_match(app_display_name: str, vuln_product_name: str) -> bool:
        # 预处理：空值保护
        if not app_display_name or not vuln_product_name:
            return False

        # --------- 第一层匹配：规约英文小写形式匹配 ---------
        disp_norm = app_display_name.strip().lower()
        prod_norm = vuln_product_name.strip().lower()

        if disp_norm and prod_norm:
            if disp_norm.find(prod_norm) != -1 or prod_norm.find(disp_norm) != -1:
                return True

        # --------- 第二层匹配：原始字符串（中文或其他字符）匹配 ---------
        if vuln_product_name in app_display_name or app_display_name in vuln_product_name:
            return True

        return False


    # --------------------- 线程入口 --------------------------
    def run(self):
        self.__app_risk_detect()



    def __app_risk_detect(self):
        """
        1. 扫描注册表软件列表，写入/更新 app 表
        2. 本地对比 msrc_app_vuln，写入/更新 app_risk 表
        3. 将本机 app_risk 记录加密发送 MQ
        """
        print('开始探测 app 数据……')

        # ---------- ① 扫描注册表 ----------
        registry_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        )
        software_list = []
        total = winreg.QueryInfoKey(registry_key)[0]

        for i in range(total):
            try:
                sub_key_name = winreg.EnumKey(registry_key, i)
                sub_key = winreg.OpenKey(registry_key, sub_key_name)

                software = {
                    "macAddress": self.__data["macAddress"],
                    "displayName": winreg.QueryValueEx(sub_key, "DisplayName")[0],
                    "installLocation": (
                        winreg.QueryValueEx(sub_key, "InstallLocation")[0]
                        if "InstallLocation" in winreg.QueryInfoKey(sub_key)
                        else ""
                    ),
                    "uninstallString": (
                        winreg.QueryValueEx(sub_key, "UninstallString")[0]
                        if "UninstallString" in winreg.QueryInfoKey(sub_key)
                        else ""
                    ),
                }
                software["appVersion"] = self.extract_version(software["displayName"])
                software_list.append(software)
            except WindowsError:
                continue  # 子键缺字段，跳过

        print(f"本机扫描到应用 {len(software_list)} 条")

        # ---------- ② 写入 / 更新 app 表 ----------
        conn = pymysql.connect(**self.DB_CONF)
        try:
            with conn.cursor() as cur:
                sql_app = """
                INSERT INTO app (mac_address, display_name, install_location, uninstall_string)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    install_location = VALUES(install_location),
                    uninstall_string = VALUES(uninstall_string)
                """
                cur.executemany(
                    sql_app,
                    [
                        (
                            s["macAddress"],
                            s["displayName"],
                            s["installLocation"],
                            s["uninstallString"],
                        )
                        for s in software_list
                    ],
                )
                conn.commit()
                print(f"写入/更新 app 表 {cur.rowcount} 行")

                # ---------- ③ 读取 msrc_app_vuln ----------
                cur.execute(
                    """
                    SELECT cve_id, title, product_name, kb_list,
                           cvss_score, fixed_before_version
                    FROM msrc_app_vuln
                    """
                )
                vuln_list = cur.fetchall()
        finally:
            conn.close()

        # ---------- ④ 本地比对，生成风险列表 ----------
        risk_rows, dedup = [], set()
        for sw in software_list:
            app_ver = sw["appVersion"]

            for v in vuln_list:
                # 双重匹配：英文规约优先，回退原始字符串（中文也能比）
                if not self.is_app_match(sw["displayName"], v["product_name"] or ""):
                    continue

                # 版本号判定
                fix_before = v["fixed_before_version"]
                if fix_before and app_ver:
                    if self.compare_version(app_ver, fix_before) >= 0:
                        continue  # 已是修复版本

                # 去重（mac + app + cve）
                key = f'{sw["macAddress"]}::{sw["displayName"]}::{v["cve_id"]}'
                if key in dedup:
                    continue
                dedup.add(key)

                risk_rows.append(
                    (
                        sw["macAddress"],
                        sw["displayName"],
                        app_ver,
                        v["product_name"],
                        v["cve_id"],
                        v["title"],
                        v["kb_list"],
                        v["cvss_score"],
                        datetime.now(),
                    )
                )

        print(f"命中风险 {len(risk_rows)} 条")

        # ---------- ⑤ 写入 / 更新 app_risk ----------
        if risk_rows:
            conn = pymysql.connect(**self.DB_CONF)
            try:
                with conn.cursor() as cur:
                    sql_risk = """
                    INSERT INTO app_risk
                      (mac_address, app_name, app_version, product_name,
                       cve_id, title, kb_list, cvss_score, report_time)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON DUPLICATE KEY UPDATE
                      report_time = VALUES(report_time)
                    """
                    cur.executemany(sql_risk, risk_rows)
                    conn.commit()
                    print(f"写入/更新 app_risk 表 {cur.rowcount} 行")
            finally:
                conn.close()
        else:
            print("本机暂无新增风险记录")

        # ---------- ⑥ 查询本机 app_risk 并上报 ----------
        conn = pymysql.connect(**self.DB_CONF)
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT mac_address, app_name, app_version, product_name,
                           cve_id, title, kb_list, cvss_score, report_time
                    FROM app_risk
                    WHERE mac_address = %s
                    """,
                    (self.__data["macAddress"],),
                )
                send_rows = cur.fetchall()
        finally:
            conn.close()

        if send_rows:
            app_risk_json = json.dumps(send_rows, ensure_ascii=False, default=str)
            encrypted = EncryptUtil.encrypt_json(app_risk_json, "thisIsASecretKey")
            self.__mq.produce_appRisk_info(encrypted)
            print(f"已上报风险记录 {len(send_rows)} 条")
        else:
            print("最终仍未发现风险记录可上报")

        print("app 数据探测结束！")



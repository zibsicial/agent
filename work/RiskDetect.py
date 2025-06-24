import pymysql
import subprocess
import json
import threading
import uuid
import platform
from util.EncryptUtil import EncryptUtil


def get_mac_address():
    """
    获取 MAC 地址，适配 Windows 和 Linux
    """
    mac = uuid.getnode()
    return ':'.join([f'{(mac >> ele) & 0xff:02x}' for ele in range(40, -1, -8)])


class RiskDetect(threading.Thread):
    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq
        self.__data = data
        self.__is_windows = platform.system() == "Windows"

    def run(self):
        risks = fetch_risks()
        results = []
        mac_address = self.__data.get("mac_address", "") or get_mac_address()
        for risk in risks:
            status, output = self.run_check(risk["check_command"], risk["expected_result"])
            results.append({
                "risk_id": risk["risk_id"],
                "name": risk["name"],
                "mac_address": mac_address,
                "status": status,
                "severity": risk.get("severity", "")  # 数据库有此字段则自动获取
            })

        final_result = {
            "task_id": "auto_" + __import__('datetime').datetime.now().strftime("%Y%m%d_%H%M%S"),
            "results": results
        }
        result_json = json.dumps(final_result, ensure_ascii=False)
        print(result_json)
        encrypted_data = EncryptUtil.encrypt_json(result_json, "thisIsASecretKey")
        print("加密后的数据:", encrypted_data)
        from mq.RabbitMQ import RabbitMQ
        mq = RabbitMQ()
        mq.produce_risk_data(encrypted_data)
        print("风险探测结束！")

    def run_check(self, command, expected):
        """
        执行风险检测命令，适配 Windows 和 Linux
        """
        try:
            if self.__is_windows:
                # Windows 命令执行
                output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, timeout=5)
            else:
                # Linux 命令执行
                output = subprocess.check_output(command, shell=True, stderr=subprocess.DEVNULL, timeout=5)

            output_text = output.decode("utf-8").strip()
            if expected:
                status = "pass" if expected in output_text else "fail"
            else:
                status = "fail" if output_text else "pass"
            return status, output_text
        except subprocess.CalledProcessError:
            return "fail", "Command failed"
        except subprocess.TimeoutExpired:
            return "fail", "Command timeout"


# === 配置数据库连接 ===
db_config = {
    "host": "47.92.120.180",
    "user": "user",
    "password": "StrongPassword123!",
    "database": "threat_perception",
    "charset": "utf8mb4"
}


def fetch_risks():
    """
    从数据库中获取风险项
    """
    connection = pymysql.connect(**db_config)
    with connection.cursor(pymysql.cursors.DictCursor) as cursor:
        sql = """
              SELECT risk_id, name, check_command, expected_result, severity
              FROM risk_items
              WHERE is_active = 1 \
              """
        cursor.execute(sql)
        risks = cursor.fetchall()
    connection.close()
    return risks
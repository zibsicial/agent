"""
基线核查检测
"""
import subprocess
import threading
import json
import pythoncom
import wmi

from util.EncryptUtil import EncryptUtil


class BaseLineDetect(threading.Thread):
    """
    基线核查检测类
    """

    def __init__(self, mq, data):
        super().__init__()
        self.mq = mq  # RabbitMQ 实例
        self.data = data  # 传递的数据

    def run(self):
        self.__detect_baseline()

    def extract_log_sections(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        section1 = []
        section2 = []

        in_section2 = False
        capture_section2 = False

        for line in lines:
            # 截取“当前系统杂类信息一览”之前的部分
            if "当前系统杂类信息一览" in line:
                break
            section1.append(line)

            # 判断是否进入“系统服务运行一览”之后的内容
            if in_section2:
                if line.startswith("——————————————"):
                    capture_section2 = False
                elif capture_section2:
                    section2.append(line)
                continue

            if "系统服务运行一览" in line:
                in_section2 = True
                capture_section2 = True

        # 合并为字符串输出
        result1 = ''.join(section1).rstrip('\n')
        result2 = ''.join(section2).rstrip('\n')

        print("=== 当前系统杂类信息一览以上内容 ===")
        print(result1)
        print("\n=== 系统服务运行一览以下内容 ===")
        print(result2)

        return result1, result2

    def __detect_baseline(self):
        """
        执行基线核查逻辑
        """
        # 初始化
        pythoncom.CoInitialize()
        # 创建WMI客户端
        c = wmi.WMI()
        ps_command = 'powershell -ExecutionPolicy bypass -File ../ps/windows.ps1'
        print("开始基线核查............")
        result = subprocess.run(['powershell', '-Command', ps_command],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        print("基线核查结束............")
        # 去初始化
        pythoncom.CoUninitialize()

        file_path = r"F:\Study\GXAstudy\code\python\agent\logs\*.log"
        # 提取日志内容
        section1, section2 = self.extract_log_sections(file_path)

        # 收集关键日志内容到 baseline_data
        baseline_list = {
            "section_before_misc": section1.strip(),  # 杂类信息之前的内容
            "section_after_service": section2.strip()  # 服务运行一览之后的内容
        }
        # 转为 JSON 字符串便于传输/保存
        baseline_data = json.dumps(baseline_list, ensure_ascii=False, indent=2)
        print("=======================================================")
        print(baseline_data)
        encrypt_baseline_data = EncryptUtil.encrypt(baseline_data)
        print("=======================================================")
        print(encrypt_baseline_data)
        self.mq.produce_baseline_data(encrypt_baseline_data)
        print("基线核查结束")



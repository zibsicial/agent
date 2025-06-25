"""
基线核查检测
"""
import platform
import subprocess
import threading
import json
import uuid
import socket
import pythoncom
import wmi
import sys
import os
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
        system = platform.system()
        if system == "Windows":
            self.__detect_baseline_windows()
        elif system == "Linux":
            self.__detect_baseline_linux()
        else:
            print(f"不支持的操作系统: {system}")

    def __detect_baseline_windows(self):
        import pythoncom
        import wmi
        print("开始Windows基线核查任务......!")
        pythoncom.CoInitialize()
        c = wmi.WMI()

        host_name = socket.gethostname()
        mac_address = ':'.join(("%012X" % uuid.getnode())[i:i + 2] for i in range(0, 12, 2))

        # 获取打包后运行或源码运行的基目录
        if getattr(sys, 'frozen', False):
            base_dir = sys._MEIPASS
        else:
            base_dir = os.path.dirname(os.path.abspath(__file__))

        # 拼接 PowerShell 脚本的绝对路径
        script_path = os.path.join(base_dir, "ps", "windows.ps1")

        # 构建 PowerShell 命令
        ps_command = f'powershell -ExecutionPolicy bypass -File "{script_path}"'

        result = subprocess.run(['powershell', '-Command', ps_command],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        full_output = result.stdout
        print("Windows基线检测输出：", full_output)
        print("Windows基线检测错误：", result.stderr)
        # 提取 baseline_list 内容
        start_marker = "[INFO] [-] 正在导出当前系统策略配置文件 config.cfg......"
        end_marker = "[INFO] - Windows Server 安全配置策略基线检测脚本已执行完毕"
        try:
            start_index = full_output.index(start_marker) + len(start_marker)
            end_index = full_output.index(end_marker)
            baseline_result = full_output[start_index:end_index].strip()
        except ValueError as e:
            baseline_result = "提取失败：" + str(e)
        pythoncom.CoUninitialize()
        baseline_obj = {
            "macAddress": mac_address,
            "hostName": host_name,
            "baseline_result": baseline_result
        }
        self.__send_result(baseline_obj)

    def __detect_baseline_linux(self):
        print("开始Linux基线核查任务......!")
        host_name = os.uname().nodename
        try:
            mac_address = open('/sys/class/net/eth0/address').read().strip()
        except Exception:
            mac_address = "未知"
        sh_path = './ps/test.sh'
        # 自动赋予可执行权限
        if not os.access(sh_path, os.X_OK):
            os.chmod(sh_path, 0o755)
        result = subprocess.run(['bash', sh_path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        full_output = result.stdout
        print("Linux基线检测输出：", full_output)
        print("Linux基线检测错误：", result.stderr)
        # 你可以根据实际输出格式提取 baseline_result
        baseline_result = full_output.strip()
        baseline_obj = {
            "macAddress": mac_address,
            "hostName": host_name,
            "baseline_result": baseline_result
        }
        self.__send_result(baseline_obj)

    def __send_result(self, baseline_obj):
        baseline_data = json.dumps(baseline_obj, ensure_ascii=False, indent=2)
        print("=======================================================")
        print(baseline_data)
        encrypt_baseline_data = EncryptUtil.encrypt_json(baseline_data, "thisIsASecretKey")
        print("=======================================================")
        print(encrypt_baseline_data)
        from mq.RabbitMQ import RabbitMQ
        mq = RabbitMQ()
        mq.produce_baseline_data(encrypt_baseline_data)
        print("基线核查结束")




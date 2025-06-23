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

    def __detect_baseline(self):
        print("开始基线核查任务......!")
        # 初始化
        pythoncom.CoInitialize()
        c = wmi.WMI()

        # 采集主机名
        try:
            host_name = c.Win32_ComputerSystem()[0].Name
        except Exception as e:
            host_name = f"获取失败: {e}"

        # 采集第一个启用的MAC地址
        try:
            mac_address = next(
                nic.MACAddress for nic in c.Win32_NetworkAdapterConfiguration()
                if nic.IPEnabled and nic.MACAddress
            )
        except Exception as e:
            mac_address = f"获取失败: {e}"

        # 定义PowerShell命令
        ps_command = 'powershell -ExecutionPolicy bypass -File ../ps/windows.ps1'
        result = subprocess.run(['powershell', '-Command', ps_command],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        full_output = result.stdout
        print(
            "=======================================================输出信息=======================================================")
        print(full_output)
        print(
            "=======================================================错误信息=======================================================")
        print(result.stderr)

        # 提取 baseline_list 内容
        start_marker = "[INFO] [-] 正在导出当前系统策略配置文件 config.cfg......"
        end_marker = "[INFO] - Windows Server 安全配置策略基线检测脚本已执行完毕,详细见桌面.txt文件"
        try:
            start_index = full_output.index(start_marker) + len(start_marker)
            end_index = full_output.index(end_marker)
            baseline_result = full_output[start_index:end_index].strip()
        except ValueError as e:
            baseline_result = "提取失败：" + str(e)

        # 去初始化
        pythoncom.CoUninitialize()

        # 拼接 JSON 对象
        baseline_obj = {
            "macAddress": mac_address,
            "hostName": host_name,
            "baseline_result": baseline_result
        }

        baseline_data = json.dumps(baseline_obj, ensure_ascii=False, indent=2)
        print("=======================================================")
        print(baseline_data)
        encrypt_baseline_data = EncryptUtil.encrypt(baseline_data)
        print("=======================================================")
        print(encrypt_baseline_data)
        self.mq.produce_baseline_data(encrypt_baseline_data)
        print("基线核查结束")




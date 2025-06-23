"""
baseline_detect_test.py
用法：
    python baseline_detect_test.py            # 使用默认 ./ps/windows.ps1
    python baseline_detect_test.py C:\tmp\a.ps1  # 指定 PowerShell 脚本
"""
import subprocess
import json
import sys
import base64
from pathlib import Path

# ---------- ▍桩（stub）实现：RabbitMQ & EncryptUtil ---------- #

class DummyMQ:
    """
    代替真正的 RabbitMQ，只在控制台打印加密后数据长度
    """
    def produce_baseline_data(self, data: str) -> None:
        print(f"[DummyMQ] produce_baseline_data 被调用，加密后长度：{len(data)}")

class EncryptUtil:
    """
    用最简单的 base64 做“加密”，方便查看
    """
    @staticmethod
    def encrypt(plain: str) -> str:
        return base64.b64encode(plain.encode("utf-8")).decode("utf-8")


# ---------- ▍真正的测试函数 ---------- #

def test_detect_baseline(ps_script: str = "../ps/windows.ps1") -> None:
    """执行 PowerShell，提取两标记之间内容并模拟发送"""
    if not Path(ps_script).exists():
        raise FileNotFoundError(f"找不到 PowerShell 脚本: {ps_script}")

    # 1️⃣ 运行 PowerShell
    ps_cmd = f'powershell -ExecutionPolicy Bypass -File "{ps_script}"'
    result = subprocess.run(
        ["powershell", "-Command", ps_cmd],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )

    full_output = result.stdout
    if result.stderr:
        print("⚠  PowerShell 错误输出：\n", result.stderr, file=sys.stderr)

    # 2️⃣ 提取基线列表
    start_marker = "[INFO] [-] 正在导出当前系统策略配置文件 config.cfg......"
    end_marker   = "[INFO] - Windows Server 安全配置策略基线检测脚本已执行完毕,详细见桌面.txt文件"
    try:
        start = full_output.index(start_marker) + len(start_marker)
        end   = full_output.index(end_marker)
        baseline_list = full_output[start:end].strip()
    except ValueError as exc:
        raise RuntimeError(f"✘ 未找到标记，无法提取：{exc}")

    # 3️⃣ JSON 化 & “加密”
    baseline_json = json.dumps(baseline_list, ensure_ascii=False)
    encrypted     = EncryptUtil.encrypt(baseline_json)

    # 4️⃣ 模拟发送
    DummyMQ().produce_baseline_data(encrypted)

    # 5️⃣ 调试输出
    print("====== 提取出的 baseline_list ======")
    print(baseline_list)
    print("============= 加密后 =============")
    print(encrypted)
    print("✅ 测试结束")
    print("========================================================================================================")
    print("========================================================================================================")
    print("========================================================================================================")
    print(baseline_json)


# ---------- ▍命令行入口 ---------- #

if __name__ == "__main__":
    script_path = sys.argv[1] if len(sys.argv) > 1 else "../ps/windows.ps1"
    test_detect_baseline(script_path)

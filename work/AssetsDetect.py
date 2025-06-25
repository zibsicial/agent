import json
import threading
import platform
import psutil
import subprocess
import shutil
import os
import sys
from util.EncryptUtil import EncryptUtil

# Windows 专用库
if platform.system() == "Windows":
    import winreg
    import pythoncom
    import wmi
    from nmap import nmap


class AssetsDetect(threading.Thread):
    """
    资产探测的线程类，支持 Windows 和 Linux
    """
    def __init__(self, mq, data):
        super().__init__()
        self.__mq = mq
        self.__data = data
        self.__is_windows = platform.system() == "Windows"

    def run(self):
        """
        线程运行函数
        """
        self.__detect()

    def __detect(self):
        """
        探测的方法
        """
        account = self.__data["account"]
        service = self.__data["service"]
        process = self.__data["process"]
        app = self.__data["app"]

        if account == 1:
            self.__detect_account()

        if service == 1:
            self.__detect_service()

        if process == 1:
            self.__detect_process()

        if app == 1 and self.__is_windows:
            self.__detect_app()

    def __check_and_install_nmap(self):
        """
        检查并自动安装 nmap
        """
        # 检查 nmap 是否已安装
        if shutil.which("nmap"):
            print("[+] nmap 已安装")
            return True
        
        print("[!] nmap 未安装，正在尝试自动安装...")
        
        if self.__is_windows:
            return self.__install_nmap_windows()
        else:
            return self.__install_nmap_linux()
    
    def __install_nmap_windows(self):
        """
        Windows 下自动安装 nmap
        """
        try:
            # 方法1: 使用 winget (Windows 10 1803+)
            if shutil.which("winget"):
                print("[*] 使用 winget 安装 nmap...")
                result = subprocess.run(
                    ["winget", "install", "nmap.nmap", "--accept-source-agreements", "--accept-package-agreements"],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    print("[+] nmap 安装成功")
                    return True
            
            # 方法2: 使用 chocolatey
            if shutil.which("choco"):
                print("[*] 使用 chocolatey 安装 nmap...")
                result = subprocess.run(
                    ["choco", "install", "nmap", "-y"],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    print("[+] nmap 安装成功")
                    return True
            
            # 方法3: 使用 scoop
            if shutil.which("scoop"):
                print("[*] 使用 scoop 安装 nmap...")
                result = subprocess.run(
                    ["scoop", "install", "nmap"],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    print("[+] nmap 安装成功")
                    return True
            
            # 方法4: 下载并安装 nmap
            print("[*] 尝试下载并安装 nmap...")
            return self.__download_and_install_nmap_windows()
            
        except Exception as e:
            print(f"[!] 自动安装 nmap 失败: {e}")
            return False
    
    def __download_and_install_nmap_windows(self):
        """
        下载并安装 nmap (Windows)
        """
        try:
            import urllib.request
            import tempfile
            
            # nmap 官方下载链接
            nmap_url = "https://nmap.org/dist/nmap-7.94-setup.exe"
            temp_dir = tempfile.gettempdir()
            installer_path = os.path.join(temp_dir, "nmap-setup.exe")
            
            print(f"[*] 下载 nmap 安装程序到: {installer_path}")
            
            # 下载安装程序
            urllib.request.urlretrieve(nmap_url, installer_path)
            
            # 静默安装
            print("[*] 正在安装 nmap...")
            result = subprocess.run(
                [installer_path, "/S"],  # /S 表示静默安装
                capture_output=True, text=True, timeout=600
            )
            
            # 清理安装文件
            try:
                os.remove(installer_path)
            except:
                pass
            
            if result.returncode == 0:
                print("[+] nmap 安装成功")
                # 刷新环境变量
                os.environ['PATH'] = os.environ.get('PATH', '') + ';C:\\Program Files (x86)\\Nmap'
                return True
            else:
                print(f"[!] nmap 安装失败: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] 下载安装 nmap 失败: {e}")
            return False
    
    def __install_nmap_linux(self):
        """
        Linux 下自动安装 nmap
        """
        try:
            # 检测包管理器
            if shutil.which("apt"):
                print("[*] 使用 apt 安装 nmap...")
                result = subprocess.run(
                    ["sudo", "apt", "update", "-y"],
                    capture_output=True, text=True, timeout=300
                )
                result = subprocess.run(
                    ["sudo", "apt", "install", "nmap", "-y"],
                    capture_output=True, text=True, timeout=300
                )
            elif shutil.which("yum"):
                print("[*] 使用 yum 安装 nmap...")
                result = subprocess.run(
                    ["sudo", "yum", "install", "nmap", "-y"],
                    capture_output=True, text=True, timeout=300
                )
            elif shutil.which("dnf"):
                print("[*] 使用 dnf 安装 nmap...")
                result = subprocess.run(
                    ["sudo", "dnf", "install", "nmap", "-y"],
                    capture_output=True, text=True, timeout=300
                )
            elif shutil.which("pacman"):
                print("[*] 使用 pacman 安装 nmap...")
                result = subprocess.run(
                    ["sudo", "pacman", "-S", "nmap", "--noconfirm"],
                    capture_output=True, text=True, timeout=300
                )
            else:
                print("[!] 未找到支持的包管理器")
                return False
            
            if result.returncode == 0:
                print("[+] nmap 安装成功")
                return True
            else:
                print(f"[!] nmap 安装失败: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"[!] 自动安装 nmap 失败: {e}")
            return False

    def __detect_account(self):
        """
        探测账号资产
        """
        if self.__is_windows:
            # Windows 账号探测
            pythoncom.CoInitialize()
            c = wmi.WMI()
            account_list = []
            for user in c.Win32_UserAccount():
                user_dict = {
                    "macAddress": self.__data['macAddress'],
                    "name": user.Name,
                    "fullName": user.FullName,
                    "sid": user.SID,
                    "sidType": user.SIDType,
                    "status": user.Status,
                    "disabled": user.Disabled,
                    "lockout": user.Lockout,
                    "passwordChangeable": user.PasswordChangeable,
                    "passwordExpires": user.PasswordExpires,
                    "passwordRequired": user.PasswordRequired,
                }
                account_list.append(user_dict)
            pythoncom.CoUninitialize()
        else:
            # Linux 账号探测
            account_list = []
            try:
                with open("/etc/passwd", "r") as f:
                    for line in f:
                        parts = line.split(":")
                        account_list.append({
                            "macAddress": self.__data['macAddress'],
                            "name": parts[0],
                            "uid": parts[2],
                            "gid": parts[3],
                            "home": parts[5],
                            "shell": parts[6].strip()
                        })
            except FileNotFoundError:
                print("[!] 无法读取 /etc/passwd 文件")

        account_data = json.dumps(account_list)
        encrypted_account_data = EncryptUtil.encrypt_json(account_data, "thisIsASecretKey")
        print(account_data)
        from mq.RabbitMQ import RabbitMQ
        mq = RabbitMQ()
        mq.produce_account_info(encrypted_account_data)

    def __detect_service(self):
        """
        探测服务资产
        """
        service_list = []
        if self.__is_windows:
            # 检查并安装 nmap
            if not self.__check_and_install_nmap():
                print("[!] nmap 安装失败，跳过服务探测")
                return
            
            # Windows 服务探测
            try:
                nm = nmap.PortScanner()
                nm.scan(hosts='127.0.0.1', arguments='-sTV')
                for host in nm.all_hosts():
                    for proto in nm[host].all_protocols():
                        lport = nm[host][proto].keys()
                        for port in lport:
                            service_list.append({
                                'macAddress': self.__data['macAddress'],
                                'protocol': proto,
                                'port': port,
                                'state': nm[host][proto][port]['state'],
                                'name': nm[host][proto][port]['name'],
                                'product': nm[host][proto][port]['product'],
                                'version': nm[host][proto][port]['version'],
                                'extraInfo': nm[host][proto][port].get('extraInfo', 'N/A')
                            })
            except Exception as e:
                print(f"[!] nmap 扫描失败: {e}")
                # 备用方案：使用 netstat
                service_list = self.__fallback_service_detection()
        else:
            # Linux 服务探测
            try:
                with open("/etc/services", "r") as f:
                    for line in f:
                        if not line.startswith("#"):
                            parts = line.split()
                            if len(parts) >= 2:
                                service_list.append({
                                    "macAddress": self.__data['macAddress'],
                                    "name": parts[0],
                                    "port_protocol": parts[1]
                                })
            except FileNotFoundError:
                print("[!] 无法读取 /etc/services 文件")

        service_data = json.dumps(service_list)
        encrypted_service_data = EncryptUtil.encrypt_json(service_data, "thisIsASecretKey")
        print(service_data)
        self.__mq.produce_service_info(encrypted_service_data)

    def __fallback_service_detection(self):
        """
        备用服务探测方案（使用 netstat）
        """
        service_list = []
        try:
            # 使用 netstat 获取端口信息
            result = subprocess.run(
                ["netstat", "-ano"], 
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for line in lines[4:]:  # 跳过标题行
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 2:
                            addr_part = parts[1]
                            if ':' in addr_part:
                                port = addr_part.split(':')[-1]
                                try:
                                    port = int(port)
                                    service_list.append({
                                        'macAddress': self.__data['macAddress'],
                                        'protocol': 'tcp',
                                        'port': port,
                                        'state': 'open',
                                        'name': f'port_{port}',
                                        'product': 'unknown',
                                        'version': 'unknown',
                                        'extraInfo': 'detected by netstat'
                                    })
                                except ValueError:
                                    continue
        except Exception as e:
            print(f"[!] 备用服务探测失败: {e}")
        
        return service_list

    def __detect_process(self):
        """
        探测进程资产
        """
        process_list = []
        if self.__is_windows:
            # Windows 进程探测
            pythoncom.CoInitialize()
            c = wmi.WMI()
            for process in c.Win32_Process():
                process_list.append({
                    'macAddress': self.__data['macAddress'],
                    'pid': process.ProcessId,
                    'ppid': process.ParentProcessId,
                    'name': process.Name,
                    'cmd': process.CommandLine,
                    'priority': process.Priority,
                    'description': process.Description,
                })
            pythoncom.CoUninitialize()
        else:
            # Linux 进程探测
            for proc in psutil.process_iter(attrs=["pid", "ppid", "name", "cmdline"]):
                process_list.append({
                    "macAddress": self.__data['macAddress'],
                    "pid": proc.info["pid"],
                    "ppid": proc.info["ppid"],
                    "name": proc.info["name"],
                    "cmd": " ".join(proc.info["cmdline"]) if proc.info["cmdline"] else ""
                })

        process_data = json.dumps(process_list)
        encrypted_process_data = EncryptUtil.encrypt_json(process_data, "thisIsASecretKey")
        print(process_data)
        self.__mq.produce_process_info(encrypted_process_data)

    def __detect_app(self):
        """
        探测应用资产（仅适用于 Windows）
        """
        registry_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
        software_list = []
        number = winreg.QueryInfoKey(registry_key)[0]
        for i in range(number):
            try:
                sub_key_name = winreg.EnumKey(registry_key, i)
                sub_key = winreg.OpenKey(registry_key, sub_key_name)
                software = {}
                try:
                    software['macAddress'] = self.__data['macAddress']
                    software['displayName'] = winreg.QueryValueEx(sub_key, 'DisplayName')[0]
                    software['installLocation'] = winreg.QueryValueEx(sub_key, 'InstallLocation')[0]
                    software['uninstallString'] = winreg.QueryValueEx(sub_key, 'UninstallString')[0]
                    software_list.append(software)
                except WindowsError:
                    continue
            except WindowsError:
                break

        app_data = json.dumps(software_list)
        encrypted_app_data = EncryptUtil.encrypt_json(app_data, "thisIsASecretKey")
        print("已探测应用："+ app_data)
        self.__mq.produce_app_info(encrypted_app_data)
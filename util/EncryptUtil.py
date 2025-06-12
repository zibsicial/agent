
# EncryptUtil.py
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Random import get_random_bytes

class EncryptUtil:

    @staticmethod
    def encrypt_json(json_str: str, key: str) -> str:
        # 输入为 JSON 字符串
        data = json_str.encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        encrypted = iv + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt_json(encrypted_data: str, key: str) -> str:
        # 输出为 JSON 字符串
        encrypted_data_bytes = base64.b64decode(encrypted_data)
        iv = encrypted_data_bytes[:16]
        ciphertext = encrypted_data_bytes[16:]
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_data.decode('utf-8')
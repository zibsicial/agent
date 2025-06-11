# EncryptUtil.py
import json
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad
from Cryptodome.Random import get_random_bytes

class EncryptUtil:
    @staticmethod
    def encrypt_json(data: list, key: str) -> str:
        json_data = json.dumps(data).encode('utf-8')
        iv = get_random_bytes(16)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(json_data, AES.block_size))
        encrypted = iv + ciphertext
        return base64.b64encode(encrypted).decode('utf-8')

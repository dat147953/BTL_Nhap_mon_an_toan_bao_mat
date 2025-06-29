import base64
import hashlib
import json
import os
import logging
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import pad
import bcrypt

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Tạo cặp khóa RSA cho sender
sender_key = RSA.generate(2048)
sender_private_key = sender_key
sender_public_key = sender_key.publickey()

# Hàm mã hóa file và gửi
def sender_process(file_path, password, medical_record_id, recipient_public_key):
    try:
        # Kiểm tra đầu vào
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File {file_path} không tồn tại")
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Mật khẩu phải là chuỗi, dài ít nhất 8 ký tự")

        # 1. Handshake
        logging.info("Sender: Hello!")
        # Giả lập nhận "Ready!" từ receiver

        # 2. Đọc file và tạo metadata với timestamp cố định
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        # Sử dụng timestamp cố định: 01:57 PM +07, Thứ Năm, 26/06/2025
        timestamp = "2025-06-26T13:57:00+07:00"  # Định dạng ISO 8601
        metadata = f"{os.path.basename(file_path)}|{timestamp}|{medical_record_id}".encode()

        # Ký metadata bằng RSA/SHA-512
        hash_metadata = SHA512.new(metadata)
        signature = pkcs1_15.new(sender_private_key).sign(hash_metadata)

        # Tạo session key cho AES
        session_key = get_random_bytes(32)  # Khóa 256-bit
        iv = get_random_bytes(16)  # IV cho AES-CBC

        # Mã hóa file bằng AES-CBC với PKCS#7 padding
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, AES.block_size)  # PKCS#7 padding
        ciphertext = cipher_aes.encrypt(padded_data)

        # Tính hash toàn vẹn (SHA-512(IV || ciphertext))
        hash_data = SHA512.new(iv + ciphertext).hexdigest()

        # Mã hóa session key bằng RSA-OAEP
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key, hashAlgo=SHA512)
        encrypted_session_key = cipher_rsa.encrypt(session_key)

        # Tạo hash mật khẩu bằng bcrypt
        salt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(password.encode(), salt).hex()

        # Tạo gói tin
        packet = {
            "iv": base64.b64encode(iv).decode(),
            "cipher": base64.b64encode(ciphertext).decode(),
            "hash": hash_data,
            "sig": base64.b64encode(signature).decode(),
            "pwd": pwd_hash,
            "encrypted_session_key": base64.b64encode(encrypted_session_key).decode(),
            "metadata": metadata.decode()  # Gửi metadata
        }

        logging.info("Sender: Gửi gói tin...")
        return packet

    except Exception as e:
        logging.error(f"Lỗi sender: {str(e)}")
        raise

# Lưu gói tin vào file JSON để truyền (giả lập truyền qua mạng)
def save_packet(packet, output_file="packet.json"):
    with open(output_file, 'w') as f:
        json.dump(packet, f, indent=2)
    logging.info(f"Gói tin được lưu tại {output_file}")

# Ví dụ sử dụng
if __name__ == "__main__": # Corrected: two underscores before and after 'name'
    # Tạo khóa RSA cho receiver (giả lập)
    receiver_key = RSA.generate(2048)
    receiver_public_key = receiver_key.publickey()

    # Tham số
    password = "securepassword123"
    file_path = "medical_record.txt"
    medical_record_id = "MED12345"

    # Tạo file mẫu
    with open(file_path, "wb") as f:
     # Mã hóa chuỗi sang bytes một cách rõ ràng bằng UTF-8
     f.write("Thông tin bệnh án mẫu".encode('utf-8'))

    # Gửi file
    try:
        packet = sender_process(file_path, password, medical_record_id, receiver_public_key)
        save_packet(packet)
        print(json.dumps(packet, indent=2))
    except Exception as e:
        logging.error(f"Lỗi chính: {str(e)}")
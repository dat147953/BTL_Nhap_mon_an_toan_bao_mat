import base64
import hashlib
import json
import os
import logging
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad
import bcrypt

# Cấu hình logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Tạo cặp khóa RSA cho receiver
receiver_key = RSA.generate(2048)
receiver_private_key = receiver_key
receiver_public_key = receiver_key.publickey()

# Hàm nhận và xử lý file
def receiver_process(packet, password, sender_public_key, private_key, output_dir="received"):
    try:
        # Kiểm tra cấu trúc gói tin
        required_keys = ["iv", "cipher", "hash", "sig", "pwd", "encrypted_session_key", "metadata"]
        if not all(key in packet for key in required_keys):
            raise ValueError("Cấu trúc gói tin không hợp lệ")

        # 1. Handshake
        logging.info("Receiver: Ready!")

        # 2. Kiểm tra mật khẩu
        if not bcrypt.checkpw(password.encode(), bytes.fromhex(packet["pwd"])):
            logging.error("Receiver: NACK - Mật khẩu không hợp lệ")
            return False

        # 3. Kiểm tra chữ ký
        metadata = packet["metadata"].encode()
        hash_metadata = SHA512.new(metadata)
        signature = base64.b64decode(packet["sig"])
        try:
            pkcs1_15.new(sender_public_key).verify(hash_metadata, signature)
            logging.info("Receiver: Chữ ký hợp lệ")
        except:
            logging.error("Receiver: NACK - Chữ ký không hợp lệ")
            return False

        # 4. Kiểm tra toàn vẹn
        iv = base64.b64decode(packet["iv"])
        ciphertext = base64.b64decode(packet["cipher"])
        computed_hash = SHA512.new(iv + ciphertext).hexdigest()
        if computed_hash != packet["hash"]:
            logging.error("Receiver: NACK - Kiểm tra toàn vẹn thất bại")
            return False

        # 5. Giải mã session key
        cipher_rsa = PKCS1_OAEP.new(private_key, hashAlgo=SHA512)
        encrypted_session_key = base64.b64decode(packet["encrypted_session_key"])
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        # 6. Giải mã file
        cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)  # PKCS#7 unpadding

        # 7. Lưu file
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"received_medical_record_{packet['metadata'].split('|')[-1]}.txt")
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
        logging.info(f"Receiver: Lưu file thành công tại {output_path}")

        # 8. Gửi ACK
        logging.info("Receiver: ACK")
        return True

    except Exception as e:
        logging.error(f"Lỗi receiver: {str(e)}")
        return False

# Đọc gói tin từ file JSON (giả lập nhận qua mạng)
def load_packet(input_file="packet.json"): # Thay đổi đường dẫn này
    try:
        with open(input_file, 'r') as f:
            packet = json.load(f)
        logging.info(f"Đọc gói tin từ {input_file}")
        return packet
    except Exception as e:
        logging.error(f"Lỗi đọc gói tin: {str(e)}")
        raise
# Ví dụ sử dụng
if __name__ == "__main__":
    # Tạo khóa RSA cho sender (giả lập)
    sender_key = RSA.generate(2048)
    sender_public_key = sender_key.publickey()

    # Tham số
    password = "securepassword123"

    # Nhận và xử lý file
    try:
        packet = load_packet()
        success = receiver_process(packet, password, sender_public_key, receiver_private_key)
        if success:
            print("Chuyển file thành công")
        else:
            print("Chuyển file thất bại")
    except Exception as e:
        logging.error(f"Lỗi chính: {str(e)}")
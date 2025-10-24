from PIL import Image
import base64
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets

# ===========================
# 🔐 AES 加解密功能
# ===========================
def aes_encrypt(message: str, password: str) -> bytes:
    key = password.encode('utf-8')
    if len(key) not in [16, 24, 32]:
        key = key.ljust(32, b'0')[:32]  # 自動補齊到 32 bytes

    iv = secrets.token_bytes(16)  # 隨機 IV
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode('utf-8')) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext  # 將 IV 附在前面

def aes_decrypt(data: bytes, password: str) -> str:
    key = password.encode('utf-8')
    if len(key) not in [16, 24, 32]:
        key = key.ljust(32, b'0')[:32]

    iv = data[:16]
    ciphertext = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plain = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded_plain) + unpadder.finalize()

    return plain.decode('utf-8')

# ===========================
# 🧩 藏入訊息
# ===========================
def hide_message():
    img_path = input("請輸入圖片檔名（例如 input.png）: ").strip()
    if not os.path.exists(img_path):
        print("❌ 找不到檔案")
        return

    message = input("請輸入要藏入的訊息（可輸入藏文或任意文字）:\n> ").strip()
    if not message:
        print("❌ 未輸入訊息")
        return

    password = input("請輸入加密密碼（AES 密鑰）: ").strip()
    if not password:
        print("❌ 密碼不可為空")
        return

    # 🔒 AES 加密 + Base64
    encrypted = aes_encrypt(message, password)
    data = base64.b64encode(encrypted)
    binary_data = ''.join(format(byte, '08b') for byte in data)
    binary_data += "1111111111111110"  # 結束標記

    data_len = len(binary_data)

    # 開啟圖片
    img = Image.open(img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size
    capacity = width * height * 3

    if data_len > capacity:
        print("⚠️ 圖片太小，無法藏入全部資料！")
        return

    print(f"🧩 可藏容量：約 {capacity // 8} bytes")
    print(f"📜 實際訊息長度：約 {len(data)} bytes")

    # 開始藏入
    idx = 0
    for y in range(height):
        for x in range(width):
            if idx >= data_len:
                break
            r, g, b = pixels[x, y]
            if idx < data_len:
                r = (r & ~1) | int(binary_data[idx])
                idx += 1
            if idx < data_len:
                g = (g & ~1) | int(binary_data[idx])
                idx += 1
            if idx < data_len:
                b = (b & ~1) | int(binary_data[idx])
                idx += 1
            pixels[x, y] = (r, g, b)
        if idx >= data_len:
            break

    output_name = "stego_aes.png"
    img.save(output_name, "PNG")
    print(f"✅ 已成功將加密訊息藏入 {output_name}")

# ===========================
# 🧩 提取訊息
# ===========================
def extract_message():
    img_path = input("請輸入要解析的圖片檔名（例如 stego_aes.png）: ").strip()
    if not os.path.exists(img_path):
        print("❌ 找不到檔案")
        return

    password = input("請輸入解密密碼: ").strip()
    if not password:
        print("❌ 密碼不可為空")
        return

    img = Image.open(img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = img.load()
    width, height = img.size

    binary_out = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            binary_out += str(r & 1)
            binary_out += str(g & 1)
            binary_out += str(b & 1)
            if binary_out.endswith("1111111111111110"):
                binary_out = binary_out[:-16]
                break
        else:
            continue
        break

    try:
        bytes_out = bytes(int(binary_out[i:i+8], 2) for i in range(0, len(binary_out), 8))
        decrypted_data = base64.b64decode(bytes_out)
        message = aes_decrypt(decrypted_data, password)
        print("🔍 成功提取並解密訊息：")
        print(message)
    except Exception as e:
        print("⚠️ 解碼或解密失敗：", e)

# ===========================
# 🔹 主程式
# ===========================
def main():
    print("\n🔹 圖片隱寫術工具（AES 加密 + Unicode 支援）🔹")
    print("1️⃣ 藏入加密訊息")
    print("2️⃣ 提取加密訊息")
    choice = input("請選擇模式 (1/2): ").strip()

    if choice == '1':
        hide_message()
    elif choice == '2':
        extract_message()
    else:
        print("❌ 無效選項，請輸入 1 或 2")

if __name__ == "__main__":
    main()

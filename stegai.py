#!/usr/bin/env python3
from PIL import Image
import base64
import os
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# -------------------------
# Fibonacci helpers (mod 256)
# -------------------------
def fibonacci_bytes(length):
    # return a bytes object length 'length' where each element is fib % 256
    if length <= 0:
        return b''
    seq = [1, 1]
    while len(seq) < length:
        seq.append((seq[-1] + seq[-2]) % 256)
    return bytes(seq[:length])

def fib_xor(data_bytes):
    fb = fibonacci_bytes(len(data_bytes))
    return bytes(b ^ f for b, f in zip(data_bytes, fb))

def fib_xor_reverse(data_bytes):
    # XOR is symmetric
    return fib_xor(data_bytes)

# -------------------------
# AES-GCM helpers
# -------------------------
def derive_key_from_password(password: str) -> bytes:
    # simple KDF: SHA256(password) -> 32 bytes key
    return hashlib.sha256(password.encode('utf-8')).digest()

def aesgcm_encrypt(plain_bytes: bytes, password: str) -> bytes:
    key = derive_key_from_password(password)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit nonce for AESGCM
    ct = aesgcm.encrypt(nonce, plain_bytes, None)  # returns ciphertext + tag
    return nonce + ct  # prepend nonce so we can decode later

def aesgcm_decrypt(enc_with_nonce: bytes, password: str) -> bytes:
    key = derive_key_from_password(password)
    if len(enc_with_nonce) < 12:
        raise ValueError("Encrypted payload too short (no nonce).")
    nonce = enc_with_nonce[:12]
    ct = enc_with_nonce[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# -------------------------
# Bit conversion helpers
# -------------------------
def bytes_to_bitstring(b: bytes) -> str:
    return ''.join(f'{byte:08b}' for byte in b)

def bitstring_to_bytes(s: str) -> bytes:
    # pad to multiple of 8 if necessary (shouldn't be)
    if len(s) % 8 != 0:
        s = s.ljust(((len(s) + 7) // 8) * 8, '0')
    return bytes(int(s[i:i+8], 2) for i in range(0, len(s), 8))

# -------------------------
# Hide message
# -------------------------
def hide_message():
    img_path = input("請輸入圖片檔名（例如 input.png）: ").strip()
    if not os.path.exists(img_path):
        print("❌ 找不到檔案，請確認路徑正確！")
        return

    message = input("請輸入要藏入的訊息（可貼藏文）:\n> ").strip()
    if not message:
        print("❌ 未輸入訊息，程式結束。")
        return

    password = input("請輸入加密密碼 (將用於 AES-GCM): ").strip()
    if not password:
        print("❌ 密碼不可為空")
        return

    # 1) UTF-8 -> bytes
    plain_bytes = message.encode('utf-8')

    # 2) Fibonacci XOR 混淆
    obf = fib_xor(plain_bytes)

    # 3) AES-GCM 加密 (返回 nonce + ct+tag)
    encrypted = aesgcm_encrypt(obf, password)

    # 4) Base64 編碼
    enc_b64 = base64.b64encode(encrypted)  # bytes

    # 5) 前綴 4-byte big-endian 長度
    length = len(enc_b64)
    if length > (2**32 - 1):
        print("❌ 編碼後資料過大，無法處理")
        return
    header = length.to_bytes(4, 'big')
    payload = header + enc_b64  # bytes to embed

    bit_payload = bytes_to_bitstring(payload)

    # 開啟圖片並檢查容量
    img = Image.open(img_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')
    pixels = img.load()
    width, height = img.size
    capacity_bits = width * height * 3
    if len(bit_payload) > capacity_bits:
        print(f"⚠️ 圖片容量不足。可藏 bits: {capacity_bits}, 需要: {len(bit_payload)}")
        print("請使用解析度更高或更大的圖片 (PNG/BMP 無損格式)。")
        return

    # embed
    idx = 0
    total = len(bit_payload)
    for y in range(height):
        for x in range(width):
            if idx >= total:
                break
            r, g, b = pixels[x, y]
            r = (r & ~1) | int(bit_payload[idx]) if idx < total else r
            idx += 1
            g = (g & ~1) | int(bit_payload[idx]) if idx < total else g
            idx += 1
            b = (b & ~1) | int(bit_payload[idx]) if idx < total else b
            idx += 1
            pixels[x, y] = (r, g, b)
        if idx >= total:
            break

    out_name = "stego_fib_aesgcm.png"
    img.save(out_name, "PNG")
    print(f"✅ 完成：已將加密後資料藏入 {out_name}")
    print(f"🔎 內嵌編碼長度 (bytes, base64): {length}")

# -------------------------
# Extract message
# -------------------------
def extract_message():
    img_path = input("請輸入要解析的圖片檔名（例如 stego_fib_aesgcm.png）: ").strip()
    if not os.path.exists(img_path):
        print("❌ 找不到檔案，請確認路徑正確！")
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

    # 我們先讀取前 32 bits (4 bytes) 的長度 header
    bit_acc = ""
    bits_needed_for_header = 32
    bits_collected = 0
    total_needed = None  # in bits

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bit_acc += str(r & 1); bits_collected += 1
            if bits_collected == bits_needed_for_header and total_needed is None:
                # compute header now if possible
                header_bits = bit_acc[:bits_needed_for_header]
                header_bytes = bitstring_to_bytes(header_bits)
                payload_len = int.from_bytes(header_bytes, 'big')  # length in bytes of base64 payload
                total_needed = bits_needed_for_header + payload_len * 8
                # continue collecting until total_needed reached
            if total_needed is not None and bits_collected >= total_needed:
                break

            bit_acc += str(g & 1); bits_collected += 1
            if bits_collected == bits_needed_for_header and total_needed is None:
                header_bits = bit_acc[:bits_needed_for_header]
                header_bytes = bitstring_to_bytes(header_bits)
                payload_len = int.from_bytes(header_bytes, 'big')
                total_needed = bits_needed_for_header + payload_len * 8
            if total_needed is not None and bits_collected >= total_needed:
                break

            bit_acc += str(b & 1); bits_collected += 1
            if bits_collected == bits_needed_for_header and total_needed is None:
                header_bits = bit_acc[:bits_needed_for_header]
                header_bytes = bitstring_to_bytes(header_bits)
                payload_len = int.from_bytes(header_bytes, 'big')
                total_needed = bits_needed_for_header + payload_len * 8
            if total_needed is not None and bits_collected >= total_needed:
                break
        if total_needed is not None and bits_collected >= total_needed:
            break

    if total_needed is None or bits_collected < total_needed:
        print("⚠️ 無法找到有效的前置長度或資料不完整。")
        return

    # 取得剛好需要的 bits
    bit_payload = bit_acc[:total_needed]
    # 轉回 bytes
    payload_bytes = bitstring_to_bytes(bit_payload)
    # first 4 bytes = length
    header = payload_bytes[:4]
    enc_b64 = payload_bytes[4:]
    try:
        encrypted = base64.b64decode(enc_b64)
    except Exception as e:
        print("⚠️ Base64 解碼失敗：", e)
        return

    try:
        # 解密 AES-GCM
        decrypted_obf = aesgcm_decrypt(encrypted, password)  # returns obfuscated bytes
        # Fibonacci 反混淆
        plain_bytes = fib_xor_reverse(decrypted_obf)
        message = plain_bytes.decode('utf-8')
        print("🔍 成功提取並解密訊息：")
        print(message)
    except Exception as e:
        print("⚠️ 解密或還原失敗：", e)

# -------------------------
# main
# -------------------------
def main():
    print("\n🔹 圖片隱寫術工具（Fibonacci 混淆 + AES-GCM）🔹")
    print("1️⃣ 藏入（Fibonacci XOR -> AES-GCM -> Base64 -> embed）")
    print("2️⃣ 提取（extract -> Base64 -> AES-GCM decrypt -> Fibonacci deobf）")
    choice = input("請選擇模式 (1/2): ").strip()
    if choice == '1':
        hide_message()
    elif choice == '2':
        extract_message()
    else:
        print("❌ 無效選項，請輸入 1 或 2")

if __name__ == "__main__":
    main()

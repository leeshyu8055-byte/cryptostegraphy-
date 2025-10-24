from PIL import Image
import base64
import os

# ===========================
# 🔹 藏入訊息
# ===========================
def hide_message():
    img_path = input("請輸入圖片檔名（例如 input.png）: ").strip()
    if not os.path.exists(img_path):
        print("❌ 找不到檔案，請確認路徑正確！")
        return

    message = input("請輸入要藏入的訊息（可輸入藏文或任意文字）:\n> ").strip()
    if not message:
        print("❌ 未輸入訊息，程式結束。")
        return

    # 將文字轉成 Base64（避免亂碼）
    data = base64.b64encode(message.encode('utf-8'))
    binary_data = ''.join(format(byte, '08b') for byte in data)

    # ✅ 加上結束標記（16 個 1 + 0）
    binary_data += "1111111111111110"

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
    print(f"📜 訊息長度：約 {len(data)} bytes")

    # 生成唯一檔案名稱
    count = 1
    while True:
        output_name = f"stego_{count:03d}.png"
        if not os.path.exists(output_name):
            break
        count += 1

    # 開始藏入資料
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

    img.save(output_name, "PNG")
    print(f"✅ 已成功將訊息藏入 {output_name}")


# ===========================
# 🔹 提取訊息
# ===========================
def extract_message():
    img_path = input("請輸入要解析的圖片檔名（例如 stego.png）: ").strip()
    if not os.path.exists(img_path):
        print("❌ 找不到檔案，請確認路徑正確！")
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

            # ✅ 偵測結束標記
            if binary_out.endswith("1111111111111110"):
                binary_out = binary_out[:-16]  # 去掉結尾標記
                break
        else:
            continue
        break

    # 將二進位轉回 bytes
    bytes_out = bytes(int(binary_out[i:i+8], 2) for i in range(0, len(binary_out), 8))

    try:
        decoded = base64.b64decode(bytes_out).decode('utf-8')
        print("🔍 成功提取藏文/訊息：")
        print(decoded)
    except Exception as e:
        print("⚠️ 無法正確解碼資料：", e)


# ===========================
# 🔹 主程式介面
# ===========================
def main():
    print("\n🔹 圖片隱寫術工具（支援藏文、Unicode）🔹")
    print("1️⃣ 藏入訊息")
    print("2️⃣ 提取訊息")
    choice = input("請選擇模式 (1/2): ").strip()

    if choice == '1':
        hide_message()
    elif choice == '2':
        extract_message()
    else:
        print("❌ 無效選項，請輸入 1 或 2")


if __name__ == "__main__":
    main()

用 AES-GCM（密鑰由密碼 SHA-256 衍生）加密混淆後的 bytes（含 12-byte nonce）

Base64 編碼加密結果，前面加 4-byte 大端長度（header），將整個 payload 以 LSB 藏入圖片

提取時：先讀 32 bits 取得長度，再讀完 payload，Base64 解碼 → AES-GCM 解密 → Fibonacci 反混淆 → 轉回文字
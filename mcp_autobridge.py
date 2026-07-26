"""
IDA Pro MCP AutoBridge 插件
============================
当 IDA Pro 加载二进制文件后，自动在二进制文件所在目录创建 .mcp.json，
使 Claude Code 能直接通过 MCP 协议连接当前 IDA 实例进行分析。

用户只需打开 IDA Pro 并加载文件，无需再手动执行：
    ida-pro-mcp.exe --install claude-code --transport streamable-http

工作原理：
  1. 等待 IDA 界面就绪（ready_to_run 钩子）
  2. 等待现有的 ida_mcp 插件启动 HTTP 服务器并写入发现文件
  3. 从发现文件中读取当前 IDA 实例的实际端口号
  4. 在二进制文件所在目录创建/更新 .mcp.json

多实例支持：
  每个 IDA 窗口会获得不同的端口（13337, 13338, ...），
  对应的 .mcp.json 分别写入各自二进制文件的目录，
  从不同目录启动 Claude Code 即可连接到正确的 IDA 实例。
  若同目录下有多个活跃 IDA 实例，自动追加带编号的条目（ida-pro-mcp-2, ...）。

依赖：
  - IDA Pro 7.7+
  - 现有的 ida_mcp 插件（会自动启动 HTTP 服务器并写入发现文件）

安装方法：
  复制此文件到 IDA Pro 的 plugins 目录：
    C:\D\tools\CTF\IDA_Pro_7.7\plugins\mcp_autobridge.py
"""

import json
import os
import socket
import time
import threading
from urllib.parse import urlparse

import idaapi
import ida_kernwin
import ida_nalt

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

MCP_SERVER_NAME = "ida-pro-mcp"

# 发现文件目录：ida_mcp 插件在此写入 instance_{port}.json
_INSTANCES_DIR = os.path.join(
    os.environ.get("APPDATA", ""), "Hex-Rays", "IDA Pro", "mcp", "instances"
)

# 轮询发现文件的最长等待时间（秒）
_DISCOVERY_TIMEOUT = 15.0
# 轮询间隔（秒）
_DISCOVERY_POLL_INTERVAL = 0.5


# ---------------------------------------------------------------------------
# 发现文件读取
# ---------------------------------------------------------------------------

def _get_instance_port():
    """读取当前 PID 对应的 MCP 实例端口号，未找到则返回 None"""
    current_pid = os.getpid()
    if not os.path.isdir(_INSTANCES_DIR):
        return None

    try:
        for name in os.listdir(_INSTANCES_DIR):
            if not name.startswith("instance_") or not name.endswith(".json"):
                continue
            filepath = os.path.join(_INSTANCES_DIR, name)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    info = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            if info.get("pid") == current_pid:
                port = info.get("port")
                host = info.get("host", "127.0.0.1")
                if port and isinstance(port, int):
                    return host, port
    except OSError:
        pass
    return None


def _wait_for_instance_port(timeout=_DISCOVERY_TIMEOUT):
    """轮询等待 ida_mcp 插件写入发现文件，返回 (host, port) 或 None"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _get_instance_port()
        if result is not None:
            return result
        time.sleep(_DISCOVERY_POLL_INTERVAL)
    return None


# ---------------------------------------------------------------------------
# .mcp.json 写入
# ---------------------------------------------------------------------------

def _get_binary_info():
    """获取当前加载的二进制文件名和目录（必须在主线程调用）"""
    binary = "未知文件"
    binary_dir = None
    try:
        input_file = ida_nalt.get_input_file_path()
        if input_file:
            binary = os.path.basename(input_file)
            binary_dir = os.path.dirname(input_file)
        else:
            binary = ida_nalt.get_root_filename() or "未知文件"
    except Exception:
        try:
            binary = ida_nalt.get_root_filename() or "未知文件"
        except Exception:
            pass
    return binary, binary_dir


def _read_mcp_json(filepath):
    """读取现有 .mcp.json，失败返回空字典"""
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError, FileNotFoundError):
        return {}


def _probe_url(url, timeout=1.0):
    """探测 URL 是否可达（用于判断旧实例是否仍在运行）"""
    try:
        parsed = urlparse(url)
        if parsed.hostname and parsed.port:
            with socket.create_connection((parsed.hostname, parsed.port), timeout=timeout):
                return True
    except (OSError, socket.timeout, ValueError):
        pass
    return False


def _write_mcp_json(binary_dir, host, port):
    """在二进制目录创建/更新 .mcp.json，指向正确的 IDA 实例。
    若同目录下已有其他活跃 IDA 实例，自动追加编号条目而非覆盖。"""
    mcp_json_path = os.path.join(binary_dir, ".mcp.json")
    expected_url = f"http://{host}:{port}/mcp"

    # 检查是否已是最新配置，避免不必要的写入
    existing = _read_mcp_json(mcp_json_path)
    existing_servers = existing.get("mcpServers", {})
    existing_entry = existing_servers.get(MCP_SERVER_NAME, {})
    if (existing_entry.get("url") == expected_url
            and existing_entry.get("type") == "http"):
        print(f"[MCP AutoBridge] .mcp.json 已是最新 ({expected_url})，跳过")
        return True

    # 如果 ida-pro-mcp 已被占用且旧实例仍存活，追加带编号的条目
    if MCP_SERVER_NAME in existing_servers:
        old_url = existing_servers[MCP_SERVER_NAME].get("url", "")
        if old_url and old_url != expected_url and _probe_url(old_url):
            i = 2
            while f"{MCP_SERVER_NAME}-{i}" in existing_servers:
                i += 1
            existing_servers[f"{MCP_SERVER_NAME}-{i}"] = {
                "type": "http",
                "url": expected_url,
            }
            try:
                with open(mcp_json_path, "w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2)
                    f.write("\n")
                print(f"[MCP AutoBridge] 检测到另一活跃实例 ({old_url})，追加为 {MCP_SERVER_NAME}-{i}")
                print(f"[MCP AutoBridge]   URL: {expected_url}")
                return True
            except OSError as e:
                print(f"[MCP AutoBridge] 写入 .mcp.json 失败: {e}")
                return False

    # 无冲突或旧实例已死：直接更新 ida-pro-mcp
    existing.setdefault("mcpServers", {})[MCP_SERVER_NAME] = {
        "type": "http",
        "url": expected_url,
    }

    try:
        with open(mcp_json_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
            f.write("\n")  # 末尾换行
        print(f"[MCP AutoBridge] ✓ 已创建/更新 {mcp_json_path}")
        print(f"[MCP AutoBridge]   URL: {expected_url}")
        return True
    except OSError as e:
        print(f"[MCP AutoBridge] 写入 .mcp.json 失败: {e}")
        return False


# ---------------------------------------------------------------------------
# 后台任务
# ---------------------------------------------------------------------------

def _auto_bridge_task(binary, binary_dir):
    """后台线程：等待 MCP 服务器就绪，然后写入 .mcp.json
    参数由主线程预先收集（ida_nalt 函数必须在主线程调用）"""
    print(f"[MCP AutoBridge] 等待 '{binary}' 的 MCP 服务器就绪...")
    result = _wait_for_instance_port()

    if result is None:
        print(f"[MCP AutoBridge] 超时: {_DISCOVERY_TIMEOUT}秒内未检测到 MCP 服务器启动")
        print("[MCP AutoBridge] 请确认 ida_mcp 插件已安装且 Autostart 已启用")
        return

    host, port = result
    print(f"[MCP AutoBridge] 检测到 MCP 服务器: {host}:{port}")
    _write_mcp_json(binary_dir, host, port)


# ---------------------------------------------------------------------------
# UI 钩子
# ---------------------------------------------------------------------------

class AutoBridgeUIHooks(ida_kernwin.UI_Hooks):
    """等待 IDA 界面完全就绪后，触发后台桥接任务"""

    def __init__(self):
        super().__init__()

    def ready_to_run(self):
        # 在主线程收集二进制文件信息（ida_nalt 函数必须在主线程调用）
        binary, binary_dir = _get_binary_info()
        if not binary_dir:
            print("[MCP AutoBridge] 无法获取二进制文件目录，跳过")
            self.unhook()
            return
        t = threading.Thread(
            target=_auto_bridge_task, args=(binary, binary_dir), daemon=True
        )
        t.start()
        self.unhook()


# ---------------------------------------------------------------------------
# 插件入口
# ---------------------------------------------------------------------------

class MCPAutoBridge(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "自动为当前二进制文件目录创建 MCP 桥接配置 (.mcp.json)"
    help = "MCP AutoBridge"
    wanted_name = "MCP AutoBridge"
    wanted_hotkey = ""

    def init(self):
        if not ida_kernwin.is_idaq():
            print("[MCP AutoBridge] idalib 模式，跳过")
            return idaapi.PLUGIN_KEEP

        self._hooks = AutoBridgeUIHooks()
        self._hooks.hook()
        print("[MCP AutoBridge] 已加载 — IDA 就绪后将自动配置 .mcp.json")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """手动触发：Edit → Plugins → MCP AutoBridge"""
        print("[MCP AutoBridge] 手动触发桥接配置...")
        binary, binary_dir = _get_binary_info()
        if not binary_dir:
            print("[MCP AutoBridge] 无法获取二进制文件目录，跳过")
            return
        t = threading.Thread(
            target=_auto_bridge_task, args=(binary, binary_dir), daemon=True
        )
        t.start()

    def term(self):
        if hasattr(self, "_hooks"):
            self._hooks.unhook()


def PLUGIN_ENTRY():
    return MCPAutoBridge()

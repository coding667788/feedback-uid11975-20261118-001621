"""HTTP 服务（标准库 http.server，多线程，每请求独立 SQLite 连接，无全局锁）。

日志只记录请求行与状态码，绝不记录请求体、密码或会话令牌。
"""
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import config
from .core import AuthError, AuthService


def _password_field(payload, key):
    value = payload.get(key)
    if not isinstance(value, str):
        raise AuthError(400, "bad_request", f"字段 {key} 缺失或类型错误")
    # 原始 UTF-8 字节：不 trim、不大小写转换、不 Unicode 规范化
    return value.encode("utf-8")


def _text_field(payload, key):
    value = payload.get(key)
    if not isinstance(value, str):
        raise AuthError(400, "bad_request", f"字段 {key} 缺失或类型错误")
    return value


def make_handler(service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "LocalAuth/1.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # 只含请求行/状态，不含请求体
            sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

        def _send(self, status, obj):
            body = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self):
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > config.MAX_BODY_BYTES:
                self._send(400, {"error": "bad_request"})
                return
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"error": "bad_request"})
                return
            if not isinstance(payload, dict):
                self._send(400, {"error": "bad_request"})
                return
            try:
                self._route(payload)
            except AuthError as exc:
                self._send(exc.status, {"error": exc.code})
            except Exception:
                self._send(500, {"error": "internal"})

        def _route(self, payload):
            if self.path == "/login":
                token = service.login(
                    _text_field(payload, "username"),
                    _password_field(payload, "password"),
                )
                self._send(200, {"token": token})
            elif self.path == "/change-password":
                service.change_password(
                    _text_field(payload, "username"),
                    _password_field(payload, "old_password"),
                    _password_field(payload, "new_password"),
                )
                self._send(200, {"ok": True})
            elif self.path == "/admin/reset":
                self._check_admin()
                service.admin_reset(
                    _text_field(payload, "username"),
                    _password_field(payload, "new_password"),
                )
                self._send(200, {"ok": True})
            elif self.path == "/session/check":
                result = service.check_session(_text_field(payload, "token"))
                self._send(200, result)
            else:
                self._send(404, {"error": "not_found"})

        def _check_admin(self):
            expected = os.environ.get("AUTH_ADMIN_TOKEN", "")
            if not expected:
                raise AuthError(503, "admin_disabled", "未配置管理员令牌")
            got = self.headers.get("X-Admin-Token", "")
            if not hmac.compare_digest(got.encode("utf-8"), expected.encode("utf-8")):
                raise AuthError(401, "invalid_admin_token")

    return Handler


def run(host, port, db_path):
    service = AuthService(db_path)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            # 客户端中途断开（如崩溃测试）属正常现象，不打印堆栈
            pass

    httpd = Server((host, port), make_handler(service))
    httpd.serve_forever()

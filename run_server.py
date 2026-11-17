"""启动一个认证服务进程。多个进程可共享同一 SQLite 数据库文件。"""
import argparse

from auth_service.server import run


def main():
    parser = argparse.ArgumentParser(description="本地口令认证服务")
    parser.add_argument("--db", required=True, help="SQLite 数据库文件路径")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    run(args.host, args.port, args.db)


if __name__ == "__main__":
    main()

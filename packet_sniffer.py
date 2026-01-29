import os
import sys
import getpass
import logging
import subprocess
import re
import ctypes
import traceback
from scapy.all import sniff, IP, TCP, Raw

BLACKLIST = set()

# ロギング設定
logging.basicConfig(filename='threat_log.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def check_platform():
    """現在のOSを判定"""
    return os.name

def is_admin_windows():
    """Windowsの管理者権限チェック"""
    if os.name != 'nt':
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_user_auth():
    """認証処理（管理者のみ）"""
    print("=== セキュリティスニッファー起動 ===")
    password = getpass.getpass("管理者パスワードを入力してください: ")
    if password != "SecurePass123":
        print("⚠️ 認証失敗。スクリプトを終了します。")
        sys.exit(1)

def load_blacklist():
    """ブラックリスト読み込み（IPリスト）"""
    try:
        with open("blacklist.txt", 'r') as f:
            return set(f.read().splitlines())
    except FileNotFoundError:
        return set()

def save_blacklist(ip):
    """ブラックリストにIPを追加"""
    with open("blacklist.txt", 'a') as f:
        f.write(f"{ip}\n")
    BLACKLIST.add(ip)

def block_ip_linux(ip):
    """Linux/macOS向けブロック（iptables）"""
    try:
        print(f"🚫 {ip} をブロックします。")
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        save_blacklist(ip)
    except Exception as e:
        logging.error(f"IPブロック失敗: {e}")

def block_ip_windows(ip):
    """Windows向けブロック（netsh）"""
    try:
        print(f"🚫 {ip} をブロックします。")
        subprocess.run(["powershell", "-Command", f"New-NetFirewallRule -DisplayName 'Block {ip}' -Direction Inbound -RemoteAddress {ip} -Action Block"], check=True)
        save_blacklist(ip)
    except Exception as e:
        logging.error(f"IPブロック失敗: {e}")

def detect_threats(packet):
    """危険な通信検出（HTTP/FTP）"""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # ブラックリストチェック
        if src_ip in BLACKLIST:
            print(f"⚠️ {src_ip} は既にブラックリストに登録されています。")
            return

        # HTTP（ポート80） or FTP（ポート21）の検出
        if dst_port == 80 or dst_port == 21:
            try:
                if not packet.haslayer(Raw):
                    return
                payload = str(packet[Raw].load).lower()
                if "http" in payload or "ftp" in payload:
                    print(f"[警告] {src_ip} から非暗号化通信（HTTP/FTP）が検出されました！")
                    logging.warning(f"{src_ip}: 非暗号化通信検出")

                    # SQLインジェクション検出
                    if re.search(r'(select|union|drop|delete)\b', payload):
                        print("🚨 SQLインジェクション攻撃が検出されました！")
                        logging.info(f"{src_ip}: SQL Injection Attempt")

                        # ブロック処理
                        if check_platform() == 'posix':
                            block_ip_linux(src_ip)
                        elif check_platform() == 'nt':
                            block_ip_windows(src_ip)

                    # XSS攻撃検出
                    elif re.search(r'<script>', payload):
                        print("🚨 XSS攻撃が検出されました！")
                        logging.info(f"{src_ip}: XSS Attack Detected")

                        # ブロック処理
                        if check_platform() == 'posix':
                            block_ip_linux(src_ip)
                        elif check_platform() == 'nt':
                            block_ip_windows(src_ip)

            except Exception as e:
                logging.error(f"検出失敗: {e}")

def main():
    get_user_auth()
    print("=== セキュリティスニッファーが起動しました ===")
    if os.name == 'nt' and not is_admin_windows():
        print("⚠️ 管理者権限で実行してください。")
        return
    try:
        print("監視中...（終了するには Ctrl+C）")
        sniff(prn=detect_threats, store=False)
    except Exception as e:
        print("❌ 実行中にエラーが発生しました。")
        print(f"エラー内容: {e}")
        logging.exception("実行中に例外が発生しました")
        print("ヒント: WindowsではNpcapが必要です（WinPcap互換モード推奨）。")
        try:
            input("Enterで終了します...")
        except Exception:
            pass

if __name__ == "__main__":
    BLACKLIST = load_blacklist()
    main()

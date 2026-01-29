import os
import sys
import getpass
from scapy.all import sniff, IP, TCP, Raw
import logging
import subprocess

# ロギング設定
logging.basicConfig(filename='threat_log.log', level=logging.INFO, format='%(asctime)s - %(message)s')

def check_platform():
    """現在のOSを判定"""
    return os.name

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
        if src_ip in load_blacklist():
            print(f"⚠️ {src_ip} は既にブラックリストに登録されています。")
            return

        # HTTP（ポート80） or FTP（ポート21）の検出
        if dst_port == 80 or dst_port == 21:
            try:
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
                        elif check,platform() == 'nt':
                            block_ip_windows(src_ip)

            except Exception as e:
                logging.error(f"検出失敗: {e}")

def main():
    get_user_auth()
    print("=== セキュリティスニッファーが起動しました ===")
    sniff(prn=detect_threats, store=False)

if __name__ == "__main__":
    import re
    main()

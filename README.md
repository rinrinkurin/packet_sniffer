# packet_sniffer

Windows/macOS/Linux で動作する簡易セキュリティスニッファーです。HTTP/FTP の平文通信や簡易的な攻撃パターン（SQLi/XSS）を検出し、必要に応じてIPをブロックします。

> ⚠️ 注意: 本ツールは学習/検証用途向けです。実運用の防御は専用のIDS/IPS製品やEDRの利用を推奨します。

## 機能

- HTTP/FTP の平文通信検出
- SQLインジェクション簡易検出
- XSS簡易検出
- IPブラックリスト保存（`blacklist.txt`）
- OS別のIPブロック
  - Windows: `New-NetFirewallRule`
  - Linux/macOS: `iptables`

## 動作要件

- Python 3.9+
- scapy
- Windowsの場合は Npcap（WinPcap互換モード推奨）
  - 未インストールの場合は L3 モードにフォールバック（制限あり）

## セットアップ

```bash
pip install scapy
```

### WindowsでのNpcap

Npcapをインストールし、**WinPcap互換モード**を有効にしてください。L2スニッフィングが可能になり、安定します。

## 使い方

```bash
python packet_sniffer.py
```

起動後、管理者パスワードの入力を求められます。

- デフォルトの管理者パスワード: `SecurePass123`
- 監視停止: `Ctrl + C`

## 出力ファイル

- `threat_log.log`: 検出イベントのログ
- `blacklist.txt`: ブロック済みIPの一覧

## 注意事項

- ルート/管理者権限が必要です。
- パケットキャプチャはネットワークのポリシーや法律に従って実施してください。
- L3モードでは一部のフィルタ/機能に制限があります。

## ライセンス

MIT

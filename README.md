# iptvscanner — NOWTV / Linux 組播盲掃

適合 Ubuntu 26.04 的 IPv4 UDP 組播掃描器。不需要知道 UDP 埠，透過 IGMP 訂閱群組，
擷取目的 IP 與埠。僅使用 Python 3 標準函式庫。

## NOWTV 四台限制

**舊版的高並行參數不適用於 NOWTV，可能漏掃。請重新下載此版本。**
本版預設與上限均為同時 4 個群組，預設觀察 5 秒；每次退組後暫停新加入 2 秒，
讓上游有機會釋放名額。退組不保證即時完成；仍漏掃時提高 `--cooldown` 或降低 `-c`。
程式只能限制自己的群組數，不能查看 ISP 已使用的名額。

掃描前關閉其他播放器與機頂盒接收。若仍有一台播放，最多使用 `-c 3`，
也要留意其他電腦或同一網卡既有的組播成員。網卡需已連到可接收 IPTV 的 ISP 網路，
具有 IPv4 位址；工具不會設定 VLAN、認證或路由。需要 VLAN 時指定 VLAN 子介面。
原始封包擷取需要 root 或 CAP_NET_RAW。

## 已知範圍與 M3U

解壓後進入目錄，**scanner.py 與 services.py 必須放在同一目錄**。

```bash
# 239.255.0.0 到 239.255.7.255，共 2048 個位址。
sudo python3 scanner.py -i ens256 -r 239.255.0.0/21 -c 4 --wait 5 --cooldown 2 --rate 4 -o /tmp/nowtv
```

輸出 `/tmp/nowtv.m3u`、`/tmp/nowtv.json`；每 10 秒保存，結束或 Ctrl+C 也會保存。
同前綴舊結果會被取代，不同掃描請使用不同前綴。強制 kill 或斷電無法保證最後保存。
這組參數掃完整段約為一小時量級，依加入、退組及收流延遲而變。

漏掃或未取得名稱可用保守參數重新掃描：

```bash
sudo python3 scanner.py -i ens256 -r 239.255.0.0/21 -c 3 --wait 10 --cooldown 5 --rate 2 --passes 2 -o /tmp/nowtv-recheck
```

兩輪會合併該次執行的發現，並非讀入舊 M3U。先拿包含已知可播放頻道的小範圍測試，
確認收流正常後再長時間掃描。無回應不表示一定沒有頻道。

## Service name 命名

解析 UDP MPEG-TS 或 RTP MPEG-TS 中 PID 0x11 的 DVB SDT actual table 及
service descriptor 0x48，取得 service_id、service name、provider。
支援跨 TS 封包重組、連續計數檢查、MPEG CRC 驗證。
擷取完整未分片 UDP 封包，避免 SDT 在 UDP 後段時被截斷。

有名稱時，M3U 格式例如（下列不是實測頻道資料）：

```text
#EXTM3U
#EXTINF:-1,NOW News
#EXTVLCOPT:program=332
udp://@239.255.1.2:54321
```

同串流若含多個 service，會輸出多筆名稱，使用 VLC 的 program 選項區分；
其他播放器不一定支援此選項。JSON 的 stream 內包含 `services` 清單。
沒有 SDT、觀察時間不足或無法解析時保留 `IP:port`，不猜頻道名稱。

文字支援 ASCII、UTF-8、UTF-16BE、部分 ISO-8859 與 DVB 指定的中韓文字編碼。
未完整實作預設 ISO-6937 的非 ASCII 字元，無法解碼時以替代字元呈現。
不做 EPG、OCR、外部名稱查詢或解密。

## 探索未知範圍

```bash
# 擴大至 239.255.*.*，仍最多四台。
sudo python3 scanner.py -i ens256 -r 239.255.0.0/16 -o /tmp/nowtv-expanded

# 支援多段 CIDR 或含起訖 IP；重疊地址只計一次。
sudo python3 scanner.py -i ens256 -r 239.255.0.0/21 -r 239.255.8.0-239.255.15.255 -o /tmp/nowtv-more

# 不連網的地址數與時間下限估計。
python3 scanner.py -i ens256 -r 239.255.0.0/21 --dry-run
```

省略 `-r` 代表完整 `224.0.0.0/4`，共 268,435,456 個位址，不是短時間能完成的工作。
時間估計不含退組冷卻、設備延遲等額外耗時。沒有通用方式向 ISP 列舉所有頻道；
四台限制不能靠增加執行緒繞過。建議優先探索已知範圍附近，再以長等待複查。

## 診斷與測試

```bash
ip -s link show dev ens256
cat /tmp/nowtv.json
python3 -m unittest -v
```

JSON 記錄加入失敗、擷取丟包、封包數、第一個來源 IP、服務名稱與掃描狀態。
網卡 RX dropped 是累計指標，和此次 packet socket 的 `capture_drops` 不同。
`scan_complete` 只表示觀察窗全部完成且未記錄到加入錯誤/擷取丟包，不保證所有頻道均發現。
不修改網卡、路由或 sysctl；不處理 IPv4 分片、IPv6 或 SSM 指定來源。
發現的 UDP 流量是候選，TS/RTP 也是初判，不保證能播放。

結束碼：0 表示觀察窗完成且未記錄到加入錯誤/擷取丟包；2 表示加入錯誤或擷取丟包；
1 為設定/執行錯誤；130 為中斷。

測試含真實 Linux loopback 組播收包、核心 BPF，以及注入擷取來源的排程、冷卻、
SDT 服務名稱/重組/CRC、輸出與中斷測試。
雲端開發機缺少 CAP_NET_RAW，也無法連到你的 ISP；尚未在 Ubuntu 26.04/NOWTV 實測。

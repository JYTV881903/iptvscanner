# iptvscanner

Linux IPv4 UDP 組播盲掃工具，適合在 Ubuntu 26.04 的 IPTV 接收介面執行。
不需要知道 UDP 埠號，也不需要掃描 65535 個埠。工具透過 IGMP 加入組播群組，
持續擷取該介面收到的 IPv4 UDP 封包，自動記錄目的 IP、埠及第一個來源 IP。

使用 Python 3 標準函式庫，沒有 pip 依賴。這是新實作，未複製 Windows 參考專案的程式碼。

## 在你的 Ubuntu 上執行

網卡必須已接到可接收 IPTV 的 ISP 網路，具有 IPv4 位址。
工具不會替你設定 VLAN、DHCP、路由或 ISP 認證。需要 VLAN 時請指定 VLAN 子介面。
以下命令在儲存庫目錄執行。原始封包擷取需要 root 或 CAP_NET_RAW。

```bash
python3 --version
ip -s link show dev ens256

# 小範圍功能測試；可換成一段包含已知頻道的網段。
sudo python3 scanner.py -i ens256 -r 239.0.0.0/24 -c 16 --wait 2 -o /tmp/iptv-check

# 完整 IPv4 組播盲掃，不預先指定 UDP 埠；Ctrl+C 會保存目前結果。
sudo python3 scanner.py -i ens256 -c 32 --wait 1.5 --rate 64 -o /tmp/iptv-full

# 若 ISP 已知使用 239/8，集中掃這一段可大幅縮短時間。
sudo python3 scanner.py -i ens256 -r 239.0.0.0/8 -c 32 --wait 1.5 --rate 64 -o /tmp/iptv-239

# 支援多段 CIDR 或含起訖的 IP 範圍；重疊位址只掃一次。
sudo python3 scanner.py -i ens256 -r 239.1.0.0/16 -r 239.2.1.1-239.2.1.254 \
  -c 64 --wait 2 --rate 128 --passes 2 -o /tmp/iptv-results
```

輸出 `<prefix>.json` 和 `<prefix>.m3u`；同名結果會被取代。每 10 秒保存一次，正常結束或
Ctrl+C 時也會保存。請對不同掃描使用不同輸出前綴。JSON 保留封包數、負載位元組數、
加入失敗、擷取丟包及掃描完成狀態。M3U 使用 `udp://@IP:port`，初步辨識到 RTP MPEG-TS
則使用 `rtp://@IP:port`。所有發現項目都是 UDP 串流候選，不保證是可播放電視頻道。

## 掃描速度與完整性的限制

完整 `224.0.0.0/4` 有 **268,435,456** 個位址；`239.0.0.0/8` 有 **16,777,216** 個。
不是所有位址都能由 ISP 提供或轉送，例如 224.0.0/24 是本地控制範圍。
沒有通用協定能向 ISP 查詢「所有存在的頻道」，只能逐群組訂閱並等待流量。
沉默群組也可能受 VLAN、認證、SSM、IGMP 限額、速率限制或啟播延遲影響，不能視為不存在。

執行前可查看不連網的理想時間估計：

```bash
python3 scanner.py -i ens256 --dry-run -c 32 --wait 1.5 --rate 64
```

以這組保守參數估計，全 /4 的理想時間約 **146 天**，239/8 約 **9.1 天**。
這不包含額外延遲，不是實測速度。若已知頻道在小範圍測試中可靠出現，才逐步提高 `-c`
與 `--rate`，或縮短 `--wait`。並行 64 個 8 Mbps 頻道可能引入約 512 Mbps 流量；
過高並行數可能超過光貓/交換器的群組上限或造成丟包。

`--wait` 是每個群組加入後的觀察秒數，預設 1.5。程式不會因第一個埠有回應就立即退組，
以保留發現同組其他埠的機會。`--passes 2` 會完整重掃兩次並合併結果；它增加觀察機會，
也會倍增掃描時間。無回應不代表一定沒有串流；應用較長等待時間複查重要網段。

程式使用每群組一個加入 socket，避免每個 socket 的組播成員數限制，仍受程序 FD 上限
及上游設備限制。大量並行時可先看 `ulimit -n`；程式會檢查 FD 預算。
接收 socket 在開始訂閱前就建立，使用核心 BPF 過濾 UDP 組播，只擷取封包前 512 bytes；
統計的 payload_bytes 來自 UDP 長度欄位，不是解碼量或完整錄影。
不處理 IPv4 分片、不加入 IPv6 組播、不做 SSM 來源指定、不解密，也不解析頻道名稱。
RTP/TS 是啟發式辨識，後續可用 VLC/ffprobe 確認。

如果小範圍測試沒有發現頻道，先將同一範圍換成包含一個已知可播放頻道的網段，
並提高 `--wait 5`，確認 ISP 連線可用後再開始長時間盲掃。
`ip -s link show dev ens256` 的 RX dropped 是網卡累計指標；JSON 的 capture_drops
是此次 packet socket 的核心丟包數，兩者不同。工具不會自動修改網卡或 sysctl。

## 開發與驗證

```bash
python3 -m unittest -v
```

測試涵蓋範圍合併、未知 UDP 埠、IPv4 options、TS/RTP 初判、畸形與分片封包、
核心 BPF 驗證及過濾、Linux loopback 真實組播加入與收包，及以注入擷取來源驗證的
並行排程、多輪掃描、輸出、錯誤與中斷清理。
雲端開發機未必有 CAP_NET_RAW，測試不能替代 Ubuntu 26.04 上的 AF_PACKET 實際抓包
及你的 ISP 實測。結束碼：0 為掃描迴圈完成且未觀測到加入失敗/擷取丟包；
2 為加入失敗或擷取丟包；1 為設定/執行錯誤；130 為中斷。0 不代表所有頻道均已發現。

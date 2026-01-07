# ONVIF Profile S 技術規格（適用於 rv1106-rkipc）

## 1. 總體目標

- 在現有 RTSP 串流基礎上，新增 ONVIF Profile S 相容服務，使設備可被 ONVIF Device Manager / NVR 自動發現與整合
- HTTP 服務使用 port 8080 或 8899（可於 ini 設定）
- 認證採用 UsernameToken Digest（與 Web/RTSP 共用帳密）
- 儲存與設定沿用現有 `rk_param_*` + ini 機制

---

## 2. 系統架構

### 2.1 新增模組結構（建議放在 `common/onvif/`）

```
common/onvif/
├── onvif_main.c          # 初始化/執行緒/服務啟停
├── onvif_httpd.c         # 輕量 HTTP server（SOAP over HTTP）
├── onvif_wsdd.c          # WS-Discovery (UDP 3702)
├── onvif_device.c        # Device Service handlers
├── onvif_media.c         # Media Service handlers
├── onvif_auth.c          # UsernameToken Digest 認證
├── onvif_util.c          # UUID/Scopes/XAddr/時間/IP 取得等工具
└── onvif.h               # 公共定義
```

### 2.2 與現有系統整合點

- **設定系統**：沿用 `rk_param_get_string/int()` 讀取 `/userdata/rkipc.ini`
- **網路資訊**：使用 `rk_network_ipv4_get()`/`rk_network_get_mac()` 取 IP/MAC
- **RTSP URL**：由 `rkipc_rtsp_init()` 的參數或 ini 決定，回傳給 ONVIF GetStreamUri
- **裝置資訊**：映射 `system.device_info` 到 ONVIF DeviceInformation

---

## 3. 服務端點與 URL

| 服務 | 路徑 | 端口 | 說明 |
|------|------|------|------|
| Device Service | `/onvif/device_service` | 8080/8899 | 設備資訊、能力、網路、時間、使用者 |
| Media Service | `/onvif/media_service` | 8080/8899 | Profile、Stream URI、Encoder/Source Configuration |
| WS-Discovery | UDP multicast 239.255.255.250:3702 | - | Probe/Hello/Bye |

---

## 4. INI 新增設定節（建議）

```ini
[onvif]
enable = 1
http_port = 8080
wsdd_enable = 1
scopes = onvif://www.onvif.org/Profile/Streaming
```

---

## 5. Device Service 實作要點

### 5.1 GetDeviceInformation

| ONVIF 欄位 | 來源（ini key） |
|------------|-----------------|
| Manufacturer | `system.device_info:manufacturer` |
| Model | `system.device_info:model` |
| FirmwareVersion | `system.device_info:firmware_version` |
| SerialNumber | `system.device_info:serial_number` |
| HardwareId | `system.device_info:hardware_id` |

### 5.2 GetCapabilities

- 回傳 Media 的 XAddr（`http://<ip>:<port>/onvif/media_service`）
- 其他服務（Imaging/PTZ/Events）暫不回傳或回空

### 5.3 GetNetworkInterfaces

- 用 `rk_network_ipv4_get()` 取 IPv4/netmask/gateway
- 用 `rk_network_get_mac()` 取 MAC

### 5.4 GetSystemDateAndTime

- 回目前系統時間（可先用 `time(NULL)`）
- SetSystemDateAndTime 後續再做

### 5.5 使用者管理（第一版）

- 只讀 `[user.0]`（admin）
- 暫不支援 CreateUsers/SetUser，回 NotSupported

---

## 6. Media Service 實作要點

### 6.1 Profile 映射（至少 2 個）

| ProfileToken | 對應 ini 節 | 說明 |
|--------------|--------------|------|
| profile0 | video.0 | mainStream |
| profile1 | video.1 | subStream |

### 6.2 GetStreamUri

- 回 `rtsp://<ip>:554/<rtsp_url_0>`（對應 profile0）
- `<ip>` 由 `rk_network_ipv4_get()` 取得
- `<rtsp_url_0>` 由 `rkipc_rtsp_init()` 參數或 ini 決定

### 6.3 VideoEncoderConfiguration 映射

| ONVIF 欄位 | 來源（ini key） |
|------------|-----------------|
| Encoding | `video.X:output_data_type`（H.264/H.265） |
| Resolution | `video.X:width`/`height` |
| Quality | `video.X:rc_quality`（可映射為數值） |
| RateControl | `video.X:rc_mode`（CBR/VBR） |
| FrameRate | `video.X:dst_frame_rate_num/dst_frame_rate_den` |
| BitrateLimit | `video.X:max_rate` |
| GovLength | `video.X:gop` |

### 6.4 VideoSourceConfiguration

- Name: "VideoSource0"
- Bounds: 對應 sensor 最大解析度（可從 `video.X:max_width/max_height` 取）

---

## 7. WS-Discovery 實作要點

### 7.1 Probe 回覆範例

```xml
<SOAP-ENV:Envelope ...>
  <SOAP-ENV:Body>
    <d:ProbeMatches>
      <d:ProbeMatch>
        <d:Scopes>onvif://www.onvif.org/Profile/Streaming</d:Scopes>
        <d:Types>dn:NetworkVideoTransmitter</d:Types>
        <d:XAddrs>http://<ip>:<port>/onvif/device_service</d:XAddrs>
      </d:ProbeMatch>
    </d:ProbeMatches>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>
```

- `<ip>` 由 `rk_network_ipv4_get()` 取得
- `<port>` 由 `onvif:http_port` ini 決定

### 7.2 Hello/Bye（可後補）

- 啟動時送 Hello，關閉時送 Bye
- 若時間不足可先只做 Probe 回覆

---

## 8. 認證機制（UsernameToken Digest）

- 採用 WS-Security UsernameToken PasswordDigest
- 密碼來源：`[user.0]` 的 `password`（目前是 base64，建議改為 hash）
- Nonce + Created + PasswordDigest 計算方式參考 ONVIF 規範
- 每個 SOAP 請求都檢查 Authorization Header（若未帶則回 401）

---

## 9. 與現有 RTSP 整合

- ONVIF Media Service 只回 URL，不干擾現有 RTSP server
- 確保 RTSP URL 可被 NVR 直接拉流
- 若 RTSP 有認證，ONVIF 與 RTSP 帳密應保持一致

---

## 10. 安全與相容性建議

- 密碼建議改為不可逆 hash（salted SHA-256 或 bcrypt）
- HTTP 可選擇開啟 Basic Auth（但 ONVIF 標準建議用 UsernameToken）
- 避免在 SOAP 回應中洩露系統路徑或敏感資訊
- 考慮加入 CORS Header 以便 Web 整合

---

## 11. 驗證工具

- ONVIF Device Manager（Windows）
- VLC（測 RTSP URL）
- Wireshark（抓 WS-Discovery / SOAP 封包）
- curl（測 HTTP/SOAP 端點）

---

## 12. 後續擴展方向（Profile S → T）

- Imaging Service：映射 ISP 調整參數（亮度/對比/曝光/日夜切換）
- Events：移動偵測/入侵事件（對接 IVS/NPU）
- PTZ：若有硬體支援
- Profile T：H.265 + Events + Metadata

---

## 13. 注意事項

- HTTP Server 必須支援 Keep-Alive（SOAP 常用）
- XML/SOAP Namespace 要正確（`http://www.onvif.org/ver10/device/wsdl` 等）
- 時區建議回 UTC + LocalTimeOffset
- 若系統有多網卡，建議只回第一個有效 IP

---

## 14. 參考實作

- gSOAP（C 語言 SOAP 框架，常用於 ONVIF）
- libmicrohttpd（輕量 HTTP server）
- 自帶 HTTP + XML parser（最小化依賴）

---

## 15. 版控與測試

- 每個 Service Handler 建議獨立單元測試
- WS-Discovery 可用 `tcpdump udp port 3702` 驗證
- ONVIF Device Manager 加入設備後，檢查是否能取得 RTSP URL 並播放

---

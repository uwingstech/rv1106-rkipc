# ONVIF Profile S 實作執行計畫（rv1106-rkipc）

## 項目總覽

- 目標：在現有 RTSP 串流基礎上，新增 ONVIF Profile S 相容服務
- HTTP 服務端口：8080 或 8899（可設定）
- 認證：UsernameToken Digest（與 Web/RTSP 共用帳密）
- 時程：分 4 個里程碑，每個里程碑可獨立驗證

---

## 里程碑 1：基礎 HTTP + SOAP 框架（預估 3-5 天）

### 目標
- 建立可運行的 HTTP server，能回應 SOAP 請求
- 完成基本 Device Service（GetDeviceInformation）

### 任務清單
- [ ] **建立 `common/onvif/` 目錄結構**
- [ ] **實作輕量 HTTP server（onvif_httpd.c）**
  - 支援 POST（SOAP over HTTP）
  - 支援 Keep-Alive
  - 端口 8080（可由 ini 設定）
- [ ] **實作 SOAP XML 基本解析/生成（onvif_util.c）**
  - Namespace 處理
  - SOAP Envelope/Body 基本結構
- [ ] **實作 Device Service：GetDeviceInformation**
  - 映射 `system.device_info` 到 ONVIF 回應
- [ ] **實作基本認證檢查（onvif_auth.c）**
  - 先做「無認證」版本，後續再加 UsernameToken
- [ ] **在 main.c 加入 `rkipc_onvif_init()`/`deinit()`**
- [ ] **ini 新增 `[onvif]` 節（enable/http_port）**

### 驗證方式
- curl 測試：
  ```bash
  curl -X POST http://<ip>:8080/onvif/device_service \
       -H 'Content-Type: text/xml; charset=utf-8' \
       -d @GetDeviceInformation.xml
  ```
- 檢查回應是否正確（SOAP XML with Manufacturer/Model/Serial/Firmware）

---

## 里程碑 2：Media Service + RTSP URL 映射（預估 3-4 天）

### 目標
- 完成 Media Service 核心功能
- ONVIF Device Manager 能取得 RTSP URL 並播放

### 任務清單
- [ ] **實作 Media Service：GetProfiles**
  - 回 profile0（mainStream）/profile1（subStream）
- [ ] **實作 Media Service：GetStreamUri**
  - 回 `rtsp://<ip>:554/<rtsp_url_0>`（對應 profile0）
  - IP 由 `rk_network_ipv4_get()` 取得
- [ ] **實作 Media Service：GetVideoEncoderConfigurations**
  - 映射 `video.0/1` 的解析度/碼率/GOP/編碼格式
- [ ] **實作 Media Service：GetVideoSourceConfigurations**
  - 回 sensor 最大解析度
- [ ] **實作 GetCapabilities**
  - 回 Media Service XAddr
- [ ] **更新 ini：新增 `onvif:scopes`（Profile/Streaming）**

### 驗證方式
- ONVIF Device Manager：
  1. 手動加入設備（輸入 Device Service URL）
  2. 檢查是否能取得 Media Profiles
  3. 檢查是否能取得 RTSP URL
  4. 用 VLC 播放 ONVIF 回傳的 RTSP URL

---

## 里程碑 3：WS-Discovery（自動發現）（預估 2-3 天）

### 目標
- 設備能被 ONVIF Device Manager 自動掃描到

### 任務清單
- [ ] **實作 WS-Discovery（onvif_wsdd.c）**
  - UDP socket bind 3702
  - 處理 Probe 請求並回覆
- [ ] **Probe 回覆內容**
  - Types: `dn:NetworkVideoTransmitter`
  - Scopes: `onvif://www.onvif.org/Profile/Streaming`
  - XAddrs: Device Service URL
- [ ] **實作 Hello/Bye（可選）**
  - 啟動時送 Hello，關閉時送 Bye
- [ ] **多播處理**
  - Join multicast group 239.255.255.250
- [ ] **錯誤處理與重試機制**

### 驗證方式
- ONVIF Device Manager：
  1. 點選「Discover」
  2. 檢查你的設備是否出現在列表
  3. 點選加入後，重做里程碑 2 的驗證
- Wireshark：
  - 抓 UDP 3702 封包，確認 Probe/Match 訊息

---

## 里程碑 4：認證與市場相容性（預估 3-4 天）

### 目標
- 支援 UsernameToken Digest 認證
- 與主流 NVR 相容

### 任務清單
- [ ] **實作 UsernameToken Digest（onvif_auth.c）**
  - Nonce + Created + PasswordDigest 計算
  - SOAP Header 處理
- [ ] **帳密來源**
  - 讀取 `[user.0]`（admin）
  - 密碼目前為 base64，建議改為 hash
- [ ] **所有 SOAP 請求都檢查認證**
  - 未帶認證回 401 + WWW-Authenticate
- [ ] **GetUsers/GetServiceCapabilities**
  - 回傳使用者資訊（admin）
- [ ] **測試主流 NVR 相容性**
  - 例如 Hikvision iVMS、Milestone、Blue Iris 等

### 驗證方式
- ONVIF Device Manager：
  - 設定帳密（admin）
  - 檢查是否能正常連接
- NVR 軟體：
  - 新增設備，輸入帳密
  - 檢查是否能取得影像

---

## 後續擴展（Profile S → T）

### Imaging Service（預估 5-7 天）
- [ ] **GetImagingSettings**：亮度/對比/飽和度/銳利度/色調
- [ ] **SetImagingSettings**：對應 `isp.0.adjustment`
- [ ] **GetOptions**：支援的範圍與步進
- [ ] **GetMoveOptions**：若有光圈/焦距控制

### Events Service（預估 7-10 天）
- [ ] **GetEventProperties**：事件類型與訊息結構
- [ ] **CreatePullPointSubscription**：事件訂閱
- [ ] **PullMessages**：事件推送
- [ ] **映射 IVS/NPU 事件**：移動偵測/區域入侵 → ONVIF Topics

### PTZ Service（若有硬體）
- [ ] **GetNodes**：PTZ 節點資訊
- [ ] **ContinuousMove/AbsoluteMove**：雲台控制

---

## 風險與對策

### 風險 1：HTTP/SOAP 框架複雜度
- **對策**：先做最小可用版本，只用字串處理，不引入第三方框架

### 風險 2：XML/SOAP Namespace 錯誤
- **對策**：用 ONVIF Device Manager 的請求當範本，確保 Namespace 一致

### 風險 3：認證相容性
- **對策**：先用 ONVIF Device Manager 測試，再擴展到 NVR

### 風險 4：多網卡 IP 問題
- **對策**：只回第一個有效 IP，或讓 ini 可指定網卡

---

## 資源需求

### 開發環境
- Linux 開發機（與目標平台相同架構）
- ONVIF Device Manager（Windows）
- Wireshark（網路封包分析）
- VLC（RTSP 播放測試）

### 第三方函式庫（可選）
- gSOAP（完整 SOAP 框架）
- libmicrohttpd（輕量 HTTP server）
- libxml2（XML 處理）

---

## 測試策略

### 單元測試
- 每個 Service Handler 獨立測試
- SOAP 請求/回應格式驗證

### 整合測試
- ONVIF Device Manager 完整流程
- NVR 軟體相容性測試

### 回歸測試
- 每次修改後重跑里程碑驗證
- 確保 RTSP 串流不受影響

---

## 交付物

### 程式碼
- `common/onvif/` 完整模組
- `main.c` 整合點
- ini 範例檔案

### 文件
- API 對應表（ini → ONVIF）
- 錯誤碼對應表
- 部署與設定手冊

### 測試報告
- ONVIF Device Manager 測試結果
- NVR 相容性測試報告
- 效能測試（記憶體/CPU）

---

## 時程總結

| 里程碑 | 預估天數 | 主要交付 |
|--------|----------|----------|
| 1：HTTP + SOAP 基礎 | 3-5 天 | Device Service 基本功能 |
| 2：Media Service | 3-4 天 | RTSP URL 映射 |
| 3：WS-Discovery | 2-3 天 | 自動發現 |
| 4：認證與相容性 | 3-4 天 | 完整 Profile S 相容性 |
| **總計** | **11-16 天** | **可上市 ONVIF Profile S IPC** |

---

## 成功標準

- ONVIF Device Manager 能自動發現設備
- 能取得 RTSP URL 並播放
- 支援 admin 帳密認證
- 與至少 2 種主流 NVR 相容
- 不影響現有 RTSP 串流功能

---

# Finding 驗證模型

**繁體中文** | [English](FINDING_VALIDATION.md)

ProofClaw 對每項 Finding 都必須分別回答兩個問題：

1. **Evidence 是否完整且可歸屬於這次 Engagement？** 可檢查儲存的位元組、Canonical Metadata、
   順序與 Hash Chain 是否遭更動；Evidence 也必須來自同一 Engagement 的 Action。
2. **Evidence 是否足以證明這項具體安全主張？** Hash 正確不代表已確認目標的預期權限政策，
   也不代表漏洞可被利用。主張需要明確的驗證方法、預期結果、實際結果，以及排除其他合理原因的脈絡。

離線 Disclosure Bundle 驗證器會檢查封裝及 Digest Manifest。Bundle 會記錄 Evidence Chain
的驗證結果，但不包含原始 Evidence，所以離線驗證器無法重新計算整條 Chain；它也**不會**重送請求、
確認授權假設、證明漏洞成立，或辨識 Bundle 作者的身分。

## 目前邊界

- 受控的被動 HTTP Assessment 可將措辭精確的 Header 或傳輸性質自動標為 `verified`。
  分析前，它會從持久化的 Canonical `http-v1` 原始位元組重建回應，不信任呼叫端提供的回應摘要。
  它會驗證整條 Engagement Evidence Chain、受控的擷取來源，以及 Evidence 所屬的同一
  Engagement Action。Action 必須為 `SUCCEEDED`，執行時間、目標、Query、參數 Digest
  與最終回應目標須和擷取內容一致。Canonical Metadata 必須記錄相符的允許 Scope Decision；
  如需 Approval，也要確認它綁定該 Action，且在 Action 開始時有效。非 2xx 回應不會產生
  被動 Finding。這些檢查只證明所觀察的性質，不代表已成功利用漏洞。
- 僅憑 Cookie 名稱推測其敏感用途，無法證明它真的是敏感 Cookie。因此，即使回應明顯缺少
  `Secure`、`HttpOnly` 或 `SameSite`，這類推測仍維持 `candidate`。
- OpenAPI 宣告與未登入的成功回應會產生 `candidate`：僅靠 API 規格，無法確認回傳內容
  原本應該保密。Active-safe 探測與報告清單只讀取通過驗證的成功 HTTP 擷取；錯誤頁連結及
  外觀像 OpenAPI 的錯誤回應不會啟動後續請求。
- `nuclei` Parser 將有目標來源資料支持的特定觀察列為 `pending_verification`，
  `httpx` Parser 則列為 `candidate`；其他 Scanner 紀錄會被排除。其輸出仍需獨立審查，
  才能成為 verified 主張。Template Severity、CVE 標籤或 LLM 斷言都不是影響的證據。
- 自主 Mission 流程將 Scanner 觀察轉為 Candidate 與 Lead。`VerificationOutcome`
  根據結構化答案計算判定，決定性的授權 Oracle 可比較不同身分的 Probe。未說明驗證
  方法的 Outcome 不會自動成為 `verified`。持久化已驗證 Finding 時，Repository 會檢查
  Evidence 歸屬與完整性；但 Outcome 的 Probe 欄位尚未從已儲存的 Capture 獨立推導，
  也尚未核對 Action 授權及預期安全政策。在完成語意綁定前，應將此路徑視為調查輔助。
- `POST /api/v1/automation/verify` 根據呼叫端提供的 Observation 計算 `pass`、
  `candidate` 或 `inconclusive`。其結果不是持久化的 Finding 決定，也不能取代以 Evidence
  為基礎的審查。Planner／Operator／Verifier 的 Next-step Endpoint 只選擇下一個角色，
  不會重新測試目標。
- Finding Review API 使用樂觀版本檢查與 Audit Event 處理人工決定。
  每次持久化 `verified` Finding，Repository 都會檢查整條 Engagement Evidence Chain、
  連結 Evidence 的存在與歸屬；人工升級另需明確的驗證方法及審查理由。
  上述 Action、目標、參數、Scope Decision 與 Approval 檢查僅適用於受控的被動自動路徑；
  一般人工審查與 Mission Finding 尚未具備這種型別化綁定，也尚未檢查回應能否證明主張。
  差異比較的審查會拒絕位元組完全相同的測試與對照擷取，但目前不會判斷變化是否足以支持主張。
  詳見 [Finding 審查](FINDING_REVIEW.zh-TW.md)。
- 現有 Scope 紀錄不是不可變的歷史快照。被動驗證器會檢查擷取中記錄的允許決定與 Action
  綁定，但無法完整重建送出請求當時的每條 Scope 規則。

## 主張與證明條件

驗證的單位是**針對特定目標及條件的具體主張**。例如「此回應中 Cookie X 缺少 `HttpOnly`」
可以由單次擷取證明；「使用者 A 可讀取使用者 B 的私人紀錄」則需要兩個身分、已知屬於 B 的
紀錄、可比較的請求，以及顯示 B 資料的回應。單靠狀態碼不足以證明。

每個驗證案例應記錄：

- 受影響的目標、具體主張及預期的安全邊界；
- Finding／Engagement ID、規則及 Verifier 版本、Action ID、Approval 與參數 Digest，
  以及按不同用途連結的 Evidence ID；
- 每次擷取使用的 Principal 或匿名脈絡，但不匯出秘密；
- 最小且安全的重現步驟、關鍵觀察欄位及限制；
- 判定（`verified`、`rejected` 或 `needs_manual_review`／`inconclusive`）、理由、
  Reviewer／Verifier 身分、時間及重試紀錄。

`observed` 指一份來自目標的資料，對照固定預期即可直接證明措辭精確的主張。
不得把 Banner、指紋、Scanner Match 或可連線的 Endpoint，擴張成沒有證據支持的 CVE
或存取控制主張。

`differential` 指受控比較能證明主張。它需要測試 Evidence，以及**獨立的對照 Evidence**。
Baseline 顯示正常行為；Negative Control 移除據稱造成結果的條件。目標、相關輸入、時間與
身分脈絡應保持可比較。若無法安全擷取，結果應維持 `inconclusive` 或 `needs_manual_review`。

## 一般驗證器升級為 verified 的條件

以下是未來所有驗證路徑的目標驗收條件。受控的被動自動路徑已執行適用的擷取檢查；
一般人工、Mission 與 Differential 路徑尚未強制執行下列所有條件。
Candidate 應只在適用的檢查全部通過時升級為 `verified`：

1. 主張明確；連結的 Evidence 可讀、完整性有效、屬於同一 Engagement 及預期 Action／目標，
   並在適用的 Scope 與 Approval 政策下擷取。
2. 驗證方法符合主張。差異比較必須有獨立對照；同一筆 Evidence 不能同時作為測試與對照。
3. 關鍵內容本身支持主張，而非只依賴工具結論、規則 Metadata、HTTP 狀態碼或一般錯誤；
   並記錄預期行為及實際偏差。
4. 對依賴時間、身分、狀態或互動的 Finding，應有安全且有界的重測或獨立檢查。
   若無法重現，須記錄原因並交由人工判斷，不能直接宣稱確定。
5. 依主張考慮其他合理解釋，例如公開資料、Cache、Redirect、錯誤頁、使用者可控的反射、
   授權政策、Middleware 效果或目標狀態變更。

一般驗證器應阻止 Evidence 遺失、互相矛盾、跨 Engagement、來自失敗 Action，或完整性檢查
失敗的主張升級。重測失敗或對照結果矛盾時，不得悄悄略過。`rejected` 表示審查後現有證據
反駁或無法支持主張；`needs_manual_review` 表示仍無法下定論。

## 安全驗證路徑

若驗證會送出請求，它就是新的面向目標 Action，必須遵守與 Discovery 相同的 Scope、DNS Pinning、
時間區間、風險分級、Approval、Worker 隔離、請求數與回應大小限制。點選審查不會授權或執行
這類 Action。優先使用唯讀檢查與無害標記。可能修改資料、觸發 Callback、使用另一帳號或影響
可用性的測試，必須先有明確審查過的計畫與相應的政策決定。遇到非預期副作用、Scope 偏移、
身分不一致或 Budget 用盡時應停止。

## 實作順序

1. **Evidence-bound Decision 與受控被動驗證（已實作）：** Evidence 遺失、損毀或跨 Engagement
   時，Repository 寫入已驗證 Finding 與產生報告都會安全拒絕；Review 會留下可稽核決定。
   SARIF 只包含已驗證 Finding。受控的被動自動路徑另會重建 Canonical Capture，驗證成功的
   Action、目標、參數、記錄的 Scope Decision 與適用的 Approval。下一步要將這種綁定擴及
   其他驗證路徑。
2. **一般 Verification Case：** 持久化主張、方法、預期／實際斷言、Evidence 用途、Verifier 版本、
   嘗試紀錄與不可變判定。Observation 應從已儲存的 Capture 建立，而非相信呼叫端填入的回應摘要。
3. **有界重測 Runner：** 依漏洞類別新增經核准且受 Scope 約束的 Recipe；測試、Baseline 與
   Negative Control 各自擷取成 Evidence。Verifier 必須獨立檢查 Discovery 的說法，
   並明確表示不確定結果。
4. **揭露品質：** JSON、Markdown、HTML、SARIF 與 Bundle 應一致呈現判定依據、對照證據、
   重現說明及限制，並在數量與畫面上區分 Candidate 和 Verified Finding。未來的儲存匯出
   應加入有版本的逐 Finding 證明清單；現有 Markdown 匯出沒有穩定 Finding ID，重新驗證
   已驗證主張時只能精確比對表格列。

驗收測試應包含偽造 Observation、Evidence 遺失或變更、跨 Engagement 連結、錯誤 Action／目標、
缺少對照、執行失敗、回應互相矛盾、安全重測成功、逾時／無法定論，以及所有報告格式都保留
一致的判定與證據參照。

# Finding 驗證模型

**繁體中文** | [English](FINDING_VALIDATION.md)

ProofClaw 對每項 Finding 都必須分別回答兩個問題：

1. **Evidence 是否完整且可歸屬於這次 Engagement？** 可檢查儲存的位元組、Canonical Metadata、
   順序與 Hash Chain 是否遭更動；Evidence 也必須來自同一 Engagement 的 Action。
2. **Evidence 是否足以證明這項具體安全主張？** Hash 正確不代表已確認目標的預期權限政策，
   也不代表漏洞可被利用。主張需要明確的驗證方法、預期結果、實際結果，以及排除其他合理原因的脈絡。

離線 Disclosure Bundle 驗證器檢查封裝及 Evidence Chain 的完整性；它**不會**重送請求、
確認授權假設、證明漏洞成立，或辨識 Bundle 作者的身分。

## 目前邊界

- 決定性的被動 HTTP 檢查可以將單次回應中直接觀察到的 Header 或傳輸性質標為
  `verified`。這只證明所觀察的性質，不代表已成功利用漏洞。
- OpenAPI 宣告與未登入的成功回應會產生 `candidate`：僅靠 API 規格，無法確認回傳內容
  原本應該保密。
- `nuclei` 與 `httpx` Parser 只把有目標來源資料支持的特定觀察列為
  `pending_verification`；其他 Scanner 紀錄會被排除。其輸出仍需獨立審查，才能成為
  verified 主張。Template Severity、CVE 標籤或 LLM 斷言都不是影響的證據。
- `POST /api/v1/automation/verify` 根據呼叫端提供的 Observation 計算 `pass`、
  `candidate` 或 `inconclusive`。其結果不是持久化的 Finding 決定，也不能取代以 Evidence
  為基礎的審查。Planner／Operator／Verifier 的 Next-step Endpoint 只選擇下一個角色，
  不會重新測試目標。
- Finding Review API 使用樂觀版本檢查與 Audit Event 處理人工決定。
  升級為 `verified` 前，會檢查整條 Engagement Evidence Chain、連結 Evidence 的存在與歸屬，
  明確的驗證方法，以及審查理由。目前尚未檢查 Action 是否成功、目標語意是否一致，
  或回應能否證明主張。差異比較的審查會拒絕位元組完全相同的測試與對照擷取，
  但目前不會判斷變化是否足以支持主張。
  詳見 [Finding 審查](FINDING_REVIEW.zh-TW.md)。

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

## 升級為 verified 的條件

Candidate 只有在適用的檢查全部通過時，才能升級為 `verified`：

1. 主張明確；連結的 Evidence 可讀、完整性有效、屬於同一 Engagement 及預期 Action／目標，
   並在適用的 Scope 與 Approval 政策下擷取。
2. 驗證方法符合主張。差異比較必須有獨立對照；同一筆 Evidence 不能同時作為測試與對照。
3. 關鍵內容本身支持主張，而非只依賴工具結論、規則 Metadata、HTTP 狀態碼或一般錯誤；
   並記錄預期行為及實際偏差。
4. 對依賴時間、身分、狀態或互動的 Finding，應有安全且有界的重測或獨立檢查。
   若無法重現，須記錄原因並交由人工判斷，不能直接宣稱確定。
5. 依主張考慮其他合理解釋，例如公開資料、Cache、Redirect、錯誤頁、使用者可控的反射、
   授權政策、Middleware 效果或目標狀態變更。

Evidence 遺失、互相矛盾、跨 Engagement、來自失敗 Action，或完整性檢查失敗時，必須阻止
升級。重測失敗或對照結果矛盾時，不得悄悄略過。`rejected` 表示審查後現有證據反駁或無法
支持主張；`needs_manual_review` 表示仍無法下定論。

## 安全驗證路徑

若驗證會送出請求，它就是新的面向目標 Action，必須遵守與 Discovery 相同的 Scope、DNS Pinning、
時間區間、風險分級、Approval、Worker 隔離、請求數與回應大小限制。點選審查不會授權或執行
這類 Action。優先使用唯讀檢查與無害標記。可能修改資料、觸發 Callback、使用另一帳號或影響
可用性的測試，必須先有明確審查過的計畫與相應的政策決定。遇到非預期副作用、Scope 偏移、
身分不一致或 Budget 用盡時應停止。

## 實作順序

1. **Evidence-bound Decision（首道關卡已實作）：** Evidence 遺失、損毀或跨 Engagement 時，
   Review 會安全拒絕並留下可稽核紀錄。下一步須將每筆 Evidence 綁定到成功執行的 Action
   與精確目標。
2. **Verification Case：** 持久化主張、方法、預期／實際斷言、Evidence 用途、Verifier 版本、
   嘗試紀錄與不可變判定。Observation 應從已儲存的 Capture 建立，而非相信呼叫端填入的回應摘要。
3. **有界重測 Runner：** 依漏洞類別新增經核准且受 Scope 約束的 Recipe；測試、Baseline 與
   Negative Control 各自擷取成 Evidence。Verifier 必須獨立檢查 Discovery 的說法，
   並明確表示不確定結果。
4. **揭露品質：** JSON、Markdown、HTML、SARIF 與 Bundle 應一致呈現判定依據、對照證據、
   重現說明及限制，並在數量與畫面上區分 Candidate 和 Verified Finding。

驗收測試應包含偽造 Observation、Evidence 遺失或變更、跨 Engagement 連結、錯誤 Action／目標、
缺少對照、執行失敗、回應互相矛盾、安全重測成功、逾時／無法定論，以及所有報告格式都保留
一致的判定與證據參照。

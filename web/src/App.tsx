import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

import { ApiError, apiRequest, downloadApiFile } from "./api";
import {
  assessmentHistoryPath,
  assessmentIdempotencyKey,
  prepareAssessment,
} from "./assessment";
import { AssessmentWorkspace } from "./AssessmentWorkspace";
import {
  AssessmentHistoryItem,
  AssessmentList,
  AssessmentSummary,
  DashboardSummary,
  Engagement,
  HealthStatus,
  Project,
  ProjectList,
} from "./contracts";
import { View, viewFromHash, views } from "./navigation";

type Language = "en" | "zh-TW";

const copy = {
  en: {
    product: "ProofClaw",
    skipContent: "Skip to content",
    edition: "CONTROL PLANE",
    nav: {
      overview: "Overview",
      projects: "Projects",
      assessments: "Assess URL",
      approvals: "Approval inbox",
      evidence: "Evidence",
      findings: "Findings",
      policy: "Safety policy",
    },
    webFoundation: "EVIDENCE CORE PREVIEW",
    phaseText: "Scoped engagements online",
    apiReady: "API ready",
    apiUnavailable: "API unavailable",
    commandCenter: "Security operations console",
    headline: "Evidence first. Every action accountable.",
    subhead:
      "Create authorized assessment boundaries and monitor evidence-backed results. Passive URL capture is available only when explicitly enabled.",
    newProject: "New project",
    refresh: "Refresh",
    metrics: {
      projects: "Projects",
      engagements: "Engagements",
      active_actions: "Active actions",
      pending_approvals: "Awaiting approval",
      evidence: "Evidence records",
      findings: "Findings",
    },
    projectPortfolio: "Project portfolio",
    projectPortfolioHint: "Top-level boundaries for products, customers, and research.",
    noProjects: "No projects yet",
    noProjectsHint: "Create the first project to establish an assessment boundary.",
    created: "Created",
    status: "Status",
    draft: "Project boundary",
    guardrails: "Execution guardrails",
    guardrailsHint: "Default policy applied at the control-plane boundary.",
    risk: [
      ["L0", "Passive reconnaissance", "Automatic"],
      ["L1", "Active scanning", "Project policy"],
      ["L2", "Exploit and credential tests", "Approval required"],
      ["L3", "Post-exploitation", "Approval required"],
      ["L4", "Destructive operations", "Disabled"],
    ],
    capability: "Capability status",
    operational: "Operational",
    foundation: "Foundation ready",
    evidenceCore: "Scoped evidence API",
    evidenceCoreText: "Engagement scope evaluation and JSON/Markdown reports are online.",
    passiveReady: "Passive assessment ready",
    passiveReadyText: "Scoped, DNS-pinned GET capture is enabled; active probes remain locked.",
    passiveLocked: "Passive assessment disabled",
    passiveLockedText: "Target traffic is off until an operator explicitly enables it.",
    chain: "Evidence chain",
    chainText: "SHA-256 chaining and persistence primitives are ready.",
    createTitle: "Create a project",
    createHint: "A project is the top-level boundary for an authorized assessment.",
    projectName: "Project name",
    projectPlaceholder: "e.g. Acme Customer Portal",
    cancel: "Cancel",
    create: "Create project",
    creating: "Creating…",
    auth: "Operator access",
    authTitle: "Operator token",
    authHint: "Kept only in this browser tab and sent as a Bearer token to this API.",
    authPlaceholder: "Paste operator token",
    saveToken: "Use token",
    clearToken: "Clear token",
    tokenActive: "Token configured",
    assessmentTitle: "Authorized passive URL assessment",
    assessmentHint: "Creates a 24-hour L0 engagement, sends one bounded GET, stores evidence, and produces report data.",
    chooseProject: "Project",
    chooseProjectPlaceholder: "Select a project",
    targetUrl: "Target URL",
    targetPlaceholder: "https://app.example.com/",
    authorizationConfirm: "I confirm that I am authorized to assess this exact target.",
    runAssessment: "Run passive assessment",
    assessing: "Assessing…",
    assessmentDisabled: "Passive target traffic is disabled in server settings.",
    assessmentResult: "Latest assessment result",
    actionState: "Action state",
    findingCount: "Findings",
    evidenceCount: "Evidence records",
    downloadJson: "Download JSON report",
    downloadMarkdown: "Download Markdown report",
    assessmentSuccess: "Assessment completed and persisted.",
    assessmentError: "Assessment could not be completed.",
    invalidTarget: "Enter a complete HTTP or HTTPS URL.",
    unsupportedTarget: "Only HTTP and HTTPS targets are supported.",
    credentialTarget: "Remove the username and password from the target URL.",
    ipTarget: "IP-literal targets require a manually reviewed API scope.",
    authorizationRequired: "Enter a valid operator token to use protected features.",
    assessmentHistory: "Assessment history",
    assessmentHistoryHint: "Persisted runs remain available after refresh and can be filtered by project.",
    assessmentHistoryFilter: "History project",
    allProjects: "All projects",
    historyCount: "Persisted runs",
    noAssessmentHistory: "No passive assessments match this project yet.",
    loadingHistory: "Loading assessment history...",
    completedAt: "Completed",
    pageHints: {
      projects: "Manage authorized assessment boundaries.",
      assessments: "Run one bounded passive check against a target you are authorized to test.",
      approvals: "Review protected actions before execution.",
      evidence: "Inspect immutable tool output and integrity chains.",
      findings: "Review evidence-backed vulnerability claims.",
      policy: "Understand the enforced L0–L4 action model.",
    },
    emptyPending: "Nothing is waiting here",
    emptyPendingHint: "This area will populate when execution workflows create records.",
    unavailableAction: "Active probes, exploit payloads, and arbitrary tools remain disabled.",
    error: "The console could not reach the control-plane API.",
  },
  "zh-TW": {
    product: "ProofClaw",
    assessmentHistory: "評估歷史",
    assessmentHistoryHint: "已保存的執行紀錄會在重新整理後保留，並可依專案篩選。",
    assessmentHistoryFilter: "歷史專案",
    allProjects: "所有專案",
    historyCount: "保存紀錄",
    noAssessmentHistory: "這個專案目前沒有符合的被動評估紀錄。",
    loadingHistory: "\u6b63\u5728\u8f09\u5165\u8a55\u4f30\u6b77\u53f2...",
    completedAt: "完成時間",
    skipContent: "跳至主要內容",
    edition: "控制平面",
    nav: {
      overview: "總覽",
      projects: "專案",
      assessments: "網址評估",
      approvals: "批准佇列",
      evidence: "證據",
      findings: "漏洞發現",
      policy: "安全政策",
    },
    webFoundation: "證據核心預覽版",
    phaseText: "授權範圍評估已上線",
    apiReady: "API 正常",
    apiUnavailable: "API 無法連線",
    commandCenter: "資安作業控制台",
    headline: "證據優先，每個動作都可追溯。",
    subhead:
      "建立明確授權的評估邊界並監控證據結果。被動 URL 擷取只有在明確啟用後才會執行。",
    newProject: "新增專案",
    refresh: "重新整理",
    metrics: {
      projects: "專案",
      engagements: "評估任務",
      active_actions: "執行中動作",
      pending_approvals: "等待批准",
      evidence: "證據紀錄",
      findings: "漏洞發現",
    },
    projectPortfolio: "專案組合",
    projectPortfolioHint: "產品、客戶與研究工作的最上層安全邊界。",
    noProjects: "目前沒有專案",
    noProjectsHint: "建立第一個專案，開始定義授權評估邊界。",
    created: "建立時間",
    status: "狀態",
    draft: "專案邊界",
    guardrails: "執行安全邊界",
    guardrailsHint: "控制平面強制套用的預設政策。",
    risk: [
      ["L0", "被動偵察", "自動執行"],
      ["L1", "主動掃描", "依專案政策"],
      ["L2", "漏洞利用與密碼測試", "需要批准"],
      ["L3", "後滲透操作", "需要批准"],
      ["L4", "破壞性操作", "預設禁止"],
    ],
    capability: "能力狀態",
    operational: "運作正常",
    foundation: "基礎功能就緒",
    evidenceCore: "範圍與證據 API",
    evidenceCoreText: "評估任務範圍判斷與 JSON／Markdown 報告已可使用。",
    passiveReady: "被動評估已就緒",
    passiveReadyText: "已啟用 Scope 與 DNS pinning 保護的 GET 擷取；主動探測仍維持鎖定。",
    passiveLocked: "被動評估未啟用",
    passiveLockedText: "操作人員明確啟用前，系統不會對目標送出流量。",
    chain: "證據鏈",
    chainText: "SHA-256 鏈結與持久化基礎已完成。",
    createTitle: "建立專案",
    createHint: "專案是一次授權資安評估的最上層邊界。",
    projectName: "專案名稱",
    projectPlaceholder: "例如：Acme 客戶入口網站",
    cancel: "取消",
    create: "建立專案",
    creating: "建立中…",
    auth: "操作員權限",
    authTitle: "Operator Token",
    authHint: "Token 只保存在目前瀏覽器分頁，並以 Bearer Token 傳送到這個 API。",
    authPlaceholder: "貼上 Operator Token",
    saveToken: "使用 Token",
    clearToken: "清除 Token",
    tokenActive: "Token 已設定",
    assessmentTitle: "已授權的被動網址評估",
    assessmentHint: "建立 24 小時 L0 Engagement、送出一次有界 GET、保存 Evidence 並產生報告資料。",
    chooseProject: "所屬專案",
    chooseProjectPlaceholder: "選擇專案",
    targetUrl: "目標網址",
    targetPlaceholder: "https://app.example.com/",
    authorizationConfirm: "我確認自己已獲授權，可以評估這個確切目標。",
    runAssessment: "執行被動評估",
    assessing: "評估中…",
    assessmentDisabled: "伺服器設定目前未啟用被動目標流量。",
    assessmentResult: "最近一次評估結果",
    actionState: "動作狀態",
    findingCount: "Finding 數量",
    evidenceCount: "Evidence 數量",
    downloadJson: "下載 JSON 報告",
    downloadMarkdown: "下載 Markdown 報告",
    assessmentSuccess: "評估已完成並保存。",
    assessmentError: "無法完成評估。",
    invalidTarget: "請輸入完整的 HTTP 或 HTTPS 網址。",
    unsupportedTarget: "目前只支援 HTTP 與 HTTPS 目標。",
    credentialTarget: "請移除目標網址內的使用者名稱與密碼。",
    ipTarget: "IP literal 目標必須使用經人工審查的 API Scope。",
    authorizationRequired: "請輸入有效的 Operator Token 以使用受保護功能。",
    pageHints: {
      projects: "管理經授權的評估邊界。",
      assessments: "針對你確實獲得授權的目標，執行一次有界的被動檢查。",
      approvals: "執行前審核受保護的動作。",
      evidence: "檢視不可變工具輸出與完整性鏈。",
      findings: "審核由證據支持的漏洞主張。",
      policy: "了解系統強制執行的 L0–L4 動作模型。",
    },
    emptyPending: "目前沒有資料",
    emptyPendingHint: "執行工作流程產生紀錄後，內容會顯示在這裡。",
    unavailableAction: "主動探測、Exploit Payload 與任意工具執行仍維持停用。",
    error: "控制台無法連線至控制平面 API。",
  },
} as const;

function formatDate(value: string, language: Language): string {
  return new Intl.DateTimeFormat(language, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

async function readJson<T>(response: Response): Promise<T> {
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return (await response.json()) as T;
}

function App() {
  const [language, setLanguage] = useState<Language>("zh-TW");
  const [view, setView] = useState<View>(() => viewFromHash(window.location.hash));
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [apiReady, setApiReady] = useState(false);
  const [appVersion, setAppVersion] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [projectName, setProjectName] = useState("");
  const [creating, setCreating] = useState(false);
  const [operatorToken, setOperatorToken] = useState(
    () => sessionStorage.getItem("proofclaw.operatorToken") ?? "",
  );
  const [tokenDraft, setTokenDraft] = useState(operatorToken);
  const [showAuthentication, setShowAuthentication] = useState(false);
  const [authenticationRequired, setAuthenticationRequired] = useState(false);
  const [assessmentProjectId, setAssessmentProjectId] = useState("");
  const [assessmentTarget, setAssessmentTarget] = useState("");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [assessing, setAssessing] = useState(false);
  const [assessmentMessage, setAssessmentMessage] = useState("");
  const [latestAssessment, setLatestAssessment] = useState<AssessmentSummary | null>(null);
  const [assessmentHistory, setAssessmentHistory] = useState<AssessmentHistoryItem[]>([]);
  const [assessmentHistoryTotal, setAssessmentHistoryTotal] = useState(0);
  const [historyProjectId, setHistoryProjectId] = useState("");
  const t = copy[language];

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const health = await fetch("/api/v1/health/ready");
      setApiReady(health.ok);
      if (health.ok) {
        const healthStatus = await readJson<HealthStatus>(health);
        setAppVersion(healthStatus.version);
      }
      const [dashboard, projectList, assessmentList] = await Promise.all([
        apiRequest<DashboardSummary>("/api/v1/dashboard/summary", operatorToken),
        apiRequest<ProjectList>("/api/v1/projects?limit=100", operatorToken),
        apiRequest<AssessmentList>(assessmentHistoryPath(historyProjectId), operatorToken),
      ]);
      setSummary(dashboard);
      setProjects(projectList.items);
      setAssessmentHistory(assessmentList.items);
      setAssessmentHistoryTotal(assessmentList.total);
      setAuthenticationRequired(false);
    } catch (loadError) {
      setError(true);
      if (loadError instanceof ApiError && loadError.status === 401) {
        setAuthenticationRequired(true);
      } else {
        setApiReady(false);
      }
    } finally {
      setLoading(false);
    }
  }, [historyProjectId, operatorToken]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  useEffect(() => {
    const restoreView = () => setView(viewFromHash(window.location.hash));
    window.addEventListener("hashchange", restoreView);
    return () => window.removeEventListener("hashchange", restoreView);
  }, []);

  const navigate = (nextView: View) => {
    setView(nextView);
    window.location.hash = nextView === "overview" ? "" : nextView;
  };

  const createProject = async (event: FormEvent) => {
    event.preventDefault();
    const normalized = projectName.trim();
    if (!normalized) return;
    setCreating(true);
    try {
      await apiRequest<Project>("/api/v1/projects", operatorToken, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: normalized }),
      });
      setProjectName("");
      setShowCreate(false);
      await loadData();
      navigate("projects");
    } catch {
      setError(true);
    } finally {
      setCreating(false);
    }
  };

  const saveOperatorToken = (event: FormEvent) => {
    event.preventDefault();
    const normalized = tokenDraft.trim();
    if (normalized) sessionStorage.setItem("proofclaw.operatorToken", normalized);
    else sessionStorage.removeItem("proofclaw.operatorToken");
    setOperatorToken(normalized);
    setShowAuthentication(false);
  };

  const clearOperatorToken = () => {
    sessionStorage.removeItem("proofclaw.operatorToken");
    setTokenDraft("");
    setOperatorToken("");
    setShowAuthentication(false);
  };

  const runAssessment = async (event: FormEvent) => {
    event.preventDefault();
    if (!assessmentProjectId || !authorizationConfirmed || assessing) return;
    setAssessing(true);
    setAssessmentMessage("");
    try {
      const prepared = prepareAssessment(assessmentTarget);
      const engagement = await apiRequest<Engagement>(
        `/api/v1/projects/${assessmentProjectId}/engagements`,
        operatorToken,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(prepared.engagementPayload),
        },
      );
      const result = await apiRequest<AssessmentSummary>(
        `/api/v1/engagements/${engagement.id}/assessments`,
        operatorToken,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": assessmentIdempotencyKey(),
          },
          body: JSON.stringify({ target: prepared.displayTarget }),
        },
      );
      setLatestAssessment(result);
      setAssessmentMessage(result.error_code ?? t.assessmentSuccess);
      await loadData();
    } catch (assessmentError) {
      const detail = assessmentError instanceof Error ? assessmentError.message : t.assessmentError;
      const localizedErrors: Record<string, string> = {
        embedded_credentials: t.credentialTarget,
        invalid_url: t.invalidTarget,
        ip_literal_requires_manual_scope: t.ipTarget,
        unsupported_scheme: t.unsupportedTarget,
      };
      setAssessmentMessage(localizedErrors[detail] ?? detail);
      if (assessmentError instanceof ApiError && assessmentError.status === 401) {
        setAuthenticationRequired(true);
        setShowAuthentication(true);
      }
    } finally {
      setAssessing(false);
    }
  };

  const downloadReport = async (
    format: "json" | "markdown",
    assessment: AssessmentSummary | AssessmentHistoryItem | null = latestAssessment,
  ) => {
    if (!assessment) return;
    const path = format === "json"
      ? assessment.report_url
      : assessment.markdown_report_url;
    const extension = format === "json" ? "json" : "md";
    try {
      await downloadApiFile(path, operatorToken, `proofclaw-${assessment.action_id}.${extension}`);
    } catch (downloadError) {
      setAssessmentMessage(
        downloadError instanceof Error ? downloadError.message : t.assessmentError,
      );
    }
  };

  const metrics = useMemo(() => {
    const counts = summary?.counts;
    return [
      ["projects", counts?.projects ?? 0],
      ["engagements", counts?.engagements ?? 0],
      ["active_actions", counts?.active_actions ?? 0],
      ["pending_approvals", counts?.pending_approvals ?? 0],
      ["evidence", counts?.evidence ?? 0],
      ["findings", counts?.findings ?? 0],
    ] as const;
  }, [summary]);

  const currentTitle = view === "overview" ? t.commandCenter : t.nav[view];

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">{t.skipContent}</a>
      <aside className="sidebar">
        <div className="brand">
          <div className="claw-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </div>
          <div>
            <strong>{t.product}</strong>
            <small>{t.edition}</small>
          </div>
        </div>

        <nav aria-label="Primary">
          {views.map((item) => (
            <button
              className={view === item ? "nav-item active" : "nav-item"}
              key={item}
              onClick={() => navigate(item)}
              type="button"
            >
              <span className={`nav-glyph glyph-${item}`} aria-hidden="true" />
              {t.nav[item]}
              {item === "approvals" && (summary?.counts.pending_approvals ?? 0) > 0 && (
                <em>{summary?.counts.pending_approvals}</em>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="phase-card">
            <span className="phase-kicker">{t.webFoundation}</span>
            <strong>{t.phaseText}</strong>
            <div className="phase-progress"><span /></div>
            <small>{appVersion ? `v${appVersion}` : "v—"} · v0.1 preview</small>
          </div>
        </div>
      </aside>

      <main id="main-content">
        <header className="topbar">
          <div>
            <span className="eyebrow">{t.webFoundation}</span>
            <h1>{currentTitle}</h1>
          </div>
          <div className="topbar-actions">
            <button
              className={operatorToken ? "quiet-button token-ready" : "quiet-button"}
              onClick={() => setShowAuthentication(true)}
              type="button"
            >
              {operatorToken ? t.tokenActive : t.auth}
            </button>
            <button
              className="language-switch"
              onClick={() => setLanguage(language === "en" ? "zh-TW" : "en")}
              type="button"
            >
              {language === "en" ? "中文" : "EN"}
            </button>
            <button className="quiet-button" onClick={() => void loadData()} type="button">
              <span className={loading ? "refresh-icon spinning" : "refresh-icon"}>↻</span>
              {t.refresh}
            </button>
            <div className={apiReady ? "status-pill ready" : "status-pill"}>
              <span />
              {apiReady ? t.apiReady : t.apiUnavailable}
            </div>
          </div>
        </header>

        <div className="workspace">
          {authenticationRequired && (
            <button
              className="error-banner auth-banner"
              onClick={() => setShowAuthentication(true)}
              type="button"
            >
              {t.authorizationRequired}
            </button>
          )}
          {error && !authenticationRequired && <div className="error-banner">{t.error}</div>}
          {view === "overview" && (
            <Overview
              executionAvailable={summary?.execution_available ?? false}
              language={language}
              metrics={metrics}
              projects={projects.slice(0, 5)}
              t={t}
              onCreate={() => setShowCreate(true)}
              onProjects={() => navigate("projects")}
            />
          )}
          {view === "projects" && (
            <Projects
              language={language}
              projects={projects}
              t={t}
              onCreate={() => setShowCreate(true)}
            />
          )}
          {view === "assessments" && (
            <AssessmentWorkspace
              authorizationConfirmed={authorizationConfirmed}
              assessing={assessing}
              formatTimestamp={(value) => formatDate(value, language)}
              history={assessmentHistory}
              historyLoading={loading}
              historyProjectId={historyProjectId}
              historyTotal={assessmentHistoryTotal}
              executionAvailable={summary?.execution_available ?? false}
              latestAssessment={latestAssessment}
              message={assessmentMessage}
              projectId={assessmentProjectId}
              projects={projects}
              target={assessmentTarget}
              t={t}
              onAuthorizationChange={setAuthorizationConfirmed}
              onDownload={(format) => void downloadReport(format)}
              onHistoryDownload={(assessment, format) => void downloadReport(format, assessment)}
              onHistoryProjectChange={setHistoryProjectId}
              onProjectChange={setAssessmentProjectId}
              onSubmit={(event) => void runAssessment(event)}
              onTargetChange={setAssessmentTarget}
            />
          )}
          {view === "policy" && <Policy t={t} />}
          {(["approvals", "evidence", "findings"] as View[]).includes(view) && (
            <EmptyCapability view={view} t={t} />
          )}
        </div>
      </main>

      {showCreate && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setShowCreate(false)}>
          <section
            aria-labelledby="create-title"
            aria-modal="true"
            className="modal"
            onMouseDown={(event) => event.stopPropagation()}
            role="dialog"
          >
            <button
              aria-label="Close"
              className="modal-close"
              onClick={() => setShowCreate(false)}
              type="button"
            >
              ×
            </button>
            <span className="eyebrow">{t.webFoundation}</span>
            <h2 id="create-title">{t.createTitle}</h2>
            <p>{t.createHint}</p>
            <form onSubmit={(event) => void createProject(event)}>
              <label htmlFor="project-name">{t.projectName}</label>
              <input
                autoFocus
                id="project-name"
                maxLength={255}
                onChange={(event) => setProjectName(event.target.value)}
                placeholder={t.projectPlaceholder}
                value={projectName}
              />
              <div className="modal-actions">
                <button className="quiet-button" onClick={() => setShowCreate(false)} type="button">
                  {t.cancel}
                </button>
                <button className="primary-button" disabled={!projectName.trim() || creating}>
                  {creating ? t.creating : t.create}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
      {showAuthentication && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={() => setShowAuthentication(false)}
        >
          <section
            aria-labelledby="auth-title"
            aria-modal="true"
            className="modal"
            onMouseDown={(event) => event.stopPropagation()}
            role="dialog"
          >
            <button
              aria-label="Close"
              className="modal-close"
              onClick={() => setShowAuthentication(false)}
              type="button"
            >
              ×
            </button>
            <span className="eyebrow">{t.auth}</span>
            <h2 id="auth-title">{t.authTitle}</h2>
            <p>{t.authHint}</p>
            <form onSubmit={saveOperatorToken}>
              <label htmlFor="operator-token">{t.authTitle}</label>
              <input
                autoComplete="off"
                autoFocus
                id="operator-token"
                onChange={(event) => setTokenDraft(event.target.value)}
                placeholder={t.authPlaceholder}
                type="password"
                value={tokenDraft}
              />
              <div className="modal-actions">
                <button className="quiet-button" onClick={clearOperatorToken} type="button">
                  {t.clearToken}
                </button>
                <button className="primary-button">{t.saveToken}</button>
              </div>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}

type Translation = (typeof copy)[Language];

function Overview({
  executionAvailable,
  language,
  metrics,
  projects,
  t,
  onCreate,
  onProjects,
}: {
  executionAvailable: boolean;
  language: Language;
  metrics: ReadonlyArray<readonly [keyof Translation["metrics"], number]>;
  projects: Project[];
  t: Translation;
  onCreate: () => void;
  onProjects: () => void;
}) {
  return (
    <>
      <section className="hero-panel">
        <div>
          <span className="eyebrow">{t.operational}</span>
          <h2>{t.headline}</h2>
          <p>{t.subhead}</p>
        </div>
        <button className="primary-button" onClick={onCreate} type="button">
          <span>＋</span>{t.newProject}
        </button>
        <div className="hero-grid" aria-hidden="true" />
      </section>

      <section className="metric-grid">
        {metrics.map(([key, value], index) => (
          <article className="metric-card" key={key}>
            <span className={`metric-symbol symbol-${index}`} />
            <div>
              <strong>{value.toLocaleString(language)}</strong>
              <span>{t.metrics[key]}</span>
            </div>
          </article>
        ))}
      </section>

      <div className="content-grid">
        <ProjectPanel
          language={language}
          projects={projects}
          t={t}
          onCreate={onCreate}
          onProjects={onProjects}
        />
        <aside className="right-stack">
          <section className="panel capability-panel">
            <div className="panel-heading">
              <div>
                <span className="eyebrow">{t.operational}</span>
                <h3>{t.capability}</h3>
              </div>
            </div>
            <div className="capability-row">
              <span className="cap-icon ready">✓</span>
              <div><strong>{t.foundation}</strong><p>API · PostgreSQL · Policy · Evidence</p></div>
            </div>
            <div className="capability-row">
              <span className="cap-icon chain">#</span>
              <div><strong>{t.evidenceCore}</strong><p>{t.evidenceCoreText}</p></div>
            </div>
            <div className="capability-row">
              <span className={`cap-icon ${executionAvailable ? "ready" : "locked"}`}>
                {executionAvailable ? "✓" : "⌁"}
              </span>
              <div>
                <strong>{executionAvailable ? t.passiveReady : t.passiveLocked}</strong>
                <p>{executionAvailable ? t.passiveReadyText : t.passiveLockedText}</p>
              </div>
            </div>
            <div className="capability-row">
              <span className="cap-icon chain">#</span>
              <div><strong>{t.chain}</strong><p>{t.chainText}</p></div>
            </div>
          </section>
          <RiskPanel t={t} compact />
        </aside>
      </div>
    </>
  );
}

function ProjectPanel({
  language,
  projects,
  t,
  onCreate,
  onProjects,
}: {
  language: Language;
  projects: Project[];
  t: Translation;
  onCreate: () => void;
  onProjects: () => void;
}) {
  return (
    <section className="panel project-panel">
      <div className="panel-heading">
        <div>
          <h3>{t.projectPortfolio}</h3>
          <p>{t.projectPortfolioHint}</p>
        </div>
        <button className="text-button" onClick={onProjects} type="button">→</button>
      </div>
      {projects.length === 0 ? (
        <div className="empty-state">
          <div className="empty-mark"><span /><span /><span /></div>
          <h4>{t.noProjects}</h4>
          <p>{t.noProjectsHint}</p>
          <button className="primary-button" onClick={onCreate} type="button">{t.newProject}</button>
        </div>
      ) : (
        <div className="project-list">
          {projects.map((project) => (
            <article className="project-row" key={project.id}>
              <span className="project-avatar">{project.name.slice(0, 2).toUpperCase()}</span>
              <div className="project-main">
                <strong>{project.name}</strong>
                <code>{project.id.slice(0, 13)}</code>
              </div>
              <div className="project-date">
                <small>{t.created}</small>
                <span>{formatDate(project.created_at, language)}</span>
              </div>
              <span className="setup-badge">{t.draft}</span>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function Projects({
  language,
  projects,
  t,
  onCreate,
}: {
  language: Language;
  projects: Project[];
  t: Translation;
  onCreate: () => void;
}) {
  return (
    <>
      <div className="page-intro">
        <p>{t.pageHints.projects}</p>
        <button className="primary-button" onClick={onCreate} type="button">＋ {t.newProject}</button>
      </div>
      <ProjectPanel
        language={language}
        projects={projects}
        t={t}
        onCreate={onCreate}
        onProjects={() => undefined}
      />
    </>
  );
}

function RiskPanel({ t, compact = false }: { t: Translation; compact?: boolean }) {
  return (
    <section className={compact ? "panel risk-panel compact" : "panel risk-panel"}>
      <div className="panel-heading">
        <div><h3>{t.guardrails}</h3><p>{t.guardrailsHint}</p></div>
      </div>
      <div className="risk-list">
        {t.risk.map(([level, label, behavior], index) => (
          <div className="risk-row" key={level}>
            <span className={`risk-level risk-${index}`}>{level}</span>
            <div><strong>{label}</strong><small>{behavior}</small></div>
          </div>
        ))}
      </div>
    </section>
  );
}

function Policy({ t }: { t: Translation }) {
  return (
    <>
      <div className="page-intro"><p>{t.pageHints.policy}</p></div>
      <RiskPanel t={t} />
      <div className="policy-note">
        <span>!</span>
        <p>{t.unavailableAction}</p>
      </div>
    </>
  );
}

function EmptyCapability({ view, t }: { view: View; t: Translation }) {
  const hint = view === "overview" || view === "projects" || view === "policy"
    ? ""
    : t.pageHints[view];
  return (
    <>
      <div className="page-intro"><p>{hint}</p></div>
      <section className="panel empty-capability">
        <div className="empty-mark"><span /><span /><span /></div>
        <h3>{t.emptyPending}</h3>
        <p>{t.emptyPendingHint}</p>
        <div className="locked-notice">⌁ {t.unavailableAction}</div>
      </section>
    </>
  );
}

export default App;

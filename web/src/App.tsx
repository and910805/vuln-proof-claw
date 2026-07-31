import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Language = "en" | "zh-TW";
type View = "overview" | "projects" | "approvals" | "evidence" | "findings" | "policy";

type Project = {
  id: string;
  name: string;
  created_at: string;
};

type DashboardSummary = {
  schema_version: "v1";
  phase: "web-foundation";
  execution_available: boolean;
  counts: {
    projects: number;
    engagements: number;
    active_actions: number;
    pending_approvals: number;
    evidence: number;
    findings: number;
  };
  recent_projects: Project[];
};

type ProjectList = {
  schema_version: "v1";
  items: Project[];
  total: number;
};

const copy = {
  en: {
    product: "ProofClaw",
    edition: "CONTROL PLANE",
    nav: {
      overview: "Overview",
      projects: "Projects",
      approvals: "Approval inbox",
      evidence: "Evidence",
      findings: "Findings",
      policy: "Safety policy",
    },
    webFoundation: "WEB FOUNDATION",
    phaseText: "Control surface online",
    apiReady: "API ready",
    apiUnavailable: "API unavailable",
    commandCenter: "Security operations console",
    headline: "Evidence first. Every action accountable.",
    subhead:
      "Create assessment projects and monitor the control plane. Target execution remains locked until scoped workers are implemented.",
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
    draft: "Setup required",
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
    locked: "Execution locked",
    lockedText: "Worker isolation and scoped HTTP execution are the next implementation gate.",
    chain: "Evidence chain",
    chainText: "SHA-256 chaining and persistence primitives are ready.",
    createTitle: "Create a project",
    createHint: "A project is the top-level boundary for an authorized assessment.",
    projectName: "Project name",
    projectPlaceholder: "e.g. Acme Customer Portal",
    cancel: "Cancel",
    create: "Create project",
    creating: "Creating…",
    pageHints: {
      projects: "Manage authorized assessment boundaries.",
      approvals: "Review protected actions before execution.",
      evidence: "Inspect immutable tool output and integrity chains.",
      findings: "Review evidence-backed vulnerability claims.",
      policy: "Understand the enforced L0–L4 action model.",
    },
    emptyPending: "Nothing is waiting here",
    emptyPendingHint: "This area will populate when execution workflows create records.",
    unavailableAction: "Execution features are not enabled in this foundation release.",
    error: "The console could not reach the control-plane API.",
  },
  "zh-TW": {
    product: "ProofClaw",
    edition: "控制平面",
    nav: {
      overview: "總覽",
      projects: "專案",
      approvals: "批准佇列",
      evidence: "證據",
      findings: "漏洞發現",
      policy: "安全政策",
    },
    webFoundation: "WEB 基礎階段",
    phaseText: "控制介面已上線",
    apiReady: "API 正常",
    apiUnavailable: "API 無法連線",
    commandCenter: "資安作業控制台",
    headline: "證據優先，每個動作都可追溯。",
    subhead:
      "建立評估專案並監控控制平面。具備範圍限制的隔離 Worker 完成前，目標執行功能維持鎖定。",
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
    draft: "需要設定",
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
    locked: "執行功能鎖定",
    lockedText: "下一個實作關卡是 Worker 隔離與具備範圍限制的 HTTP 執行。",
    chain: "證據鏈",
    chainText: "SHA-256 鏈結與持久化基礎已完成。",
    createTitle: "建立專案",
    createHint: "專案是一次授權資安評估的最上層邊界。",
    projectName: "專案名稱",
    projectPlaceholder: "例如：Acme 客戶入口網站",
    cancel: "取消",
    create: "建立專案",
    creating: "建立中…",
    pageHints: {
      projects: "管理經授權的評估邊界。",
      approvals: "執行前審核受保護的動作。",
      evidence: "檢視不可變工具輸出與完整性鏈。",
      findings: "審核由證據支持的漏洞主張。",
      policy: "了解系統強制執行的 L0–L4 動作模型。",
    },
    emptyPending: "目前沒有資料",
    emptyPendingHint: "執行工作流程產生紀錄後，內容會顯示在這裡。",
    unavailableAction: "此基礎版本尚未啟用執行功能。",
    error: "控制台無法連線至控制平面 API。",
  },
} as const;

const navViews: View[] = [
  "overview",
  "projects",
  "approvals",
  "evidence",
  "findings",
  "policy",
];

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
  const [view, setView] = useState<View>("overview");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [apiReady, setApiReady] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [projectName, setProjectName] = useState("");
  const [creating, setCreating] = useState(false);
  const t = copy[language];

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(false);
    try {
      const [health, dashboard, projectList] = await Promise.all([
        fetch("/api/v1/health/ready"),
        fetch("/api/v1/dashboard/summary").then(readJson<DashboardSummary>),
        fetch("/api/v1/projects?limit=100").then(readJson<ProjectList>),
      ]);
      setApiReady(health.ok);
      setSummary(dashboard);
      setProjects(projectList.items);
    } catch {
      setApiReady(false);
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const createProject = async (event: FormEvent) => {
    event.preventDefault();
    const normalized = projectName.trim();
    if (!normalized) return;
    setCreating(true);
    try {
      await fetch("/api/v1/projects", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: normalized }),
      }).then(readJson<Project>);
      setProjectName("");
      setShowCreate(false);
      await loadData();
      setView("projects");
    } catch {
      setError(true);
    } finally {
      setCreating(false);
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
          {navViews.map((item) => (
            <button
              className={view === item ? "nav-item active" : "nav-item"}
              key={item}
              onClick={() => setView(item)}
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
            <small>v0.0.1 · Phase 0+</small>
          </div>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">{t.webFoundation}</span>
            <h1>{currentTitle}</h1>
          </div>
          <div className="topbar-actions">
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
          {error && <div className="error-banner">{t.error}</div>}
          {view === "overview" && (
            <Overview
              language={language}
              metrics={metrics}
              projects={projects.slice(0, 5)}
              t={t}
              onCreate={() => setShowCreate(true)}
              onProjects={() => setView("projects")}
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
    </div>
  );
}

type Translation = (typeof copy)[Language];

function Overview({
  language,
  metrics,
  projects,
  t,
  onCreate,
  onProjects,
}: {
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
              <span className="cap-icon locked">⌁</span>
              <div><strong>{t.locked}</strong><p>{t.lockedText}</p></div>
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

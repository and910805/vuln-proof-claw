import { FormEvent } from "react";

import {
  AssessmentHistoryItem,
  AssessmentSummary,
  EngagementReport,
  Project,
} from "./contracts";

type AssessmentCopy = {
  pageHints: { assessments: string };
  assessmentTitle: string;
  assessmentHint: string;
  assessmentDisabled: string;
  chooseProject: string;
  chooseProjectPlaceholder: string;
  advancedOptions: string;
  testMode: string;
  modeActiveSafe: string;
  modePassive: string;
  scanPreset: string;
  presetSafe: string;
  presetFast: string;
  presetDeep: string;
  automaticProject: string;
  targetUrl: string;
  targetPlaceholder: string;
  authorizationConfirm: string;
  assessing: string;
  preparingScope: string;
  contactingTarget: string;
  buildingReport: string;
  runAssessment: string;
  assessmentResult: string;
  actionState: string;
  findingCount: string;
  evidenceCount: string;
  evidenceIntegrity: string;
  pagesScanned: string;
  crawlLimited: string;
  activeProbes: string;
  apiOperations: string;
  activeLimited: string;
  findingDetails: string;
  noFindings: string;
  downloadJson: string;
  downloadMarkdown: string;
  downloadSarif: string;
  downloadBundle: string;
  previewHtml: string;
  viewResult: string;
  emptyPendingHint: string;
  assessmentHistory: string;
  assessmentHistoryHint: string;
  assessmentHistoryFilter: string;
  allProjects: string;
  historyCount: string;
  noAssessmentHistory: string;
  loadingHistory: string;
  completedAt: string;
};

export function AssessmentWorkspace({
  authorizationConfirmed,
  assessing,
  history,
  historyLoading,
  historyProjectId,
  historyTotal,
  executionAvailable,
  latestAssessment,
  latestReport,
  message,
  projectId,
  projects,
  mode,
  preset,
  target,
  stage,
  t,
  onAuthorizationChange,
  onDownload,
  onHistoryDownload,
  onHistoryProjectChange,
  onHistoryView,
  onPreviewHtml,
  onModeChange,
  onPresetChange,
  onProjectChange,
  onSubmit,
  onTargetChange,
  formatTimestamp,
}: {
  authorizationConfirmed: boolean;
  assessing: boolean;
  history: AssessmentHistoryItem[];
  historyLoading: boolean;
  historyProjectId: string;
  historyTotal: number;
  executionAvailable: boolean;
  latestAssessment: AssessmentSummary | AssessmentHistoryItem | null;
  latestReport: EngagementReport | null;
  message: string;
  projectId: string;
  projects: Project[];
  mode: "passive" | "active-safe";
  preset: "safe" | "fast" | "deep";
  target: string;
  stage: "preparing" | "capturing" | "reporting" | null;
  t: AssessmentCopy;
  onAuthorizationChange: (value: boolean) => void;
  onDownload: (format: "json" | "markdown" | "sarif" | "bundle") => void;
  onHistoryDownload: (
    assessment: AssessmentHistoryItem,
    format: "json" | "markdown" | "sarif" | "bundle",
  ) => void;
  onHistoryProjectChange: (value: string) => void;
  onHistoryView: (assessment: AssessmentHistoryItem) => void;
  onPreviewHtml: () => void;
  onModeChange: (value: "passive" | "active-safe") => void;
  onPresetChange: (value: "safe" | "fast" | "deep") => void;
  onProjectChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onTargetChange: (value: string) => void;
  formatTimestamp: (value: string) => string;
}) {
  const canRun = executionAvailable
    && Boolean(target.trim())
    && authorizationConfirmed
    && !assessing;
  const evidenceCount = latestAssessment
    ? "evidence_ids" in latestAssessment
      ? latestAssessment.evidence_ids.length
      : latestAssessment.evidence_count
    : 0;
  return (
    <>
      <div className="page-intro"><p>{t.pageHints.assessments}</p></div>
      <div className="assessment-grid">
        <section className="panel assessment-panel">
          <div className="panel-heading">
            <div><h3>{t.assessmentTitle}</h3><p id="assessment-hint">{t.assessmentHint}</p></div>
          </div>
          {!executionAvailable && <div className="locked-notice">⌁ {t.assessmentDisabled}</div>}
          <form onSubmit={onSubmit}>
            <label htmlFor="assessment-target">{t.targetUrl}</label>
            <input
              autoComplete="url"
              id="assessment-target"
              maxLength={2048}
              onChange={(event) => onTargetChange(event.target.value)}
              placeholder={t.targetPlaceholder}
              required
              type="url"
              value={target}
            />
            <label htmlFor="assessment-mode">{t.testMode}</label>
            <select
              id="assessment-mode"
              onChange={(event) => onModeChange(event.target.value as "passive" | "active-safe")}
              value={mode}
            >
              <option value="active-safe">{t.modeActiveSafe}</option>
              <option value="passive">{t.modePassive}</option>
            </select>
            <details className="assessment-advanced">
              <summary>{t.advancedOptions}</summary>
              <p>{t.automaticProject}</p>
              <label htmlFor="assessment-preset">{t.scanPreset}</label>
              <select
                id="assessment-preset"
                onChange={(event) => onPresetChange(event.target.value as "safe" | "fast" | "deep")}
                value={preset}
              >
                <option value="safe">{t.presetSafe}</option>
                <option value="fast">{t.presetFast}</option>
                <option value="deep">{t.presetDeep}</option>
              </select>
              <label htmlFor="assessment-project">{t.chooseProject}</label>
              <select
                aria-describedby="assessment-hint"
                id="assessment-project"
                onChange={(event) => onProjectChange(event.target.value)}
                value={projectId}
              >
                <option value="">{t.chooseProjectPlaceholder}</option>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>{project.name}</option>
                ))}
              </select>
            </details>
            <label className="authorization-check" htmlFor="authorization-confirmed">
              <input
                checked={authorizationConfirmed}
                id="authorization-confirmed"
                onChange={(event) => onAuthorizationChange(event.target.checked)}
                required
                type="checkbox"
              />
              <span>{t.authorizationConfirm}</span>
            </label>
            <button className="primary-button assessment-submit" disabled={!canRun}>
              {assessing ? t.assessing : t.runAssessment}
            </button>
            {assessing && (
              <ol aria-live="polite" className="assessment-progress">
                <ProgressStep active={stage === "preparing"} complete={stage !== "preparing"} label={t.preparingScope} />
                <ProgressStep active={stage === "capturing"} complete={stage === "reporting"} label={t.contactingTarget} />
                <ProgressStep active={stage === "reporting"} complete={false} label={t.buildingReport} />
              </ol>
            )}
          </form>
          {message && (
            <div aria-live="polite" className="assessment-message" role="status">{message}</div>
          )}
        </section>

        <section className="panel assessment-result" id="assessment-result">
          <div className="panel-heading"><div><h3>{t.assessmentResult}</h3></div></div>
          {latestAssessment ? (
            <>
              <dl>
                <div><dt>{t.actionState}</dt><dd>{latestAssessment.state}</dd></div>
                <div><dt>{t.findingCount}</dt><dd>{latestAssessment.findings_count}</dd></div>
                <div><dt>{t.evidenceCount}</dt><dd>{evidenceCount}</dd></div>
                {latestReport && (
                  <div>
                    <dt>{t.evidenceIntegrity}</dt>
                    <dd>{latestReport.evidence_integrity.status}</dd>
                  </div>
                )}
                {latestReport && (
                  <div><dt>{t.pagesScanned}</dt><dd>{latestReport.discovery.pages_scanned}</dd></div>
                )}
                {latestReport && (
                  <div><dt>{t.apiOperations}</dt><dd>{latestReport.api_inventory.operations_total}</dd></div>
                )}
                {latestReport && (
                  <div><dt>{t.activeProbes}</dt><dd>{latestReport.api_inventory.active_probes_run}</dd></div>
                )}
              </dl>
              {"crawl_truncated" in latestAssessment && latestAssessment.crawl_truncated && (
                <p className="crawl-limited">{t.crawlLimited}</p>
              )}
              {"active_probe_truncated" in latestAssessment
                && latestAssessment.active_probe_truncated && (
                <p className="crawl-limited">{t.activeLimited}</p>
              )}
              {latestReport && (
                <div className="finding-results">
                  <h4>{t.findingDetails}</h4>
                  {latestReport.findings.length === 0 ? (
                    <p>{t.noFindings}</p>
                  ) : (
                    <ul>
                      {latestReport.findings.map((finding) => (
                        <li key={finding.id}>
                          <div className="finding-heading">
                            <strong>{finding.title}</strong>
                            <span className={`severity-badge severity-${finding.severity}`}>
                              {finding.severity}
                            </span>
                          </div>
                          <code>{finding.vulnerability_class} · {finding.confidence}</code>
                          <span>{finding.affected_target}</span>
                          <p>{finding.remediation}</p>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
              <code className="action-reference">{latestAssessment.action_id}</code>
              <div className="report-actions">
                <button className="quiet-button" onClick={() => onDownload("json")} type="button">
                  {t.downloadJson}
                </button>
                <button className="quiet-button" onClick={() => onDownload("markdown")} type="button">
                  {t.downloadMarkdown}
                </button>
                <button className="quiet-button" onClick={() => onDownload("sarif")} type="button">
                  {t.downloadSarif}
                </button>
                <button className="quiet-button" onClick={() => onDownload("bundle")} type="button">
                  {t.downloadBundle}
                </button>
                <button className="quiet-button" onClick={onPreviewHtml} type="button">
                  {t.previewHtml}
                </button>
              </div>
            </>
          ) : (
            <div className="empty-state compact">
              <div className="empty-mark"><span /><span /><span /></div>
              <p>{t.emptyPendingHint}</p>
            </div>
          )}
        </section>
      </div>

      <section className="panel assessment-history">
        <div className="panel-heading history-heading">
          <div>
            <h3>{t.assessmentHistory}</h3>
            <p>{t.assessmentHistoryHint}</p>
          </div>
          <label className="history-filter" htmlFor="assessment-history-project">
            <span>{t.assessmentHistoryFilter}</span>
            <select
              id="assessment-history-project"
              onChange={(event) => onHistoryProjectChange(event.target.value)}
              value={historyProjectId}
            >
              <option value="">{t.allProjects}</option>
              {projects.map((project) => (
                <option key={project.id} value={project.id}>{project.name}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="history-summary">
          <span>{t.historyCount}</span>
          <strong>{historyTotal.toLocaleString()}</strong>
        </div>
        {historyLoading ? (
          <div aria-busy="true" className="history-loading">{t.loadingHistory}</div>
        ) : history.length === 0 ? (
          <div className="history-empty"><p>{t.noAssessmentHistory}</p></div>
        ) : (
          <div className="history-list">
            {history.map((item) => {
              const project = projects.find((candidate) => candidate.id === item.project_id);
              return (
                <article className="history-row" key={item.action_id}>
                  <div className="history-primary">
                    <div className={`state-badge state-${item.state}`}>
                      <span aria-hidden="true" />{item.state}
                    </div>
                    <strong title={item.target}>{item.target}</strong>
                    <small>{project?.name ?? item.project_id}</small>
                  </div>
                  <dl className="history-metrics">
                    <div><dt>{t.evidenceCount}</dt><dd>{item.evidence_count}</dd></div>
                    <div><dt>{t.findingCount}</dt><dd>{item.findings_count}</dd></div>
                  </dl>
                  <div className="history-time">
                    <span>{t.completedAt}</span>
                    <time dateTime={item.completed_at ?? item.created_at}>
                      {formatTimestamp(item.completed_at ?? item.created_at)}
                    </time>
                    {item.error_code && <code>{item.error_code}</code>}
                  </div>
                  <div className="history-actions">
                    <button
                      aria-label={`${t.viewResult}: ${item.target}`}
                      className="quiet-button"
                      onClick={() => onHistoryView(item)}
                      type="button"
                    >
                      {t.viewResult}
                    </button>
                    <button
                      aria-label={`${t.downloadJson}: ${item.target}`}
                      className="quiet-button"
                      onClick={() => onHistoryDownload(item, "json")}
                      type="button"
                    >
                      JSON
                    </button>
                    <button
                      aria-label={`${t.downloadMarkdown}: ${item.target}`}
                      className="quiet-button"
                      onClick={() => onHistoryDownload(item, "markdown")}
                      type="button"
                    >
                      Markdown
                    </button>
                    <button
                      aria-label={`${t.downloadSarif}: ${item.target}`}
                      className="quiet-button"
                      onClick={() => onHistoryDownload(item, "sarif")}
                      type="button"
                    >
                      SARIF
                    </button>
                    <button
                      aria-label={`${t.downloadBundle}: ${item.target}`}
                      className="quiet-button"
                      onClick={() => onHistoryDownload(item, "bundle")}
                      type="button"
                    >
                      Bundle
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </section>
    </>
  );
}

function ProgressStep({
  active,
  complete,
  label,
}: {
  active: boolean;
  complete: boolean;
  label: string;
}) {
  const className = active ? "active" : complete ? "complete" : "";
  return <li aria-current={active ? "step" : undefined} className={className}>{label}</li>;
}

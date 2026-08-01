import { FormEvent } from "react";

import { AssessmentHistoryItem, AssessmentSummary, Project } from "./contracts";

type AssessmentCopy = {
  pageHints: { assessments: string };
  assessmentTitle: string;
  assessmentHint: string;
  assessmentDisabled: string;
  chooseProject: string;
  chooseProjectPlaceholder: string;
  targetUrl: string;
  targetPlaceholder: string;
  authorizationConfirm: string;
  assessing: string;
  runAssessment: string;
  assessmentResult: string;
  actionState: string;
  findingCount: string;
  evidenceCount: string;
  downloadJson: string;
  downloadMarkdown: string;
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
  message,
  projectId,
  projects,
  target,
  t,
  onAuthorizationChange,
  onDownload,
  onHistoryDownload,
  onHistoryProjectChange,
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
  latestAssessment: AssessmentSummary | null;
  message: string;
  projectId: string;
  projects: Project[];
  target: string;
  t: AssessmentCopy;
  onAuthorizationChange: (value: boolean) => void;
  onDownload: (format: "json" | "markdown") => void;
  onHistoryDownload: (assessment: AssessmentHistoryItem, format: "json" | "markdown") => void;
  onHistoryProjectChange: (value: string) => void;
  onProjectChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onTargetChange: (value: string) => void;
  formatTimestamp: (value: string) => string;
}) {
  const canRun = executionAvailable
    && Boolean(projectId)
    && Boolean(target.trim())
    && authorizationConfirmed
    && !assessing;
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
            <label htmlFor="assessment-project">{t.chooseProject}</label>
            <select
              aria-describedby="assessment-hint"
              id="assessment-project"
              onChange={(event) => onProjectChange(event.target.value)}
              required
              value={projectId}
            >
              <option value="">{t.chooseProjectPlaceholder}</option>
              {projects.map((project) => (
                <option key={project.id} value={project.id}>{project.name}</option>
              ))}
            </select>
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
          </form>
          {message && (
            <div aria-live="polite" className="assessment-message" role="status">{message}</div>
          )}
        </section>

        <section className="panel assessment-result">
          <div className="panel-heading"><div><h3>{t.assessmentResult}</h3></div></div>
          {latestAssessment ? (
            <>
              <dl>
                <div><dt>{t.actionState}</dt><dd>{latestAssessment.state}</dd></div>
                <div><dt>{t.findingCount}</dt><dd>{latestAssessment.findings_count}</dd></div>
                <div><dt>{t.evidenceCount}</dt><dd>{latestAssessment.evidence_ids.length}</dd></div>
              </dl>
              <code className="action-reference">{latestAssessment.action_id}</code>
              <div className="report-actions">
                <button className="quiet-button" onClick={() => onDownload("json")} type="button">
                  {t.downloadJson}
                </button>
                <button className="quiet-button" onClick={() => onDownload("markdown")} type="button">
                  {t.downloadMarkdown}
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

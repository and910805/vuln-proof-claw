import { FormEvent } from "react";

import { AssessmentSummary, Project } from "./contracts";

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
};

export function AssessmentWorkspace({
  authorizationConfirmed,
  assessing,
  executionAvailable,
  latestAssessment,
  message,
  projectId,
  projects,
  target,
  t,
  onAuthorizationChange,
  onDownload,
  onProjectChange,
  onSubmit,
  onTargetChange,
}: {
  authorizationConfirmed: boolean;
  assessing: boolean;
  executionAvailable: boolean;
  latestAssessment: AssessmentSummary | null;
  message: string;
  projectId: string;
  projects: Project[];
  target: string;
  t: AssessmentCopy;
  onAuthorizationChange: (value: boolean) => void;
  onDownload: (format: "json" | "markdown") => void;
  onProjectChange: (value: string) => void;
  onSubmit: (event: FormEvent) => void;
  onTargetChange: (value: string) => void;
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
    </>
  );
}

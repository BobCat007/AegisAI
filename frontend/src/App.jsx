
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity, AlertTriangle, Bell, Bot, CheckCircle2, CircleHelp,
  Clock3, Cpu, ExternalLink, Fingerprint, LayoutDashboard,
  LockKeyhole, RefreshCw, Shield, ShieldAlert, ShieldCheck,
  Siren, Wifi, X, Send, MessageSquare, User, FileText,
} from 'lucide-react';

const REFRESH_MS = 15000;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    const detail = typeof payload.detail === 'string'
      ? payload.detail
      : `Request failed (${response.status})`;
    throw new Error(detail);
  }

  return payload;
}

function renderInlineMarkdown(text, keyPrefix = 'inline') {
  const parts = String(text || '').split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g);
  return parts.map((part, index) => {
    if (part.startsWith('**') && part.endsWith('**')) {
      return <strong key={`${keyPrefix}-${index}`}>{part.slice(2, -2)}</strong>;
    }
    if (part.startsWith('`') && part.endsWith('`')) {
      return <code key={`${keyPrefix}-${index}`}>{part.slice(1, -1)}</code>;
    }
    if (part.startsWith('*') && part.endsWith('*')) {
      return <em key={`${keyPrefix}-${index}`}>{part.slice(1, -1)}</em>;
    }
    return part;
  });
}

function MarkdownContent({ content }) {
  // Normalize both real line endings and escaped Markdown returned by some model responses.
  const normalizedContent = String(content || '')
    .replace(/\r\n?/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\\([*`#])/g, '$1');
  const lines = normalizedContent.split('\n');
  const blocks = [];
  let paragraph = [];
  let listItems = [];
  let listType = null;

  const flushParagraph = () => {
    if (paragraph.length) {
      blocks.push({ type: 'paragraph', text: paragraph.join(' ').trim() });
      paragraph = [];
    }
  };
  const flushList = () => {
    if (listItems.length) {
      blocks.push({ type: listType, items: listItems });
      listItems = [];
      listType = null;
    }
  };

  lines.forEach((rawLine) => {
    const line = rawLine.trim();
    if (!line) {
      flushParagraph();
      flushList();
      return;
    }
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    const bullet = line.match(/^[-*+]\s+(.+)$/);
    const numbered = line.match(/^\d+[.)]\s+(.+)$/);
    if (heading) {
      flushParagraph(); flushList();
      blocks.push({ type: 'heading', level: heading[1].length, text: heading[2] });
    } else if (bullet || numbered) {
      flushParagraph();
      const nextType = bullet ? 'ul' : 'ol';
      if (listType && listType !== nextType) flushList();
      listType = nextType;
      listItems.push((bullet || numbered)[1]);
    } else {
      flushList();
      paragraph.push(line);
    }
  });
  flushParagraph();
  flushList();

  return (
    <div className="copilot-markdown">
      {blocks.map((block, index) => {
        if (block.type === 'heading') {
          const Tag = block.level <= 2 ? 'h3' : 'h4';
          return <Tag key={index}>{renderInlineMarkdown(block.text, `h-${index}`)}</Tag>;
        }
        if (block.type === 'ul' || block.type === 'ol') {
          const Tag = block.type;
          return <Tag key={index}>{block.items.map((item, itemIndex) => (
            <li key={itemIndex}>{renderInlineMarkdown(item, `li-${index}-${itemIndex}`)}</li>
          ))}</Tag>;
        }
        return <p key={index}>{renderInlineMarkdown(block.text, `p-${index}`)}</p>;
      })}
    </div>
  );
}

function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function shortId(value) {
  return value ? `${value.slice(0, 8)}…` : '—';
}

function severityClass(value) {
  return `severity severity-${String(value || 'low').toLowerCase()}`;
}

function statusClass(value) {
  return `status status-${String(value || 'unknown').toLowerCase().replaceAll('_', '-')}`;
}

function MetricCard({ label, value, detail, icon: Icon, tone = 'blue' }) {
  return (
    <article className="metric-card">
      <div className={`metric-icon ${tone}`}>
        <Icon size={19} />
      </div>
      <div className="metric-copy">
        <span className="metric-label">{label}</span>
        <strong>{value}</strong>
        <span className="metric-detail">{detail}</span>
      </div>
    </article>
  );
}

function EmptyState({ icon: Icon = ShieldCheck, title, detail }) {
  return (
    <div className="empty-state">
      <Icon size={25} />
      <strong>{title}</strong>
      <span>{detail}</span>
    </div>
  );
}

function AnalyticsPanel({ analytics }) {
  const volume = analytics?.request_volume || [];
  const statuses = analytics?.status_distribution || {};
  const endpoints = analytics?.top_endpoints || [];

  const maxVolume = Math.max(1, ...volume.map((item) => item.count));
  const maxEndpoint = Math.max(1, ...endpoints.map((item) => item.count));
  const maxStatus = Math.max(1, ...Object.values(statuses));

  const statusColors = {
    '2xx': 'success',
    '3xx': 'info',
    '4xx': 'warning',
    '5xx': 'danger',
    other: 'muted',
  };

  return (
    <section className="analytics-grid">
      <article className="panel analytics-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">TRAFFIC ANALYTICS</div>
            <h2>Request volume</h2>
            <p>
              Requests per {analytics?.bucket_minutes || 5}-minute interval
              {' '}· last {analytics?.lookback_minutes || 60} minutes
            </p>
          </div>
          <span className="count-pill">
            {(analytics?.events_analyzed || 0).toLocaleString()} events
          </span>
        </div>

        <div className="volume-chart">
          {volume.map((item) => (
            <div
              className="volume-column"
              key={item.timestamp}
              title={`${item.count} requests`}
            >
              <div
                className="volume-bar"
                style={{
                  height: `${Math.max(2, (item.count / maxVolume) * 100)}%`,
                }}
              />
            </div>
          ))}

          {!volume.length && (
            <EmptyState
              title="No traffic data"
              detail="Retained telemetry will appear here."
            />
          )}
        </div>

        <div className="chart-axis">
          <span>Earlier</span>
          <span>Now</span>
        </div>
      </article>

      <article className="panel analytics-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">HTTP RESPONSES</div>
            <h2>Status distribution</h2>
            <p>Response classes across retained events</p>
          </div>
        </div>

        <div className="analytics-bars">
          {Object.entries(statuses).map(([label, count]) => (
            <div className="analytics-bar-row" key={label}>
              <span>{label}</span>
              <div className="analytics-track">
                <div
                  className={`analytics-fill ${statusColors[label] || 'muted'}`}
                  style={{ width: `${(count / maxStatus) * 100}%` }}
                />
              </div>
              <b>{count}</b>
            </div>
          ))}
        </div>

        <div className="auth-failure">
          <div>
            <span className="panel-kicker">AUTHENTICATION FAILURES</span>
            <strong>{analytics?.authentication_failures ?? '—'}</strong>
          </div>
          <span>HTTP 401 + 403</span>
        </div>
      </article>

      <article className="panel analytics-panel endpoint-panel">
        <div className="panel-header">
          <div>
            <div className="panel-kicker">API DISCOVERY</div>
            <h2>Top endpoints</h2>
            <p>Most frequently observed paths</p>
          </div>
        </div>

        <div className="analytics-bars endpoint-bars">
          {endpoints.map((item) => (
            <div className="analytics-bar-row" key={item.endpoint}>
              <span className="endpoint-name" title={item.endpoint}>
                {item.endpoint}
              </span>
              <div className="analytics-track">
                <div
                  className="analytics-fill endpoint-fill"
                  style={{
                    width: `${(item.count / maxEndpoint) * 100}%`,
                  }}
                />
              </div>
              <b>{item.count}</b>
            </div>
          ))}

          {!endpoints.length && (
            <EmptyState
              title="No endpoint data"
              detail="Endpoints will appear when telemetry is received."
            />
          )}
        </div>
      </article>
    </section>
  );
}

function App() {
  const [incidents, setIncidents] = useState([]);
  const [eventsConsidered, setEventsConsidered] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [copilot, setCopilot] = useState(null);
  const [health, setHealth] = useState(null);
  const [analytics, setAnalytics] = useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [responsePlan, setResponsePlan] = useState(null);
  const [actionError, setActionError] = useState('');
  const [copilotQuestion, setCopilotQuestion] = useState('');
  const [copilotMessages, setCopilotMessages] = useState([]);
  const [copilotBusy, setCopilotBusy] = useState(false);
  const [copilotError, setCopilotError] = useState('');

  const refresh = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    const requests = [
      ['incidents', () => api('/api/telemetry/incidents?lookback_minutes=60&window_seconds=300')],
      ['alerts', () => api('/api/telemetry/alerts?limit=100')],
      ['copilot', () => api('/api/copilot/status')],
      ['health', () => api('/health')],
      ['analytics', () => api('/api/telemetry/analytics?lookback_minutes=60&bucket_minutes=5')],
    ];
    const results = await Promise.allSettled(requests.map(([, request]) => request()));
    const failures = [];
    results.forEach((result, index) => {
      const [name] = requests[index];
      if (result.status === 'rejected') {
        failures.push(`${name}: ${result.reason?.message || 'request failed'}`);
        return;
      }
      const data = result.value;
      if (name === 'incidents') {
        setIncidents(data.incidents || []);
        setEventsConsidered(data.events_considered || 0);
      } else if (name === 'alerts') setAlerts(data.alerts || []);
      else if (name === 'copilot') setCopilot(data);
      else if (name === 'health') setHealth(data);
      else if (name === 'analytics') setAnalytics(data);
    });
    if (results.some((result) => result.status === 'fulfilled')) setLastUpdated(new Date());
    setError(failures.length ? `Some dashboard data could not be refreshed: ${failures.join(' · ')}` : '');
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    refresh();
    const timer = window.setInterval(() => refresh(), REFRESH_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const openAlerts = useMemo(
    () => alerts.filter((item) => item.status === 'open').length,
    [alerts]
  );

  const acknowledgedAlerts = useMemo(
    () => alerts.filter((item) => item.status === 'acknowledged').length,
    [alerts]
  );

  const highPriority = useMemo(
    () => incidents.filter((item) => ['high', 'critical'].includes(item.severity)).length,
    [incidents]
  );

  const visibleIncidents = useMemo(() => {
    if (filter === 'all') return incidents;
    return incidents.filter((item) => item.severity === filter);
  }, [incidents, filter]);

  async function generatePlan(incident) {
    setActionError('');
    setResponsePlan(null);

    try {
      const result = await api(
        `/api/telemetry/incidents/${encodeURIComponent(incident.incident_id)}/response-plan`,
        { method: 'POST', body: '{}' }
      );
      setResponsePlan(result);
    } catch (err) {
      setActionError(err.message || 'Could not generate response plan.');
    }
  }

  async function updateAlert(alert, nextStatus) {
    setActionError('');

    const reason = nextStatus === 'acknowledged'
      ? 'Acknowledged from AegisAI dashboard.'
      : 'Resolved from AegisAI dashboard.';

    try {
      await api(
        `/api/telemetry/alerts/${encodeURIComponent(alert.alert_id)}/status`,
        {
          method: 'PATCH',
          body: JSON.stringify({
            new_status: nextStatus,
            changed_by: 'dashboard_operator',
            reason,
          }),
        }
      );

      await refresh();
    } catch (err) {
      setActionError(err.message || 'Could not update alert.');
    }
  }

  async function askCopilot(event) {
    event.preventDefault();
    const question = copilotQuestion.trim();
    if (question.length < 3 || copilotBusy) return;
    setCopilotError('');
    setCopilotBusy(true);
    setCopilotQuestion('');
    setCopilotMessages((messages) => [...messages, {
      role: 'user', content: question, id: `user-${Date.now()}`,
    }]);
    try {
      const result = await api('/api/copilot/ask', {
        method: 'POST',
        body: JSON.stringify({
          question, top_k: 5, document_types: [], include_unconfirmed: true,
        }),
      });
      setCopilotMessages((messages) => [...messages, {
        role: 'assistant', content: result.answer, result,
        id: result.response_id || `answer-${Date.now()}`,
      }]);
    } catch (err) {
      setCopilotError(err.message || 'Security Copilot could not answer this question.');
      setCopilotQuestion(question);
    } finally {
      setCopilotBusy(false);
    }
  }

  function navigateTo(sectionId) {
    document.getElementById(sectionId)?.scrollIntoView({
      behavior: 'smooth', block: 'start',
    });
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={22} /></div>
          <div>
            <b>AEGIS<span>AI</span></b>
            <small>API SECURITY PLATFORM</small>
          </div>
        </div>

        <div className="nav-label">WORKSPACE</div>
        <button className="nav-item" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>
          <LayoutDashboard size={17} /> Overview
        </button>
        <button className="nav-item" onClick={() => navigateTo('incidents-section')}>
          <Siren size={17} /> Incidents
          <span className="nav-count">{incidents.length}</span>
        </button>
        <button className="nav-item" onClick={() => navigateTo('alerts-section')}>
          <Bell size={17} /> Alerts
          <span className="nav-count">{openAlerts}</span>
        </button>
        <button className="nav-item" onClick={() => navigateTo('copilot-section')}>
          <MessageSquare size={17} /> Security Copilot
        </button>

        <div className="nav-label nav-label-spaced">SYSTEM</div>
        <div className="system-status">
          <span className={`pulse ${health?.status === 'healthy' ? 'online' : ''}`} />
          <div>
            <b>Detection API</b>
            <small>
              {health?.status === 'healthy' ? 'Connected' : 'Checking connection'}
            </small>
          </div>
        </div>

        <div className="sidebar-bottom">
          <div className="sidebar-version">AEGISAI <span>v0.1.0</span></div>
          <small>Security signals. Clear decisions.</small>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS / OVERVIEW</div>
            <h1>Security Overview</h1>
            <p className="subtitle">
              Monitor API security signals, correlated incidents, and response activity.
            </p>
          </div>

          <div className="topbar-actions">
            <div className="live-indicator">
              <span className={`pulse ${health?.status === 'healthy' ? 'online' : ''}`} /> AUTO REFRESH · 15s
            </div>
            <button
              className="refresh-button"
              onClick={() => refresh(true)}
              disabled={refreshing}
            >
              <RefreshCw size={15} className={refreshing ? 'spin' : ''} />
              Refresh
            </button>
          </div>
        </header>

        {error && (
          <div className="error-banner">
            <AlertTriangle size={17} />
            <span>
              {error} Check that the FastAPI backend is running and the API key is configured in the root .env.
            </span>
          </div>
        )}

        {actionError && (
          <div className="error-banner">
            <AlertTriangle size={17} />
            <span>{actionError}</span>
            <button onClick={() => setActionError('')} aria-label="Dismiss">
              <X size={15} />
            </button>
          </div>
        )}

        <section className="metric-grid" id="overview-section">
          <MetricCard
            label="Events analyzed"
            value={loading ? '—' : eventsConsidered.toLocaleString()}
            detail="Retained telemetry · last 60 min"
            icon={Activity}
            tone="blue"
          />
          <MetricCard
            label="Correlated incidents"
            value={loading ? '—' : incidents.length}
            detail="Heuristic correlations"
            icon={ShieldAlert}
            tone="purple"
          />
          <MetricCard
            label="High / critical"
            value={loading ? '—' : highPriority}
            detail="Incidents needing attention"
            icon={AlertTriangle}
            tone="red"
          />
          <MetricCard
            label="Open alerts"
            value={loading ? '—' : openAlerts}
            detail={`${acknowledgedAlerts} acknowledged`}
            icon={Bell}
            tone="amber"
          />
        </section>

        <AnalyticsPanel analytics={analytics} />

        <section className="content-grid">
          <article className="panel incidents-panel" id="incidents-section">
            <div className="panel-header">
              <div>
                <div className="panel-kicker">THREAT ACTIVITY</div>
                <h2>Correlated incidents</h2>
                <p>Suspected activity grouped by pseudonymous actor and time window.</p>
              </div>

              <div className="panel-tools">
                <select
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                  aria-label="Filter incidents"
                >
                  <option value="all">All severity</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <span className="count-pill">{visibleIncidents.length}</span>
              </div>
            </div>

            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>INCIDENT</th>
                    <th>SEVERITY</th>
                    <th>ACTOR</th>
                    <th>EVENTS</th>
                    <th>LAST SEEN</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {visibleIncidents.map((incident) => (
                    <tr key={incident.incident_id}>
                      <td>
                        <button
                          className="text-link"
                          onClick={() => setSelectedIncident(incident)}
                        >
                          {shortId(incident.incident_id)}
                        </button>
                        <small className="cell-sub">
                          {incident.distinct_endpoints} endpoints
                        </small>
                      </td>
                      <td>
                        <span className={severityClass(incident.severity)}>
                          {incident.severity}
                        </span>
                      </td>
                      <td>
                        <span className="actor-type">
                          <Fingerprint size={13} />
                          {incident.actor_type}
                        </span>
                        <small className="cell-sub mono">
                          {shortId(incident.actor_reference)}
                        </small>
                      </td>
                      <td className="numeric">{incident.event_count}</td>
                      <td className="date-cell">{formatDate(incident.window_end)}</td>
                      <td>
                        <button
                          className="icon-button"
                          title="View incident"
                          onClick={() => setSelectedIncident(incident)}
                        >
                          <ExternalLink size={15} />
                        </button>
                      </td>
                    </tr>
                  ))}

                  {!loading && visibleIncidents.length === 0 && (
                    <tr>
                      <td colSpan="6">
                        <EmptyState
                          icon={ShieldCheck}
                          title="No incidents in this view"
                          detail="Correlated incidents will appear here when retained telemetry meets the correlation rules."
                        />
                      </td>
                    </tr>
                  )}

                  {loading && (
                    <tr>
                      <td colSpan="6">
                        <EmptyState
                          icon={RefreshCw}
                          title="Loading security data"
                          detail="Connecting to AegisAI services…"
                        />
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="panel-footer">
              <span><span className="pulse online" /> Correlation window: 60 minutes</span>
              <span>Refreshes every 15 seconds</span>
            </div>
          </article>

          <article className="panel alerts-panel" id="alerts-section">
            <div className="panel-header">
              <div>
                <div className="panel-kicker">RESPONSE QUEUE</div>
                <h2>Recent alerts</h2>
                <p>Persistent analyst-facing notifications.</p>
              </div>
              <span className="count-pill">{alerts.length}</span>
            </div>

            <div className="alert-list">
              {alerts.slice(0, 7).map((alert) => (
                <div className="alert-row" key={alert.alert_id}>
                  <div className={`alert-symbol ${alert.severity}`}>
                    <AlertTriangle size={16} />
                  </div>
                  <div className="alert-main">
                    <div className="alert-title-row">
                      <b>{alert.summary}</b>
                      <span className={severityClass(alert.severity)}>
                        {alert.severity}
                      </span>
                    </div>
                    <div className="alert-meta">
                      <span>{shortId(alert.alert_id)}</span>
                      <span>·</span>
                      <span>{formatDate(alert.created_at)}</span>
                    </div>
                    <div className="alert-actions">
                      <span className={statusClass(alert.status)}>{alert.status}</span>
                      {alert.status === 'open' && (
                        <button onClick={() => updateAlert(alert, 'acknowledged')}>
                          Acknowledge
                        </button>
                      )}
                      {alert.status === 'acknowledged' && (
                        <button onClick={() => updateAlert(alert, 'resolved')}>
                          Resolve
                        </button>
                      )}
                    </div>
                  </div>
                </div>
              ))}

              {!loading && alerts.length === 0 && (
                <EmptyState
                  icon={CheckCircle2}
                  title="No alerts yet"
                  detail="New alerts are created when telemetry correlation produces incidents."
                />
              )}
            </div>

            <div className="panel-footer">
              <span>{openAlerts} open · {acknowledgedAlerts} acknowledged</span>
              <span>Showing latest 7</span>
            </div>
          </article>
        </section>

        <section className="bottom-grid">
          <article className="panel system-panel">
            <div className="panel-header">
              <div>
                <div className="panel-kicker">PLATFORM HEALTH</div>
                <h2>AI services</h2>
              </div>
              <span className="health-tag">
                <span className={`pulse ${health?.status === 'healthy' ? 'online' : ''}`} />
                {health?.status === 'healthy' ? 'Backend healthy' : 'Backend unavailable'}
              </span>
            </div>

            <div className="service-list">
              <div className="service-row">
                <div className="service-icon"><Cpu size={17} /></div>
                <div>
                  <b>Behavioral telemetry</b>
                  <small>Telemetry analytics and incident correlation endpoints</small>
                </div>
                <span className={`service-state ${analytics ? '' : 'muted'}`}>
                  {analytics ? 'Connected' : 'Unavailable'}
                </span>
              </div>

              <div className="service-row">
                <div className="service-icon"><Bot size={17} /></div>
                <div>
                  <b>Security Copilot</b>
                  <small>{copilot?.model || 'Model status unavailable'}</small>
                </div>
                <span className={`service-state ${copilot?.configured ? '' : 'muted'}`}>
                  {copilot?.configured ? 'Configured' : 'Not configured'}
                </span>
              </div>

              <div className="service-row">
                <div className="service-icon"><LockKeyhole size={17} /></div>
                <div>
                  <b>Knowledge retrieval</b>
                  <small>{copilot?.retrieval || 'Retrieval status unavailable'}</small>
                </div>
                <span className={`service-state ${copilot ? '' : 'muted'}`}>
                  {copilot ? `${copilot.knowledge_index_size ?? 0} indexed` : 'Unavailable'}
                </span>
              </div>
            </div>
          </article>

          <article className="panel context-panel">
            <div className="panel-kicker">MONITORING CONTEXT</div>
            <h2>Signal interpretation</h2>

            <div className="context-note">
              <CircleHelp size={17} />
              <p>
                Incidents are heuristic correlations of telemetry metadata.
                A suspected incident is not proof of an attack or confirmed vulnerability.
              </p>
            </div>

            <div className="context-note">
              <Wifi size={17} />
              <p>
                Events are supplied by an external collector or target-side agent.
                This dashboard does not passively intercept API traffic.
              </p>
            </div>

            <div className="last-updated">
              <Clock3 size={14} />
              Last successful update: {lastUpdated ? lastUpdated.toLocaleTimeString() : 'Waiting for data'}
            </div>
          </article>
        </section>

        <section className="copilot-section panel" id="copilot-section">
          <div className="panel-header">
            <div>
              <div className="panel-kicker">RETRIEVAL-AUGMENTED SECURITY ASSISTANT</div>
              <h2>Security Copilot</h2>
              <p>Ask questions about records ingested into the AegisAI knowledge base.</p>
            </div>
            <span className={`copilot-config ${copilot?.configured ? 'configured' : 'muted'}`}>
              <span className={`pulse ${copilot?.configured ? 'online' : ''}`} />
              {copilot?.configured ? 'Provider configured' : 'Provider not configured'}
            </span>
          </div>
          <div className="copilot-disclaimer">
            <CircleHelp size={16} />
            <span>Answers explain retrieved records; they are not independent security validation. Citations do not confirm a finding.</span>
          </div>
          <div className="copilot-messages" aria-live="polite">
            {!copilotMessages.length && (
              <EmptyState icon={Bot} title="Ask the Security Copilot"
                detail="Example: Summarize the evidence for the latest authentication-related incident." />
            )}
            {copilotMessages.map((message) => (
              <article className={`copilot-message ${message.role}`} key={message.id}>
                <div className="copilot-avatar">
                  {message.role === 'user' ? <User size={15} /> : <Bot size={16} />}
                </div>
                <div className="copilot-message-body">
                  <div className="copilot-message-label">
                    {message.role === 'user' ? 'YOU' : 'AEGISAI COPILOT'}
                  </div>
                  <div className="copilot-answer"><MarkdownContent content={message.content} /></div>
                  {message.result && (
                    <>
                      <div className="copilot-meta">
                        <span>{message.result.model}</span>
                        <span>{message.result.retrieval_method}</span>
                        <span>{message.result.retrieved_count} records retrieved</span>
                      </div>
                      {!!message.result.citations?.length && (
                        <div className="copilot-citations">
                          <h3><FileText size={14} /> Retrieved evidence</h3>
                          {message.result.citations.map((citation, index) => (
                            <div className="citation-card" key={`${citation.document_id}-${citation.chunk_id || index}`}>
                              <div>
                                <b>{citation.title || citation.document_id}</b>
                                <small>{citation.document_type} · {citation.validation_status || 'status unavailable'} · {citation.confirmed ? 'Confirmed record' : 'Unconfirmed record'}</small>
                                {citation.source && <small>Source: {citation.source}</small>}
                              </div>
                              <span>{Number(citation.relevance_score || 0).toFixed(3)}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {!!message.result.limitations?.length && (
                        <details className="copilot-limitations">
                          <summary>Limitations and interpretation notes ({message.result.limitations.length})</summary>
                          <ul>{message.result.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>
                        </details>
                      )}
                    </>
                  )}
                </div>
              </article>
            ))}
            {copilotBusy && (
              <div className="copilot-thinking"><span className="pulse online" /> Retrieving evidence and generating an answer…</div>
            )}
          </div>
          {copilotError && (
            <div className="copilot-error" role="alert"><AlertTriangle size={15} /> {copilotError}</div>
          )}
          <form className="copilot-composer" onSubmit={askCopilot}>
            <textarea value={copilotQuestion}
              onChange={(event) => setCopilotQuestion(event.target.value)}
              placeholder="Ask a security question about your indexed evidence…"
              rows={3} maxLength={4000} minLength={3} disabled={copilotBusy}
              aria-label="Security Copilot question" />
            <div className="copilot-composer-footer">
              <span>Evidence-based responses · Up to 4,000 characters</span>
              <button className="primary-button" type="submit"
                disabled={copilotBusy || copilotQuestion.trim().length < 3}>
                <Send size={14} /> {copilotBusy ? 'Working…' : 'Ask Copilot'}
              </button>
            </div>
          </form>
        </section>

        <footer className="app-footer">
          <span>AEGISAI SECURITY OPERATIONS</span>
          <span>Telemetry metadata only · Privacy-conscious monitoring</span>
        </footer>
      </main>

      {selectedIncident && (
        <div
          className="modal-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setSelectedIncident(null);
          }}
        >
          <section className="modal">
            <div className="modal-header">
              <div>
                <div className="panel-kicker">INCIDENT DETAILS</div>
                <h2>{shortId(selectedIncident.incident_id)}</h2>
              </div>
              <button className="icon-button" onClick={() => setSelectedIncident(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="detail-grid">
              <div>
                <small>SEVERITY</small>
                <span className={severityClass(selectedIncident.severity)}>
                  {selectedIncident.severity}
                </span>
              </div>
              <div>
                <small>PRIORITY SCORE</small>
                <b>{selectedIncident.priority_score}/100</b>
              </div>
              <div>
                <small>ACTOR TYPE</small>
                <b>{selectedIncident.actor_type}</b>
              </div>
              <div>
                <small>EVENT COUNT</small>
                <b>{selectedIncident.event_count}</b>
              </div>
              <div>
                <small>WINDOW START</small>
                <b>{formatDate(selectedIncident.window_start)}</b>
              </div>
              <div>
                <small>WINDOW END</small>
                <b>{formatDate(selectedIncident.window_end)}</b>
              </div>
            </div>

            <div className="detail-section">
              <h3>Summary</h3>
              <p>{selectedIncident.summary}</p>
            </div>

            <div className="detail-section">
              <h3>Indicators</h3>
              <div className="chip-row">
                {(selectedIncident.indicators || []).map((item) => (
                  <span className="detail-chip" key={item}>
                    {item.replaceAll('_', ' ')}
                  </span>
                ))}
              </div>
            </div>

            <div className="detail-section">
              <h3>Evidence ({selectedIncident.evidence?.length || 0})</h3>
              <div className="evidence-list">
                {(selectedIncident.evidence || []).slice(0, 8).map((item) => (
                  <div key={item.event_id}>
                    <b>{item.method} {item.endpoint_path}</b>
                    <span>
                      HTTP {item.status_code} · {formatDate(item.timestamp)}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            <div className="modal-note">
              <AlertTriangle size={15} />
              Vulnerabilities confirmed: {selectedIncident.vulnerabilities_confirmed ? 'Yes' : 'No'}
              {' '}· Correlation is a review signal, not proof of malicious activity.
            </div>

            <button
              className="primary-button"
              onClick={() => generatePlan(selectedIncident)}
            >
              Generate dry-run response plan
            </button>
          </section>
        </div>
      )}

      {responsePlan && (
        <div
          className="modal-backdrop"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setResponsePlan(null);
          }}
        >
          <section className="modal">
            <div className="modal-header">
              <div>
                <div className="panel-kicker">AUTOMATED RESPONSE</div>
                <h2>Response plan generated</h2>
              </div>
              <button className="icon-button" onClick={() => setResponsePlan(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="plan-banner">
              <ShieldCheck size={20} />
              <div>
                <b>Dry-run mode</b>
                <span>No account, identity, client, or network access was changed.</span>
              </div>
            </div>

            <div className="detail-grid">
              <div>
                <small>PLAN ID</small>
                <b className="mono">{shortId(responsePlan.plan_id)}</b>
              </div>
              <div>
                <small>POLICY</small>
                <b>{responsePlan.policy_id}</b>
              </div>
              <div>
                <small>DECISIONS</small>
                <b>{responsePlan.decisions?.length || 0}</b>
              </div>
              <div>
                <small>DRY RUN</small>
                <b>{responsePlan.dry_run ? 'Enabled' : 'Disabled'}</b>
              </div>
            </div>

            <div className="detail-section">
              <h3>Recommendations</h3>
              {(responsePlan.decisions || []).map((decision) => (
                <div className="decision-row" key={decision.decision_id}>
                  <div>
                    <b>{decision.action.replaceAll('_', ' ')}</b>
                    <small>{decision.rationale}</small>
                  </div>
                  <span className={statusClass(decision.execution_status)}>
                    {decision.execution_status.replaceAll('_', ' ')}
                  </span>
                </div>
              ))}
              {!responsePlan.decisions?.length && (
                <p>No actions matched the current response policy.</p>
              )}
            </div>

            <div className="modal-note">
              <LockKeyhole size={15} />
              Recommendations are simulated or proposed. No response action is executed automatically.
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

export default App;

import React from 'react';

export default function StatsPanel({ stats, config }) {
  const s = stats.alerts || {};
  const p = stats.processes || {};

  return (
    <div className="stats-panel">
      <div className="stat-box critical">
        <div className="value">{s.by_severity?.critical || 0}</div>
        <div className="label">Critical</div>
      </div>
      <div className="stat-box high">
        <div className="value">{s.by_severity?.high || 0}</div>
        <div className="label">High</div>
      </div>
      <div className="stat-box medium">
        <div className="value">{s.by_severity?.medium || 0}</div>
        <div className="label">Medium</div>
      </div>
      <div className="stat-box ok">
        <div className="value">{s.total || 0}</div>
        <div className="label">Total Alerts</div>
      </div>
      <div className="stat-box">
        <div className="value">{p.total || 0}</div>
        <div className="label">Processes</div>
      </div>
      <div className="stat-box">
        <div className="value">{p.with_alerts || 0}</div>
        <div className="label">Suspicious</div>
      </div>
      <div className="stat-box">
        <div className="value" style={{ fontSize: 14 }}>
          {config.learning_mode ? 'LEARNING' : 'ENFORCING'}
        </div>
        <div className="label">Mode</div>
      </div>
    </div>
  );
}

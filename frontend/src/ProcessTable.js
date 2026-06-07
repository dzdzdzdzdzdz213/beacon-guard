import React from 'react';

export default function ProcessTable({ processes }) {
  const sorted = [...processes]
    .sort((a, b) => (b.suspicion_score || 0) - (a.suspicion_score || 0))
    .slice(0, 20);

  return (
    <div className="scroll">
      <table>
        <thead>
          <tr>
            <th>PID</th>
            <th>Comm</th>
            <th>Score</th>
            <th>Alerts</th>
            <th>State</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map(p => (
            <tr key={p.pid}>
              <td>{p.pid}</td>
              <td>{p.comm}</td>
              <td style={{ color: (p.suspicion_score || 0) > 80 ? '#ff4444' : '#888' }}>
                {p.suspicion_score || 0}
              </td>
              <td>{p.alert_count || 0}</td>
              <td className={`state-${p.state || 'learning'}`}>{p.state || 'learning'}</td>
            </tr>
          ))}
          {sorted.length === 0 && (
            <tr><td colSpan={5} style={{ textAlign: 'center', color: '#444', padding: 20 }}>
              No processes tracked yet
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

import React from 'react';

export default function AlertFeed({ alerts }) {
  const recent = [...alerts].reverse().slice(0, 50);

  return (
    <div className="scroll">
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Severity</th>
            <th>Rule</th>
            <th>Process</th>
            <th>Description</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {recent.map((a, i) => (
            <tr key={a.id || i}>
              <td style={{ color: '#666', fontSize: 11 }}>
                {new Date(a.timestamp || a.received_at).toLocaleTimeString()}
              </td>
              <td className={`severity-${a.severity}`}>{a.severity}</td>
              <td style={{ color: '#888' }}>{a.rule}</td>
              <td>{a.comm || `pid:${a.pid}`}</td>
              <td style={{ fontSize: 11 }}>{a.description}</td>
              <td><span className={`action-${a.action}`}>{a.action}</span></td>
            </tr>
          ))}
          {recent.length === 0 && (
            <tr><td colSpan={6} style={{ textAlign: 'center', color: '#444', padding: 20 }}>
              No alerts yet — system in learning mode
            </td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

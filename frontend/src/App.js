import React, { useEffect, useState, useRef } from 'react';
import './App.css';
import AlertTimeline from './AlertTimeline';
import ProcessTable from './ProcessTable';
import AlertFeed from './AlertFeed';
import StatsPanel from './StatsPanel';

const API = process.env.REACT_APP_API || 'http://localhost:9091';

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({});
  const [processes, setProcesses] = useState([]);
  const [config, setConfig] = useState({});
  const [connected, setConnected] = useState(false);
  const sseRef = useRef(null);

  // Initial data load
  useEffect(() => {
    fetch(`${API}/api/v1/alerts?limit=200`).then(r => r.json()).then(setAlerts);
    fetch(`${API}/api/v1/stats`).then(r => r.json()).then(setStats);
    fetch(`${API}/api/v1/processes?limit=100`).then(r => r.json()).then(setProcesses);
    fetch(`${API}/api/v1/config`).then(r => r.json()).then(setConfig);
  }, []);

  // SSE connection
  useEffect(() => {
    const evtSource = new EventSource(`${API}/api/v1/alerts/stream`);
    sseRef.current = evtSource;

    evtSource.onopen = () => setConnected(true);
    evtSource.onerror = () => setConnected(false);

    evtSource.addEventListener('alert', (e) => {
      const alert = JSON.parse(e.data);
      setAlerts(prev => [...prev.slice(-299), alert]);
      setStats(prev => ({
        ...prev,
        alerts: { ...prev.alerts, total: (prev.alerts?.total || 0) + 1 }
      }));
    });

    return () => evtSource.close();
  }, []);

  // Periodic refresh
  useEffect(() => {
    const interval = setInterval(() => {
      fetch(`${API}/api/v1/stats`).then(r => r.json()).then(setStats);
      fetch(`${API}/api/v1/processes?limit=100`).then(r => r.json()).then(setProcesses);
    }, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app">
      <header>
        <h1>BEACONGUARD</h1>
        <span className={`status ${connected ? 'connected' : 'disconnected'}`}>
          {connected ? 'LIVE' : 'OFFLINE'}
        </span>
        <span className="subtitle">Behavioral Kernel Guard</span>
      </header>

      <StatsPanel stats={stats} config={config} />

      <div className="grid">
        <div className="card wide">
          <h2>Alert Timeline</h2>
          <AlertTimeline alerts={alerts} />
        </div>
        <div className="card">
          <h2>Top Processes</h2>
          <ProcessTable processes={processes} />
        </div>
      </div>

      <div className="card">
        <h2>Real-Time Alerts <span className="badge">{alerts.length}</span></h2>
        <AlertFeed alerts={alerts} />
      </div>
    </div>
  );
}

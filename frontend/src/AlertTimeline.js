import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, Area, AreaChart } from 'recharts';

function buildTimeline(alerts) {
  const buckets = {};
  const now = Date.now() / 1000;
  const windowSec = 600; // 10 min

  for (const a of alerts) {
    const ts = new Date(a.timestamp || a.received_at).getTime() / 1000;
    if (now - ts > windowSec) continue;
    const minute = Math.floor(ts / 60);
    buckets[minute] = (buckets[minute] || 0) + 1;
  }

  const data = [];
  const start = Math.floor((now - windowSec) / 60);
  const end = Math.floor(now / 60);
  for (let m = start; m <= end; m++) {
    data.push({
      time: new Date(m * 60 * 1000).toLocaleTimeString(),
      alerts: buckets[m] || 0,
    });
  }
  return data;
}

export default function AlertTimeline({ alerts }) {
  const data = buildTimeline(alerts);

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data}>
        <defs>
          <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#00ff88" stopOpacity={0.3} />
            <stop offset="100%" stopColor="#00ff88" stopOpacity={0} />
          </linearGradient>
        </defs>
        <XAxis dataKey="time" tick={{ fill: '#666', fontSize: 10 }} />
        <YAxis tick={{ fill: '#666', fontSize: 10 }} allowDecimals={false} />
        <Tooltip
          contentStyle={{ background: '#0d0d1a', border: '1px solid #1a1a2e', borderRadius: 4 }}
          itemStyle={{ color: '#00ff88' }}
        />
        <Area type="monotone" dataKey="alerts" stroke="#00ff88" fill="url(#alertGrad)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

'use client';

import { useState } from 'react';

export default function Home() {
    const [ip, setIp] = useState('');
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [hasSearched, setHasSearched] = useState(false);

    const handleSearch = async (e) => {
        e.preventDefault();
        if (!ip) return;

        setLoading(true);
        setError('');
        setData(null);
        setHasSearched(true);

        try {
            const res = await fetch(`/api/check-ip?ip=${ip}`);
            const result = await res.json();

            if (!res.ok) {
                throw new Error(result.error || 'Failed to fetch data');
            }

            setData(result);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <main className="container">
            <div style={{ textAlign: 'center', marginBottom: '3rem', marginTop: '3rem' }}>
                <h1 style={{ fontSize: '2.5rem', marginBottom: '0.5rem', background: 'linear-gradient(to right, #60a5fa, #a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                    IP Intelligence
                </h1>
                <p style={{ color: '#94a3b8' }}>Analyze IP reputation with AbuseIPDB & VirusTotal</p>
            </div>

            <form onSubmit={handleSearch} className="input-group">
                <input
                    type="text"
                    placeholder="Enter IP Address (e.g. 8.8.8.8)"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    disabled={loading}
                />
                <button type="submit" disabled={loading} style={{ minWidth: '120px' }}>
                    {loading ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span className="loader"></span>
                            <span>Processing...</span>
                        </div>
                    ) : 'Analyze'}
                </button>
            </form>

            {/* Loading Indicator for whole section if needed, though button loader is usually enough. 
          Let's add a subtle text below if it takes long? No, stick to button loader for now as it's standard. */}

            {error && (
                <div className="card" style={{ borderColor: 'var(--error)', color: '#fca5a5' }}>
                    <strong>Error:</strong> {error}
                </div>
            )}

            {!loading && hasSearched && !error && !data && (
                <div className="card" style={{ textAlign: 'center', color: '#94a3b8' }}>
                    No results found.
                </div>
            )}

            {data && (
                <div className="results-container">
                    {/* Summary Section */}
                    <div className="card">
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                            <h2 style={{ margin: 0 }}>Report for {data.ip}</h2>
                        </div>

                        <div className="grid">
                            {data.abuseIpDb?.data ? (
                                <div>
                                    <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Abuse Confidence</span>
                                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: data.abuseIpDb.data.abuseConfidenceScore > 50 ? '#ef4444' : '#22c55e' }}>
                                        {data.abuseIpDb.data.abuseConfidenceScore}%
                                    </div>
                                </div>
                            ) : (
                                <div>
                                    <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>AbuseIPDB</span>
                                    <div style={{ color: '#64748b' }}>No data available</div>
                                </div>
                            )}

                            {data.virusTotal?.data?.attributes ? (
                                <div>
                                    <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Malicious Votes</span>
                                    <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: data.virusTotal.data.attributes.last_analysis_stats.malicious > 0 ? '#ef4444' : '#22c55e' }}>
                                        {data.virusTotal.data.attributes.last_analysis_stats.malicious} / {Object.keys(data.virusTotal.data.attributes.last_analysis_results).length}
                                    </div>
                                </div>
                            ) : (
                                <div>
                                    <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>VirusTotal</span>
                                    <div style={{ color: '#64748b' }}>No data available</div>
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Details Grid */}
                    <div className="grid">
                        {/* AbuseIPDB Details */}
                        {data.abuseIpDb?.data && (
                            <div className="card">
                                <h3>AbuseIPDB</h3>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                    <DetailRow label="ISP" value={data.abuseIpDb.data.isp} />
                                    <DetailRow label="Country" value={data.abuseIpDb.data.countryCode} />
                                    <DetailRow label="Usage Type" value={data.abuseIpDb.data.usageType} />
                                    <DetailRow label="Domain" value={data.abuseIpDb.data.domain} />
                                    <DetailRow label="Reports" value={data.abuseIpDb.data.totalReports} />
                                    <DetailRow label="Last Reported" value={data.abuseIpDb.data.lastReportedAt} />
                                </div>
                            </div>
                        )}

                        {/* VirusTotal Details */}
                        {data.virusTotal?.data?.attributes && (
                            <div className="card">
                                <h3>VirusTotal</h3>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                                    <DetailRow label="Network" value={data.virusTotal.data.attributes.network} />
                                    <DetailRow label="AS Owner" value={data.virusTotal.data.attributes.as_owner} />
                                    <DetailRow label="Reputation" value={data.virusTotal.data.attributes.reputation} />

                                    <div style={{ marginTop: '1rem' }}>
                                        <h4 style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Analysis Stats</h4>
                                        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                                            <Badge label="Malicious" value={data.virusTotal.data.attributes.last_analysis_stats.malicious} color="red" />
                                            <Badge label="Suspicious" value={data.virusTotal.data.attributes.last_analysis_stats.suspicious} color="yellow" />
                                            <Badge label="Harmless" value={data.virusTotal.data.attributes.last_analysis_stats.harmless} color="green" />
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Warnings/Errors section from API */}
                    {data.errors && data.errors.length > 0 && (
                        <div className="card" style={{ borderColor: 'orange' }}>
                            <h3 style={{ color: '#fbbf24' }}>Notices</h3>
                            <ul>
                                {data.errors.map((e, i) => <li key={i}>{e}</li>)}
                            </ul>
                        </div>
                    )}

                    {/* Fallback for completely empty data (e.g. valid IP but no records found in either) */}
                    {!data.abuseIpDb?.data && !data.virusTotal?.data?.attributes && data.errors.length === 0 && (
                        <div className="card" style={{ textAlign: 'center' }}>
                            <p>No reputation data found for this IP in the configured sources.</p>
                        </div>
                    )}
                </div>
            )}
        </main>
    );
}

function DetailRow({ label, value }) {
    if (!value) return null;
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--card-border)', paddingBottom: '0.25rem' }}>
            <span style={{ color: '#94a3b8' }}>{label}</span>
            <span style={{ textAlign: 'right', maxWidth: '60%' }}>{value}</span>
        </div>
    );
}

function Badge({ label, value, color }) {
    let styleC = {};
    if (color === 'red') styleC = { borderColor: '#ef4444', color: '#fca5a5', background: 'rgba(239,68,68,0.1)' };
    if (color === 'green') styleC = { borderColor: '#22c55e', color: '#86efac', background: 'rgba(34,197,94,0.1)' };
    if (color === 'yellow') styleC = { borderColor: '#eab308', color: '#fde047', background: 'rgba(234,179,8,0.1)' };

    return (
        <div style={{
            border: '1px solid',
            borderRadius: '4px',
            padding: '2px 6px',
            fontSize: '0.75rem',
            ...styleC
        }}>
            {label}: {value}
        </div>
    );
}

'use client';

import { useState } from 'react';

export default function Home() {
    const [ip, setIp] = useState('');
    const [file, setFile] = useState(null);
    const [mode, setMode] = useState('single'); // 'single' | 'bulk'
    const [data, setData] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [hasSearched, setHasSearched] = useState(false);

    const handleSearch = async (e) => {
        e.preventDefault();

        if (mode === 'single' && !ip) return;
        if (mode === 'bulk' && !file) return;

        setLoading(true);
        setError('');
        setData(null);
        setHasSearched(true);

        try {
            if (mode === 'single') {
                const res = await fetch(`/api/check-ip?ip=${ip}`);
                const result = await res.json();

                if (!res.ok) {
                    throw new Error(result.error || 'Failed to fetch data');
                }
                setData([result]); // Unify as array for display logic
            } else {
                // Bulk mode
                const text = await file.text();

                // Parse lines, skip headers, and extract IPs

                let lines = text.split(/[\r\n]+/).map(l => l.trim()).filter(l => l.length > 0);

                if (lines.length === 0) {
                    throw new Error('File appears to be empty');
                }

                // If the first line doesn't look like an IP (e.g. "IP Address"), skip it
                // Simple check: does it check start with a digit?
                if (!/^\d/.test(lines[0])) {
                    lines = lines.slice(1);
                }

                // Now extract anything that looks like an IP from the remaining lines
                // This handles "1.1.1.1, 2.2.2.2" on one line or purely one per line
                const allContent = lines.join('\n');
                // Regex for basic IPv4
                const ipRegex = /(?:\d{1,3}\.){3}\d{1,3}/g;
                const matches = allContent.match(ipRegex) || [];
                const rawIps = [...new Set(matches)]; // Deduplicate

                if (rawIps.length === 0) {
                    throw new Error('No valid IP addresses found in file');
                }

                // Limit batch size if needed, for now send all
                const res = await fetch('/api/check-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ips: rawIps })
                });

                const result = await res.json();
                if (!res.ok) {
                    throw new Error(result.error || 'Failed to process batch');
                }
                setData(result);
            }
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const downloadCsv = () => {
        if (!data || data.length === 0) return;

        const headers = [
            'IP Address', 'Abuse Confidence', 'Abuse Reports', 'VirusTotal Malicious',
            'Country', 'Region', 'City', 'ISP', 'ASN', 'ASN Owner'
        ];

        const csvRows = [headers.join(',')];

        data.forEach(item => {
            // Helper to escape commas in values
            const escape = (val) => {
                if (!val) return '';
                const str = String(val);
                if (str.includes(',') || str.includes('"') || str.includes('\n')) {
                    return `"${str.replace(/"/g, '""')}"`;
                }
                return str;
            };

            // Parse ASN/Owner
            let asn = '';
            let owner = '';
            if (item.ipApi?.as) {
                const parts = item.ipApi.as.split(' ');
                if (parts.length > 1 && parts[0].startsWith('AS')) {
                    asn = parts[0];
                    owner = parts.slice(1).join(' ');
                } else {
                    asn = item.ipApi.as;
                    owner = item.ipApi.org;
                }
            } else {
                asn = item.virusTotal?.data?.attributes?.asn ? `AS${item.virusTotal.data.attributes.asn}` : '';
                owner = item.virusTotal?.data?.attributes?.as_owner || '';
            }

            const row = [
                item.ip,
                item.abuseIpDb?.data?.abuseConfidenceScore || 0,
                item.abuseIpDb?.data?.totalReports || 0,
                item.virusTotal?.data?.attributes?.last_analysis_stats?.malicious || 0,
                escape(item.ipApi?.country || item.abuseIpDb?.data?.countryCode),
                escape(item.ipApi?.regionName),
                escape(item.ipApi?.city),
                escape(item.ipApi?.isp || item.abuseIpDb?.data?.isp),
                escape(asn),
                escape(owner)
            ];
            csvRows.push(row.join(','));
        });

        const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `ip-analysis-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        window.URL.revokeObjectURL(url);
    };

    return (
        <main className="container">
            <div style={{ textAlign: 'center', marginBottom: '2rem', marginTop: '3rem' }}>
                <h1 style={{ fontSize: '2.5rem', marginBottom: '0.5rem', background: 'linear-gradient(to right, #60a5fa, #a78bfa)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                    IP Intelligence
                </h1>
                <p style={{ color: '#94a3b8' }}>Analyze IP reputation with AbuseIPDB & VirusTotal</p>
            </div>

            <div style={{ maxWidth: '600px', margin: '0 auto 2rem auto', textAlign: 'center' }}>
                <div style={{
                    display: 'inline-flex',
                    background: 'var(--card-bg)',
                    padding: '4px',
                    borderRadius: '8px',
                    border: '1px solid var(--card-border)',
                    marginBottom: '1.5rem'
                }}>
                    <button
                        onClick={() => setMode('single')}
                        style={{
                            background: mode === 'single' ? 'var(--foreground)' : 'transparent',
                            color: mode === 'single' ? 'var(--background)' : 'var(--foreground)',
                            border: 'none',
                            padding: '6px 16px',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontWeight: mode === 'single' ? '600' : '400',
                            transition: 'all 0.2s'
                        }}
                    >
                        Single IP
                    </button>
                    <button
                        onClick={() => setMode('bulk')}
                        style={{
                            background: mode === 'bulk' ? 'var(--foreground)' : 'transparent',
                            color: mode === 'bulk' ? 'var(--background)' : 'var(--foreground)',
                            border: 'none',
                            padding: '6px 16px',
                            borderRadius: '6px',
                            cursor: 'pointer',
                            fontWeight: mode === 'bulk' ? '600' : '400',
                            transition: 'all 0.2s'
                        }}
                    >
                        Bulk Upload
                    </button>
                </div>

                <form onSubmit={handleSearch} className="input-group" style={{ flexDirection: mode === 'bulk' ? 'column' : 'row', gap: '1rem' }}>
                    {mode === 'single' ? (
                        <input
                            type="text"
                            placeholder="Enter IP Address (e.g. 8.8.8.8)"
                            value={ip}
                            onChange={(e) => setIp(e.target.value)}
                            disabled={loading}
                            style={{ flex: 1 }}
                        />
                    ) : (
                        <div style={{
                            flex: 1,
                            border: '2px dashed var(--card-border)',
                            padding: '2rem',
                            borderRadius: '8px',
                            cursor: 'pointer',
                            position: 'relative',
                            background: 'var(--card-bg)',
                            width: '100%'
                        }}>
                            <input
                                type="file"
                                accept=".csv,.txt"
                                onChange={(e) => setFile(e.target.files[0])}
                                disabled={loading}
                                style={{
                                    position: 'absolute',
                                    top: 0, left: 0, width: '100%', height: '100%',
                                    opacity: 0, cursor: 'pointer'
                                }}
                            />
                            <div style={{ pointerEvents: 'none' }}>
                                {file ? (
                                    <div style={{ color: '#22c55e', fontWeight: 'bold' }}>{file.name}</div>
                                ) : (
                                    <div style={{ color: '#94a3b8' }}>
                                        Drag & drop a CSV/TXT file here or click to upload<br />
                                        <span style={{ fontSize: '0.8rem' }}>(One IP per line or comma separated)</span>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}

                    <button type="submit" disabled={loading} style={{ minWidth: '120px', width: mode === 'bulk' ? '100%' : 'auto' }}>
                        {loading ? (
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem' }}>
                                <span className="loader"></span>
                                <span>Processing...</span>
                            </div>
                        ) : 'Analyze'}
                    </button>
                </form>
            </div>

            {error && (
                <div className="card" style={{ borderColor: 'var(--error)', color: '#fca5a5', marginBottom: '1rem' }}>
                    <strong>Error:</strong> {error}
                </div>
            )}

            {!loading && hasSearched && !error && (!data || data.length === 0) && (
                <div className="card" style={{ textAlign: 'center', color: '#94a3b8' }}>
                    No results found.
                </div>
            )}

            {data && data.length > 0 && (
                <div className="results-container" style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
                    <div style={{ textAlign: 'right' }}>
                        <button
                            onClick={downloadCsv}
                            style={{
                                background: '#22c55e',
                                color: 'white',
                                border: 'none',
                                padding: '8px 16px',
                                borderRadius: '6px',
                                cursor: 'pointer',
                                fontWeight: '600'
                            }}
                        >
                            Export CSV
                        </button>
                    </div>

                    {data.map((item, index) => (
                        <ReportCard key={index} data={item} />
                    ))}
                </div>
            )}
        </main>
    );
}

function ReportCard({ data }) {
    return (
        <div style={{ border: '1px solid var(--card-border)', borderRadius: '8px', overflow: 'hidden' }}>
            {/* Header */}
            <div style={{
                background: 'rgba(30, 41, 59, 0.5)',
                padding: '1rem',
                borderBottom: '1px solid var(--card-border)',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center'
            }}>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '1rem' }}>
                    <h2 style={{ margin: 0, fontSize: '1.25rem' }}>{data.ip}</h2>
                    {data.ipApi?.countryCode && (
                        <span style={{ fontSize: '1rem' }} title={data.ipApi.country}>{getFlagEmoji(data.ipApi.countryCode)}</span>
                    )}
                </div>
                <div style={{ display: 'flex', gap: '1rem' }}>
                    {/* Mini badges for quick status */}
                    {data.abuseIpDb?.data?.abuseConfidenceScore > 0 && (
                        <span style={{ color: data.abuseIpDb.data.abuseConfidenceScore > 50 ? '#ef4444' : '#fbbf24', fontSize: '0.8rem' }}>
                            Abuse Score: {data.abuseIpDb.data.abuseConfidenceScore}%
                        </span>
                    )}
                    {data.virusTotal?.data?.attributes?.last_analysis_stats?.malicious > 0 && (
                        <span style={{ color: '#ef4444', fontSize: '0.8rem' }}>
                            VT: {data.virusTotal.data.attributes.last_analysis_stats.malicious} Malicious
                        </span>
                    )}
                </div>
            </div>

            <div style={{ padding: '1.5rem' }}>
                <div className="grid">
                    {/* Summary Boxes */}
                    <div className="card">
                        {data.abuseIpDb?.data ? (
                            <div>
                                <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Abuse Confidence</span>
                                <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: data.abuseIpDb.data.abuseConfidenceScore > 50 ? '#ef4444' : '#22c55e' }}>
                                    {data.abuseIpDb.data.abuseConfidenceScore}%
                                </div>
                                <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginTop: '0.25rem' }}>
                                    {data.abuseIpDb.data.totalReports} Reports
                                </div>
                            </div>
                        ) : (
                            <div>
                                <span style={{ color: '#94a3b8', fontSize: '0.875rem' }}>AbuseIPDB</span>
                                <div style={{ color: '#64748b' }}>No data</div>
                            </div>
                        )}
                    </div>
                    <div className="card">
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
                                <div style={{ color: '#64748b' }}>No data</div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Detailed Info Section */}
                <div className="card" style={{ marginTop: '1.5rem' }}>
                    <h3 style={{ fontSize: '1rem', color: '#94a3b8', marginBottom: '1rem' }}>IP Details</h3>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1rem 2rem' }}>
                        <DetailRow label="Country" value={data.ipApi ? `${data.ipApi.country} (${data.ipApi.countryCode})` : data.abuseIpDb?.data?.countryCode} />
                        <DetailRow label="Region" value={data.ipApi?.regionName} />
                        <DetailRow label="City" value={data.ipApi?.city} />
                        <DetailRow label="ISP" value={data.ipApi?.isp || data.abuseIpDb?.data?.isp} />

                        {/* Logic to split AS string (e.g. "AS35819 Etihad Etisalat") */}
                        {(() => {
                            let asn = null;
                            let owner = null;

                            if (data.ipApi?.as) {
                                const parts = data.ipApi.as.split(' ');
                                if (parts.length > 1 && parts[0].startsWith('AS')) {
                                    asn = parts[0];
                                    owner = parts.slice(1).join(' ');
                                } else {
                                    // Fallback if formatting is unexpected or just a number
                                    asn = data.ipApi.as;
                                    owner = data.ipApi.org; // Use org as owner if split fails
                                }
                            } else {
                                // Fallback to other sources
                                asn = data.virusTotal?.data?.attributes?.asn ? `AS${data.virusTotal.data.attributes.asn}` : null;
                                // owner might be in as_owner
                                owner = data.virusTotal?.data?.attributes?.as_owner;
                            }

                            return (
                                <>
                                    <DetailRow label="ASN" value={asn} />
                                    <DetailRow label="ASN Owner" value={owner} />
                                </>
                            );
                        })()}

                        <DetailRow label="Abuse Reports" value={data.abuseIpDb?.data?.totalReports} />
                    </div>
                </div>

                {data.errors && data.errors.length > 0 && (
                    <div className="card" style={{ borderColor: 'orange', marginTop: '1rem' }}>
                        <h3 style={{ color: '#fbbf24', fontSize: '1rem', margin: '0 0 0.5rem 0' }}>Notices</h3>
                        <ul style={{ margin: 0, paddingLeft: '1.5rem' }}>
                            {data.errors.map((e, i) => <li key={i}>{e}</li>)}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
}

// Helper for flag emoji
function getFlagEmoji(countryCode) {
    if (!countryCode) return '';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...codePoints);
}

function DetailRow({ label, value }) {
    if (!value) return null;
    return (
        <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--card-border)', paddingBottom: '0.25rem' }}>
            <span style={{ color: '#94a3b8' }}>{label}</span>
            <span style={{ textAlign: 'right', maxWidth: '60%', overflowWrap: 'break-word' }}>{value}</span>
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

import { NextResponse } from 'next/server';

const abuseIpDbApiKey = process.env.ABUSEIPDB_API_KEY;
const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;

// Helper function to check a single IP
async function checkIp(ip) {
    const results = {
        ip,
        abuseIpDb: null,
        virusTotal: null,
        ipApi: null,
        errors: [],
    };

    // Basic IP validation
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
        results.errors.push('Invalid IP address format');
        return results;
    }

    if (!abuseIpDbApiKey || !virusTotalApiKey) {
        // Proceeding without keys will result in limited/no data from those specific sources
    }

    // IP-API.com (Free tier: 45 req/min, HTTP only usually)
    try {
        const ipApiRes = await fetch(`http://ip-api.com/json/${ip}`);
        if (ipApiRes.ok) {
            results.ipApi = await ipApiRes.json();
        } else {
            // Non-critical, just log or ignore
            results.errors.push(`IP-API Error: ${ipApiRes.status}`);
        }
    } catch (error) {
        results.errors.push(`IP-API Exception: ${error.message}`);
    }

    try {
        if (abuseIpDbApiKey) {
            const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
                headers: {
                    'Key': abuseIpDbApiKey,
                    'Accept': 'application/json',
                },
            });
            if (abuseRes.ok) {
                results.abuseIpDb = await abuseRes.json();
            } else {
                results.errors.push(`AbuseIPDB Error: ${abuseRes.status}`);
            }
        }
    } catch (error) {
        results.errors.push(`AbuseIPDB Exception: ${error.message}`);
    }

    try {
        if (virusTotalApiKey) {
            const vtRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
                headers: {
                    'x-apikey': virusTotalApiKey,
                },
            });
            if (vtRes.ok) {
                results.virusTotal = await vtRes.json();
            } else {
                results.errors.push(`VirusTotal Error: ${vtRes.status}`);
            }
        }
    } catch (error) {
        results.errors.push(`VirusTotal Exception: ${error.message}`);
    }

    return results;
}

export async function GET(request) {
    const { searchParams } = new URL(request.url);
    const ip = searchParams.get('ip');

    if (!ip) {
        return NextResponse.json({ error: 'IP address is required' }, { status: 400 });
    }

    const result = await checkIp(ip);
    return NextResponse.json(result);
}

export async function POST(request) {
    try {
        const body = await request.json();
        const { ips } = body;

        if (!ips || !Array.isArray(ips) || ips.length === 0) {
            return NextResponse.json({ error: 'List of IPs is required' }, { status: 400 });
        }

        // Process IPs in parallel
        // Note: Real-world large batches might need rate limiting/queuing.
        const promises = ips.map(ip => checkIp(ip));
        const results = await Promise.all(promises);

        return NextResponse.json(results);
    } catch (error) {
        return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
    }
}

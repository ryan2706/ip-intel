import { NextResponse } from 'next/server';

export async function GET(request) {
    const { searchParams } = new URL(request.url);
    const ip = searchParams.get('ip');

    if (!ip) {
        return NextResponse.json({ error: 'IP address is required' }, { status: 400 });
    }

    // Basic IP validation
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (!ipRegex.test(ip)) {
        return NextResponse.json({ error: 'Invalid IP address format' }, { status: 400 });
    }

    const abuseIpDbApiKey = process.env.ABUSEIPDB_API_KEY;
    const virusTotalApiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!abuseIpDbApiKey || !virusTotalApiKey) {
        console.warn('Missing API Keys');
        // Proceeding but warning - for dev check. 
        // In prod we might want to error, but for now we try what we can.
    }

    const results = {
        ip,
        abuseIpDb: null,
        virusTotal: null,
        errors: [],
    };

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

    return NextResponse.json(results);
}

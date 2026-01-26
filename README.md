# IP Intelligence App

A simple, powerful web application to check if an IP address is malicious and gather detailed location/network data. It uses [AbuseIPDB](https://www.abuseipdb.com/), [VirusTotal](https://www.virustotal.com/), and [IP-API](https://ip-api.com/).

## Features
- **Single IP Analysis**: Check reputation, location, and ISP details for any IP.
- **Bulk Upload**: Upload a `.csv` or `.txt` file to analyze multiple IPs at once (headers are automatically ignored).
- **Granular Details**: View Country, Region, City, ISP, ASN, and ASN Owner.
- **CSV Export**: Download your full analysis report for offline use.

## Prerequisites

Before you start, you need to have **Docker** installed. Docker allows you to run this application without installing Node.js or other dependencies on your computer.

- [Download Docker Desktop](https://docs.docker.com/get-docker/) (available for Mac, Windows, and Linux)

## Getting Started in 3 Steps

### 1. Get Your API Keys
To get real data, you need free API keys from the services we use.
- **AbuseIPDB**: [Sign up here](https://www.abuseipdb.com/register) and go to the API tab to generate a key.
- **VirusTotal**: [Sign up here](https://www.virustotal.com/gui/join-us), click your profile icon -> API Key.
- *(IP-API.com does not require a key for basic usage)*

### 2. Configure the App
1. Make a copy of `.env.example` and name it `.env.local`:
   ```bash
   cp .env.example .env.local
   ```
2. Open `.env.local` and paste your API keys after the equals signs:
   ```env
   ABUSEIPDB_API_KEY=your_long_key_here
   VIRUSTOTAL_API_KEY=your_long_key_here
   ```

### 3. Run the App
Open your terminal, navigate to this folder, and run:

```bash
docker-compose up --build
```

Wait a few minutes for it to build. Once you see "Listening on port 3000", you are good to go!

---

## How to Use

### Single IP Mode
1. Go to [http://localhost:3000](http://localhost:3000).
2. Ensure **"Single IP"** is selected.
3. Enter an IP (e.g., `8.8.8.8`) and click **Analyze**.

### Bulk Upload Mode
1. Click **"Bulk Upload"**.
2. Select a `.csv` or `.txt` file containing IPs (one per line or comma-separated).
   - *Note: The app automatically detects and skips header rows.*
3. Click **Analyze** to process the list.

### Exporting Results
After analyzing (in either mode), click the green **"Export CSV"** button to download a spreadsheet containing all gathered checks, scores, and location data.

## Troubleshooting

**"No results found"**
- Check if your API keys are correct in `.env.local`.
- Restart the app if you changed the keys.

**"Command not found: docker"**
- Make sure Docker Desktop is downloaded and **currently running**.

**"Address already in use"**
- You might have another app running on port 3000.

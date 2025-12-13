# IP Intelligence App

A simple, powerful web application to check if an IP address is malicious. It uses [AbuseIPDB](https://www.abuseipdb.com/) and [VirusTotal](https://www.virustotal.com/) to gather reputation data.

## Prerequisites

Before you start, you need to have **Docker** installed. Docker allows you to run this application without installing Node.js or other dependencies on your computer.

- [Download Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)

## Getting Started in 3 Steps

### 1. Get Your API Keys
To get real data, you need free API keys from the services we use.
- **AbuseIPDB**: [Sign up here](https://www.abuseipdb.com/register) and go to the API tab to generate a key.
- **VirusTotal**: [Sign up here](https://www.virustotal.com/gui/join-us), click your profile icon -> API Key.

### 2. Configure the App
1. Open the file named `.env.local` in this folder.
2. Paste your API keys after the equals signs:
   ```env
   ABUSEIPDB_API_KEY=your_long_key_here
   VIRUSTOTAL_API_KEY=your_long_key_here
   ```
   *(Make sure there are no spaces around the `=` sign).*

### 3. Run the App
Open your terminal (Command+Space, type "Terminal"), navigate to this folder, and run:

```bash
docker-compose up --build
```

Wait a few minutes for it to build. Once you see a message saying "Ready in ... ms" or "Listening on port 3000", you are good to go!

---

## How to Use
1. Open your web browser (Chrome, Safari, etc.).
2. Go to: [http://localhost:3000](http://localhost:3000)
3. Enter an IP address (e.g., `8.8.8.8` or `1.1.1.1`) and click **Analyze**.
4. Read the report!

## Troubleshooting

**"No results found"**
- Check if your API keys are correct in `.env.local`.
- Restart the app if you changed the keys (press `Ctrl+C` in the terminal to stop, then run the command again).

**"Command not found: docker"**
- Make sure Docker Desktop is downloaded and **currently running** (look for the whale icon in your menu bar).

**"Address already in use"**
- You might have another app running on port 3000. You can change the port in `docker-compose.yml` if needed.

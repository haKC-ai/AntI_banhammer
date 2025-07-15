# AntI Banhammer: Bypass techniques


**Service Status:**

![ChatGPT: Online](https://img.shields.io/badge/ChatGPT-Online-brightgreen?logo=openai)![Gemini: Online](https://img.shields.io/badge/Gemini-Online-blue?logo=google)![Claude: Online](https://img.shields.io/badge/Claude-Online-purple?logo=anthropic)![Mistral: Online](https://img.shields.io/badge/Mistral-Online-yellow?logo=mistralai)![Hugging Face: Online](https://img.shields.io/badge/Hugging%20Face-Online-yellowgreen?logo=huggingface)

---

**Goal:** Understand, replicate, and block how users or adversaries may bypass chatbot (LLM) blocks in corporate environments with runnable, copy-paste examples.

---

## Table of Contents

1.  Background
2.  Blocked Domains & API Keys
3.  Bypass Techniques
    1.  Remote Desktop and Screen Sharing
    2.  VPNs and Tunnels
    3.  Browser Extensions
    4.  API Wrappers
    5.  Self-hosted Chatbot Frontends
    6.  Cloud Function Proxies
    7.  IDE Plugins
    8.  SOCKS/SSH Tunneling
    9.  Local LLMs
4.  Why These Still Work
5.  Defensive Countermeasures
6.  Detection Techniques
7.  Resources

---

### Background

Even after firewalls block access to primary Large Language Model (LLM) domains like ChatGPT, Claude, and Gemini, adversaries and employees often continue accessing chatbot capabilities. This playbook documents how that happens, provides technical walkthroughs with runnable code, and offers detection and prevention strategies for blue teams. The goal is to move beyond simple domain blocking to a more resilient, behavior-based defense.

---

### Blocked Domains & API Keys

A foundational step is to block known domains. API access is the primary vector for programmatic bypasses. Below are the key domains and links to obtain API keys for testing.

| Provider | Primary Domain(s) to Block | API Endpoint(s) to Block | Get API Key |
| :--- | :--- | :--- | :--- |
| **OpenAI (ChatGPT)** | `chat.openai.com` | `api.openai.com` | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| **Google (Gemini)** | `gemini.google.com` | `generativelanguage.googleapis.com` | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) |
| **Anthropic (Claude)** | `claude.ai` | `api.anthropic.com` | [console.anthropic.com](https://console.anthropic.com) |
| **Mistral AI** | `chat.mistral.ai` | `api.mistral.ai` | [console.mistral.ai/api-keys](https://console.mistral.ai/api-keys/) |
| **Perplexity AI** | `perplexity.ai` | `api.perplexity.ai` | [perplexity.ai/settings/api](https://www.perplexity.ai/settings/api) |
| **Cohere** | `cohere.com` | `api.cohere.ai`, `api.cohere.com` | [dashboard.cohere.com/api-keys](https://dashboard.cohere.com/api-keys) |
| **Hugging Face** | `huggingface.co` | `api-inference.huggingface.co` | [huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) |
| **GitHub (Copilot)** | `copilot.github.com` | `copilot-proxy.githubusercontent.com` | Subscription-based, via GitHub account |
| **Poe (by Quora)** | `poe.com` | `api.quora.com` | [developer.poe.com](https://developer.poe.com) |

---

### Bypass Techniques

#### 1. Remote Desktop and Screen Sharing

**Tools:** Microsoft Remote Desktop (RDP), VNC, TeamViewer, AnyDesk, Chrome Remote Desktop.

A user connects from their restricted machine to another, less-restricted machine on the local network, effectively inheriting its network access.

**Proof of Concept (PoC) Code:**

On a Windows machine, use the built-in Remote Desktop client to connect to an internal server that has unfiltered internet access.

```powershell
# Initiate an RDP session to another machine on the local network (e.g., 192.168.1.100)
mstsc /v:192.168.1.100
```

**How it Works:** The corporate firewall sees only internal RDP traffic (port 3389) between two trusted machines. The user, now operating from the remote machine, can freely access blocked external sites.

#### 2. VPNs and Tunnels

**Tools:** Tailscale, Cloudflare WARP, ngrok, Mullvad, frp, Serveo, sshuttle.

These tools create encrypted tunnels to external networks, making the user's traffic appear to originate from the tunnel endpoint.

**Proof of Concept (PoC) Code:**

Use `sshuttle` to create a "VPN over SSH" to a remote server you have access to, routing all traffic through it.

```bash
# Prerequisites: SSH access to an external server (user@remote.server)
# Install sshuttle: pip install sshuttle
# This command routes all traffic from your machine through the remote server.
sshuttle --dns -r user@remote.server 0/0
```

**How it Works:** `sshuttle` forwards all TCP traffic and DNS requests through an SSH session. To the firewall, this looks like a single, encrypted SSH connection.

#### 3. Browser Extensions

**Examples:** WebChatGPT, Merlin, Superpower ChatGPT, ChatHub.

This runnable Node.js script simulates the backend of a browser extension proxy. It creates a local web server that listens for requests and forwards them to the OpenAI API. This demonstrates how extensions hide the final destination from firewalls.

**Proof of Concept (PoC) Code:**

**Step 1: Save the code as `proxy_server.js`**

```javascript
// proxy_server.js
const http = require('http');
const https = require('https');

const API_KEY = process.env.OPENAI_API_KEY; // Use environment variable for the key

const server = http.createServer((req, res) => {
    if (req.method === 'POST' && req.url === '/api/chat') {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            const options = {
                hostname: 'api.openai.com',
                port: 443,
                path: '/v1/chat/completions',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${API_KEY}`
                }
            };

            const proxyReq = https.request(options, (proxyRes) => {
                res.writeHead(proxyRes.statusCode, proxyRes.headers);
                proxyRes.pipe(res, { end: true });
            });

            proxyReq.on('error', (e) => {
                console.error(`Problem with request: ${e.message}`);
                res.writeHead(500);
                res.end(`Proxy error: ${e.message}`);
            });

            proxyReq.write(body);
            proxyReq.end();
        });
    } else {
        res.writeHead(404);
        res.end('Not Found');
    }
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Proxy server running on http://localhost:${PORT}`);
    console.log('Send POST requests to http://localhost:3000/api/chat');
});
```

**Step 2: Run the server**

```bash
# Set your API key in your terminal session
export OPENAI_API_KEY='sk-yourkeyhere'

# Run the proxy server
node proxy_server.js
```

**Step 3: Test the proxy from another terminal**

```bash
# This curl command sends a request to your local proxy, not directly to OpenAI
curl http://localhost:3000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "Explain how a proxy works."}]}'
```

**How it Works:** The firewall sees a request to `localhost:3000`. The Node.js script then makes the onward request to `api.openai.com`, effectively hiding the final destination.

#### 4. API Wrappers

**Tools:** curl, Python (`requests`), Node.js (`axios`), custom scripts.

Direct API calls are made from scripts, which can easily be configured to use a proxy, bypassing simple domain blocks.

**Proof of Concept (PoC) Code:**

This runnable Python script uses the `requests` library to call the OpenAI API through a proxy server (e.g., a SOCKS5 proxy created via SSH).

```python
import os
import requests
import json

# --- Configuration ---
# Set your API key: export OPENAI_API_KEY='sk-...'
API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# Set your proxy. This could be a SOCKS5 proxy from an SSH tunnel (see section 8)
# or any other HTTP/HTTPS proxy.
PROXY_URL = "socks5h://localhost:1080"
proxies = {
   "http": PROXY_URL,
   "https": PROXY_URL,
}

# --- API Call ---
headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
}

data = {
    "model": "gpt-4",
    "messages": [{"role": "user", "content": "Write a python script to query an API."}],
}

try:
    # The 'proxies' argument routes this request through our tunnel
    response = requests.post(OPENAI_API_URL, headers=headers, data=json.dumps(data), proxies=proxies)
    response.raise_for_status() # Raise an exception for bad status codes

    print(response.json()["choices"][0]["message"]["content"])

except requests.exceptions.RequestException as e:
    print(f"An error occurred: {e}")
```

**How it Works:** The script's traffic is routed through the specified proxy. The firewall only sees traffic going to the proxy's IP, not to `api.openai.com`.

#### 5. Self-hosted Chatbot Frontends

**Tools:** LibreChat, Open WebUI, Chatbot UI, Jan.

Users host their own web interface on a home server or VPS. The frontend is accessed from a personal domain, and its backend makes the real API calls.

**Proof of Concept (PoC) Code:**

Use Docker to deploy LibreChat. The user accesses their own server, which then calls the LLM provider.

```bash
# 1. Clone the repository
git clone https://github.com/danny-avila/LibreChat.git
cd LibreChat

# 2. Create a .env file from the example
cp .env.example .env

# 3. Edit the .env file and add your API keys (e.g., OPENAI_API_KEY)
# nano .env

# 4. Run the application with Docker
docker compose up -d
```

**How it Works:** The corporate firewall only sees HTTPS traffic from the user's workstation to their personal server (`my-chat.mydomain.com`), not to the blocked API endpoints.

#### 6. Cloud Function Proxies

**Abuse Targets:** AWS Lambda, Google Cloud Functions, Cloudflare Workers.

A serverless function acts as a simple, disposable proxy.

**Proof of Concept (PoC) Code:**

Deploy a Cloudflare Worker that forwards requests to the OpenAI API.

**Step 1: Create `src/index.js` file:**
```javascript
// src/index.js
export default {
  async fetch(request) {
    const url = new URL(request.url);
    const apiRequest = new Request("https://api.openai.com" + url.pathname, request);
    return fetch(apiRequest);
  },
};
```

**Step 2: Create `wrangler.toml` configuration file:**
```toml
# wrangler.toml
name = "llm-proxy-worker"
main = "src/index.js"
compatibility_date = "2023-10-30"
```

**Step 3: Deploy using Cloudflare's CLI:**
```bash
# Prerequisite: npm install -g wrangler && wrangler login
wrangler deploy
```

**Step 4: Use the deployed worker:**
```bash
# Replace 'your-account' with your Cloudflare account details
curl https://llm-proxy-worker.your-account.workers.dev/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

**How it Works:** The request goes to a `*.workers.dev` domain, which is trusted Cloudflare infrastructure. The worker then makes the onward request to OpenAI from a Cloudflare IP.

#### 7. IDE Plugins

**Tools:** GitHub Copilot, JetBrains AI Assistant, AWS CodeWhisperer.

The bypass is the installation and use of the plugin itself. The traffic blends with normal developer activity.

**Proof of Concept (PoC) Code:**

This is an action performed by the user, not a script to run.

```plaintext
# Action:
# 1. Open Visual Studio Code.
# 2. Go to the Extensions view (Ctrl+Shift+X).
# 3. Search for "GitHub Copilot" and install it.
# 4. Follow the authentication prompts.
# 5. Start typing code; Copilot will send requests to its proxy.

# Detection Focus:
# Monitor network traffic from 'Code.exe' (VS Code) to:
# copilot-proxy.githubusercontent.com
```

**How it Works:** IDE and GitHub domains are almost always allow-listed. The plugin's traffic is encrypted and uses these trusted channels.

#### 8. SOCKS/SSH Tunneling

**Tools:** OpenSSH, PuTTY.

An SSH client creates an encrypted tunnel to an external server, which can then proxy traffic.

**Proof of Concept (PoC) Code:**

**Step 1: Create the SOCKS5 proxy tunnel:**
This command connects to your remote server and opens a SOCKS proxy on your local machine at port 1080. The `-N` flag means do not execute a remote command.

```bash
# Prerequisite: SSH access to an external server (user@remote.server)
ssh -N -D 1080 user@remote.server
```

**Step 2: Use the proxy:**
Run a command-line tool like `curl` and instruct it to use the local SOCKS proxy to reach a blocked resource.

```bash
curl --socks5-hostname localhost:1080 https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

**How it Works:** The `curl` command sends its request to `localhost:1080`. The SSH client listening on that port encrypts the request, sends it through the tunnel to `remote.server`, which then makes the real request to `api.openai.com`.

#### 9. Local LLMs

**Tools:** Ollama, llama.cpp, GPT4All, LM Studio.

This bypasses all network controls by running the model directly on the user's hardware.

**Proof of Concept (PoC) Code:**

**Step 1: Install and run a model with Ollama:**
(Assumes Ollama is installed. See ollama.com for instructions.)

```bash
# Download and run the Mistral 7B model locally
ollama run mistral
```

**Step 2: Interact with the local Ollama API:**
Once a model is running, Ollama exposes a local API. You can interact with it using scripts.

```bash
# Send a request to the local API endpoint
curl http://localhost:11434/api/generate -d '{
  "model": "mistral",
  "prompt": "Why is the sky blue?",
  "stream": false
}'
```

**How it Works:** No external network calls are made for inference. All processing is local, making it invisible to firewalls and web proxies.

---

### Why These Still Work

| Technique | Evasion Method |
| :--- | :--- |
| **Remote Desktop** | Leverages trusted internal network paths to pivot to a machine with fewer restrictions. The traffic is east-west and may not be inspected. |
| **VPN/Tunnels** | Encapsulates traffic in an encrypted overlay network (e.g., WireGuard, QUIC, HTTPS) that bypasses domain/IP filters. |
| **Extensions** | Hides final destination by routing API calls through third-party proxy domains on common cloud platforms. |
| **API Wrappers** | Bypasses static domain blocks by using alternate domains or user-controlled API proxies. |
| **Cloud Functions** | Masks requests by using legitimate, often allow-listed, FaaS domains (e.g., `*.workers.dev`, `*.cloudfront.net`). |
| **IDE Plugins** | Blends malicious or unapproved LLM traffic with sanctioned developer activity to trusted domains like GitHub. |
| **SOCKS/SSH Tunnels** | Creates an encrypted channel for all traffic that is invisible to most firewalls unless deep packet inspection is used. |
| **Local LLMs** | Requires no network calls for inference, making it completely invisible to egress filtering and network monitoring. |

---

### Defensive Countermeasures

| Category | Control Strategy |
| :--- | :--- |
| **Network Segmentation** | Implement a Zero Trust network architecture. Restrict east-west traffic between workstations and servers. Deny all traffic by default and only allow connections that are explicitly required for business functions. |
| **DNS & Egress Filtering** | Aggressively block wildcard domains used for proxies: `*.vercel.app`, `*.workers.dev`, `*.ngrok.io`, `*.serveo.net`, `*.onrender.com`, `*.cloudfunctions.net`. Block known VPN/tunneling provider ASNs and IP ranges. |
| **Endpoint Detection (EDR)** | Monitor for command-line execution of tools like `ngrok`, `tailscale`, `ollama`, and `frp`. Create rules to detect scripting languages (Python, Node.js) making external network calls with suspicious patterns (e.g., "Authorization: Bearer sk-"). Monitor for unauthorized remote desktop access. |
| **Browser Policy** | Use browser management (e.g., Chrome Enterprise) to whitelist approved extensions. Block the installation of all other extensions to prevent proxying. |
| **Application Control** | Use an application-aware firewall or EDR to block the execution of unauthorized software, including remote desktop clients (where not required), VPN clients, tunneling tools, and local LLM installers. |
| **TLS/SSL Inspection** | Implement TLS inspection (SSL Bumping) on proxies and firewalls. This allows visibility into encrypted traffic, enabling detection of API calls to blocked services, even when routed through a proxy domain. |
| **Data Loss Prevention (DLP)** | Deploy DLP solutions to monitor and block the exfiltration of sensitive data. Create policies that detect patterns of proprietary code, customer data, or PII being pasted into web forms, IDEs, or CLI tools. |
| **Cloud Security Posture** | Audit cloud environments (AWS, GCP, Azure) for unauthorized deployments of serverless functions (Lambda, GCF) or containerized proxies that could be used to bypass internal controls. |
| **User and Entity Behavior Analytics (UEBA)** | Analyze logs for anomalous RDP activity. Look for logins at unusual hours, access from atypical subnets, or multiple failed login attempts, which could indicate misuse. |

---

### Detection Techniques

**Anomalous Remote Desktop Sessions**
- **Log Source:** Windows Event Logs (Security, TerminalServices-LocalSessionManager), Firewall Logs, Netflow.
- **What to look for:**
    - RDP connections (TCP/3389) between workstations or from workstations to servers that are not part of a standard administrative workflow.
    - Multiple failed RDP login attempts followed by a success.
    - RDP sessions initiated from non-standard source devices.

**Scripting Tools Calling Chatbots**
- **Log Source:** EDR, Sysmon, Process Creation Logs
- **What to look for:**
    - `curl`, `python`, `node`, `go` processes making network connections.
    - Command line arguments containing `api.openai.com`, `claude.ai`, or other LLM domains, or proxy flags like `--socks5-hostname`.
    - Suspicious string combinations like `requests.post` and `"Authorization: Bearer"`.

**Extension-based Proxy Traffic**
- **Log Source:** DNS Logs, Web Proxy Logs
- **What to look for:**
    - A high volume of requests to domains like `*.vercel.app`, `*.workers.dev`, `*.ngrok.io`.
    - Direct connections to IP addresses known to belong to services like Merlin or WebChatGPT.

**VPN and Tunneling Activity**
- **Log Source:** Firewall Logs, Netflow
- **What to look for:**
    - Outbound connections to known VPN provider IPs (e.g., Cloudflare WARP at `162.159.193.5`).
    - Outbound UDP traffic on unusual high ports, such as Tailscale's default of `41641`.
    - Sustained, high-bandwidth connections over SSH from non-admin devices.

**IDE Plugin Activity**
- **Log Source:** EDR, Web Proxy Logs
- **What to look for:**
    - POST requests from IDE processes (`code.exe`, `idea64.exe`, `pycharm64.exe`) to `copilot-proxy.githubusercontent.com`.
    - Anomalous data uploads from developer workstations to GitHub domains.

---

### Resources

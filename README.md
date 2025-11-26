# ⭐ Environment Enumerator & Endpoint Discovery Toolkit
High-Performance Async Recon Engine for Pentesters & Bug Hunters

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-yellow?style=flat-square" />
  <img src="https://img.shields.io/badge/Async-AIOHTTP-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/JS_Analysis-Regex%2FExec-green?style=flat-square" />
  <img src="https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square" />
</p>

## 📚 Table of Contents
* [🔍 Overview](#-overview)
* [✨ Features](#-features)
* [📦 Installation](#-installation)
* [⚙ Usage](#-usage)
* [🚩 Available Flags](#-available-flags)
* [📝 Input Format](#-input-format)
* [📤 Output Format](#-output-format)
* [📌 Example Commands](#-example-commands)
* [⚡ Performance Tips](#-performance-tips)
* [🤝 Contributions](#-contributions)
* [📜 License](#-license)

---

## 🔍 Overview
**env\_enum\_tool.py** is a powerful **asynchronous environment enumerator** designed for:

* **Penetration testers**
* **Bug bounty hunters**
* **Red team operators**
* **Secure code review analysts**

Given a list of domains/subdomains, the tool:

* Generates **environment-based subdomain permutations**
* Fuzzes **API & backend paths**
* Detects **Swagger/OpenAPI/GraphQL endpoints**
* Discovers **SPA-style (/\#/path) hidden URLs**
* Crawls **JS files & extracts hidden endpoints**
* Discovers **parameters (?token=, ?auth=, etc.)**
* Uses **concurrent async HTTP requests** for maximum speed
* Automatically saves all output to **env-enum.txt**

---

## ✨ Features

### 🏗 Environment Subdomain Enumeration
Automatically generates **50+ variants** like:

* `dev.example.com`
* `staging.example.com`
* `uat.example.com`
* `preview.api.example.com`
* `v1.example.com`, `v2.example.com`, `beta.example.com`

### 🧪 Endpoint & API Discovery
Detects:

* `/swagger`, `/api-docs`, `/swagger-ui`
* `/openapi.json`, `/openapi.yaml`
* `/api/v1/`, `/api/v2/`
* `/graphql`
* `/internal/`, `/config`, `/admin`

### 🕸 JavaScript Crawling
Extracts script tags
Searches inside JS for:
* `/api/...`
* `.json configs`
* `/v1/`, `/v2/`
* parameters (`id`, `auth`, `session`, `token`, `email`)

Supports:

| Mode | Description |
| :--- | :--- |
| **regex** | fast text-based extraction |
| **exec** | uses JS engine to compute dynamically constructed URLs |

### ⚡ Async High-Concurrency Engine
* Up to **20× faster** than synchronous recon
* Configurable concurrency (`--concurrency`)

---

## 📦 Installation
1.  **Clone the repository**

```bash
git clone https://github.com/Learn5ec/env-enum
cd env-enum
python3 -m venv here
source here/bin/activate
````

2.  **Install dependencies**

<!-- end list -->

```bash
pip3 install aiohttp py-mini-racer
```

If you don’t need JS execution:

```bash
pip3 install aiohttp
```

-----

## ⚙ Usage

**Basic run**

```bash
python3 env-enum.py input.txt
```

**Debug mode (full details)**

```bash
python3 env-enum.py input.txt --mode debug
```

**Quiet mode (no console output)**

```bash
python3 env-enum.py input.txt --mode quiet
```

**Regex-only JS parsing (default)**

```bash
python3 env-enum.py input.txt --jsmode regex
```

**Evaluate JS expressions**

```bash
python3 env-enum.py input.txt --jsmode exec
```

**Boost performance**

```bash
python3 env-enum.py input.txt --concurrency 150
```

-----

## 🚩 Available Flags

### Logging Modes

| Flag | Description |
| :--- | :--- |
| `--mode debug` | Full logs: requests, errors, discoveries |
| `--mode verbose` | Info + discoveries |
| `--mode discovery` | Default — Only discoveries |
| `--mode quiet` | Silent mode, writes only to file |

### JS Analysis Modes

| Flag | Description |
| :--- | :--- |
| `--jsmode regex` | Regex parsing |
| `--jsmode exec` | Evaluates JS (requires `py-mini-racer`) |

### Performance Flags

| Flag | Description |
| :--- | :--- |
| `--concurrency 80` | Number of async workers |

-----

## 📝 Input Format

One domain per line:

```
example.com
api.example.com
[https://portal.company.in](https://portal.company.in)
sub.domain.org
```

Protocol will be auto-normalized.

-----

## 📤 Output Format

All results are saved to:

* `env-enum.txt`

Examples:

```
[DISCOVERY] [https://dev.example.com/api/v1/login](https://dev.example.com/api/v1/login) [200] Login endpoint
[JS-ENDPOINT] /internal/config
[API-DOC] [https://app.example.com/swagger.json](https://app.example.com/swagger.json)
[PARAM] token
```

A backup file `env-enum.txt.bak` is created on each run.

-----

## 📌 Example Commands

🔎 **Run all features with full logs**

```bash
python3 env-enum.py targets.txt --mode debug --jsmode exec --concurrency 100
```

🚀 **Fast scanning, minimal logs**

```bash
python3 env-enum.py targets.txt --mode discovery --concurrency 150
```

🧩 **JS crawling only (regex)**

```bash
python3 env-enum.py targets.txt --jsmode regex
```

💀 **Fully silent (useful for automation)**

```bash
python3 env-enum.py targets.txt --mode quiet
```

-----

## ⚡ Performance Tips

  * Increase concurrency (`--concurrency 200`) only on fast networks
  * Use `--jsmode regex` for faster scans
  * For large lists, avoid debug mode
  * Use IP ranges only if needed — JS crawling takes time

-----

## 🤝 Contributions

PRs are welcome\!

You can contribute:

  * New environment patterns
  * Better regexes
  * Faster JS extraction
  * Plugin-like scanners
  * Bug fixes / optimizations

-----

## 📜 License

**MIT** — free for commercial and personal use.

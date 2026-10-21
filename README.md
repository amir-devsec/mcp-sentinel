# 🛡️ MCP-Sentinel

> Static Security Linter & Auditor for Model Context Protocol (MCP) Servers and AI Agents.

<p align="center">
  <img src="assets/demo.gif" alt="MCP-Sentinel Demo" width="750">
</p>

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Static security scanner for AI agent tools, prompt injection vectors, and hardcoded secrets.

## 🚀 Features

- **Arbitrary Code Execution:** Detects dangerous shell calls (`os.system`, `subprocess(shell=True)`, `eval/exec`).
- **SSRF Detection:** Catches suspicious loopback requests (`localhost`, `127.0.0.1`).
- **Prompt Injection Defense:** Audits tool schemas for description-based prompt overriding.
- **Secret Scanning:** Flags plaintext tokens (Anthropic, OpenAI, AWS).

## 📦 Quick Start

```bash
git clone [https://github.com/](https://github.com/)<USERNAME>/mcp-sentinel.git
cd mcp-sentinel
pip install -r requirements.txt
python3 mcp.py .
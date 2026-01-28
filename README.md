# Self-Attesting TEE

A TEE application that can explain its own attestation. Responds to "If you're TEE, show me your remote attestation" with actual evidence.

## Motivation

TEE + AI agents (Twitter bots, confer.to, etc.) claim trustworthiness but lack reflective ability - they can't explain their own attestation or help users verify it. This app demonstrates what "self-attesting" could look like.

**Core critique:** "If you're TEE, show me your remote attestation"

## What It Does

1. **TLS Oracle** (`/oracle/price`) - Fetches BTC price with TLS fingerprint bound to TDX quote
2. **Commit/Reveal Game** (`/game/commit`, `/game/guess`) - Provably fair coin flip
3. **Chat with Tools** (`/chat`, `/ui`) - LLM that can read its own code, fetch its attestation, search its source

The LLM has tools to introspect itself:
- `read_file` - read app.py, verifier.py, docker-compose.yaml, system_prompt.txt
- `get_attestation` - fetch TDX quote with parsed MRTD, RTMRs
- `search_code` - grep through source
- `list_files` - list /app directory

## Security Model

**What attestation proves:**
- Exact code (compose-hash) running in isolated hardware
- Memory encryption - host cannot read state
- Binding of outputs to quotes via report_data

**What attestation does NOT prove:**
- Code correctness (audit required)
- External API trustworthiness
- Operator won't deploy different code tomorrow

**Operator control (allowed_envs):**
- `ANTHROPIC_API_KEY` - operator chooses LLM backend
- This is disclosed honestly by the bot when asked

## Files

```
├── app.py                 # Main Flask app with tools
├── verifier.py            # Attestation parsing/verification utils
├── system_prompt.txt      # LLM system prompt (edit for iteration)
├── static/index.html      # Chat UI
├── docker-compose.yaml    # dstack deployment config (pinned digest)
├── Dockerfile
└── README.md
```

## Local Development

```bash
# Add your API key to .env
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env

# Run locally
docker compose up --build

# Visit http://localhost:8080/ui
```

## Deployment to dstack/Phala Cloud

See DEPLOY.md for step-by-step instructions.

---

## Future Ideas

### Vibe Auditor Integration

The bot acts as an **evidence-gathering clerk** for a remote "vibe auditor". Compare with:

- **dstack-verify**: CLI tool, verifies attestation programmatically
- **trust.phala.com**: Web dashboard showing attestation status

This bot is different - it's **interactive and explanatory**. A vibe auditor can ask:
- "Show me your allowed_envs"
- "Search your code for hardcoded URLs"
- "What compose-hash are you running?"
- "How do I verify this independently?"

The bot gathers evidence and explains it, rather than just showing green checkmarks.

**TODO:**
- [ ] Add tool to fetch and parse external attestations (verify other TEE apps)
- [ ] Add tool to query on-chain AppAuth contracts
- [ ] Add tool to compare compose-hash against known-good values
- [ ] Structured "audit report" generation
- [ ] Integration with rekor/sigstore for manifest verification

### Comparison with Existing Tools

| Tool | What it does | Interactive? | Explains? |
|------|-------------|--------------|-----------|
| dstack-verify | CLI verification | No | No |
| trust.phala.com | Dashboard with checkmarks | No | Minimal |
| **This bot** | Chat-based evidence gathering | Yes | Yes |

The insight: verification tools show "pass/fail" but don't help users understand *what* they're trusting or *how* to verify independently.

# Session Notes - 2026-01-28

## What We Built

### Core App
- Flask app with TLS oracle, commit/reveal game, self-attestation endpoints
- Chat UI at `/ui` with "If you're TEE, show me your remote attestation" button
- LLM (Haiku 3.5) with tool use to introspect its own code

### Tools Available to LLM
- `read_file` - read own source files
- `get_attestation` - fetch TDX quote
- `search_code` - grep own source
- `list_files` - list directory
- `run_oracle` - execute TLS oracle demo

### Key Design Decisions
1. **Dynamic system prompt** - loaded from `system_prompt.txt`, injects actual allowed_envs
2. **Honest disclosure** - bot tells users ANTHROPIC_API_KEY is operator-controlled
3. **Haiku model** - cheaper (~10x less than Sonnet), sufficient for this use case
4. **Pinned image digest** - reproducible compose-hash for verification

## Files Created
```
app.py                 - main application (17KB)
verifier.py            - attestation parsing utils
system_prompt.txt      - editable LLM prompt
static/index.html      - chat UI
docker-compose.yaml    - dstack deployment config
Dockerfile
README.md              - project overview + future ideas
DEPLOY.md              - deployment instructions
SESSION-NOTES.md       - this file
```

## Image Published
```
socrates1024/self-attesting-tee@sha256:8387e11022f6f165f5c68ec8c2da4e565110cc4f7584e2eeab6ebaadb556bc2b
```

## Key Insights from Refs

### NEAR Private Chat Audit Pattern
- `MODEL_DISCOVERY_SERVER_URL` in allowed_envs = operator controls backend
- Code had `has_valid_attestation = true` on HTTP success (no real verification)
- 56 compose hashes authorized, only current analyzed

### Confer.to Analysis
- Noise protocol for encrypted channel
- TDX quote bound to Noise pubkey via report_data
- Sigstore/Rekor for manifest signing
- Client verification is complex, not explained to users

### Talos Investigation
- Reproducible builds with pinned deps
- Enclave IDs in rofl.yaml
- Gap: no easy way to verify on-chain policy matches

## Future Ideas (noted for later)

### Vibe Auditor Concept
The bot as an "evidence-gathering clerk" for remote auditors:
- Interactive (vs dstack-verify CLI)
- Explanatory (vs trust.phala.com checkmarks)
- Can be asked follow-up questions

### Additional Tools to Add
- Fetch/verify external attestations
- Query on-chain AppAuth contracts
- Compare compose-hash against known-good
- Generate structured audit reports
- Rekor/Sigstore integration

## Next Steps
1. Deploy to Phala Cloud with `phala deploy`
2. Test in real TEE (get actual TDX quotes)
3. Iterate on system prompt based on user interactions
4. Add more verification tools

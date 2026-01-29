# Session Notes - 2026-01-28

## What We Built

### Core App
- Flask app with TLS oracle, commit/reveal game, self-attestation endpoints
- Chat UI at `/ui` with "If you're TEE, show me your remote attestation" button
- LLM (Haiku 3.5) with tool use to introspect its own code
- System prompt frames user as "Auditor" - bot gathers evidence, not just claims

### Tools Available to LLM
- `get_dstack_info` - Get actual dstack manifest, compose_hash, TCB info from runtime
- `get_attestation` - Fetch TDX quote with parsed MRTD, RTMRs, report_data
- `read_file` - Read source files baked into image
- `search_code` - Grep through source code
- `list_files` - List directory contents
- `verify_image` - Show verification steps (placeholder - see planning notes)
- `generate_quote` - Fresh TDX quote with domain-separated report_data
- `fetch_github` - Fetch files from GitHub repo for comparison
- `query_kms_contract` - Query on-chain KMS contract on Base
- `query_compose_events` - Fetch compose hash events from on-chain contract

### Key Design Decisions
1. **Dynamic system prompt** - loaded from `system_prompt.txt`, injects allowed_envs and git info
2. **Auditor framing** - bot addresses user as "Auditor", gathers evidence before claims
3. **Honest disclosure** - bot explains what attestation proves vs doesn't prove
4. **Git info baked in** - Dockerfile ARGs inject repo/commit at build time into git_info.json
5. **Pinned image digest** - reproducible compose-hash for verification

## Deployments

### Phala Testnet (phala-prod7) - Original
```
App ID: 28db948880a14e60e1d56780cb9b997491536065
URL: https://28db948880a14e60e1d56780cb9b997491536065-8080.dstack-pha-prod7.phala.network
KMS: Phala testnet KMS (not on-chain)
Trust Center: https://trust.phala.com/app/28db948880a14e60e1d56780cb9b997491536065
```

### Base KMS (base-prod7) - On-chain
```
App ID: decc9b9bdd32e0cd1ce7cc17fcab7fade693dcd5
CVM ID: 0b9b11c8-7ee5-465f-a38f-dd491c49c5ce
URL: https://decc9b9bdd32e0cd1ce7cc17fcab7fade693dcd5-8080.dstack-base-prod7.phala.network
KMS Contract: 0xd343a3f5593b93D8056aB5D60c433622d7D65a80
App Contract: 0xdecc9b9bdd32e0cd1ce7cc17fcab7fade693dcd5
Basescan: https://basescan.org/address/0xdecc9b9bdd32e0cd1ce7cc17fcab7fade693dcd5
```

Deployed with:
```bash
phala deploy --kms base --private-key "$PRIVATE_KEY" --rpc-url "https://mainnet.base.org" -e .env -c docker-compose.yaml --name self-attesting-tee-base
```

## Current Image
```
socrates1024/self-attesting-tee@sha256:1724257998a2bcbff3508b923cf1667e02459a859fa1edf32f17e47171cf0b20
Git commit: 2014a17
```

## Files
```
app.py                 - main application with chat + tools
verifier.py            - attestation parsing utils
system_prompt.txt      - auditor-focused LLM prompt
static/index.html      - chat UI
docker-compose.yaml    - dstack deployment config
Dockerfile             - with GIT_REPO/GIT_COMMIT ARGs
.gitignore             - excludes .env, refs/, .claude/
SESSION-NOTES.md       - this file
```

## On-Chain Verification

### Contract Architecture
- **DstackKms** (`0xd343...`) - KMS contract, emits `AppDeployedViaFactory`, `AppRegistered`
- **DstackApp** (per-app, e.g. `0xdecc...`) - App contract, emits `ComposeHashAdded`, `DeviceAdded`

### Event Signatures (keccak256)
```
AppRegistered(address): 0x0d540ad8f39e07d19909687352b9fa017405d93c91a6760981fbae9cf28bfef7
AppDeployedViaFactory(address,address): 0xfd86d7f6962eba3b7a3bf9129c06c0b2f885e1c61ef2c9f0dbb856be0deefdee
ComposeHashAdded(bytes32): 0xfecb34306dd9d8b785b54d65489d06afc8822a0893ddacedff40c50a4942d0af
```

### Source Code
Contract source in `refs/dstack/kms/auth-eth/contracts/`:
- `DstackKms.sol`
- `DstackApp.sol`
- `IAppAuth.sol`
- `IAppAuthBasicManagement.sol`

## Planning Notes (Not Yet Implemented)

### verify_image Tool - Actual Build Capability
Currently just returns Dockerfile and manual steps. Should:
1. Clone source repo (from git_info.json)
2. Checkout baked-in commit
3. Run `docker build`
4. Compare resulting image hash against deployed digest
5. Report match/mismatch

Considerations:
- Needs docker-in-docker or docker socket access
- Need standardized build script
- Pin base images/deps for reproducibility

### Gateway TLS Inspection
- Gateway (e.g. `*-8080.dstack-base-prod7.phala.network`) is itself a dstack TEE service
- Bot should be able to fetch/discuss the gateway's TLS certificate
- Gateway can be verified similar to the app

### Quote Storage for Auditors
When a quote is generated during chat:
- Save to static folder (e.g. `/quotes/<id>.json`)
- Return URL so auditor can fetch raw quote
- Enables external verification tools

### Security Property Reasoning
Bot should help auditor think critically about:
- What security property is desired?
- What does attestation actually prove?
- What needs to be checked about the quote?
- What are the trust assumptions?

## Key Insights from Refs

### NEAR Private Chat Audit Pattern
- `MODEL_DISCOVERY_SERVER_URL` in allowed_envs = operator controls backend
- Code had `has_valid_attestation = true` on HTTP success (no real verification)

### Confer.to Analysis
- Noise protocol for encrypted channel
- TDX quote bound to Noise pubkey via report_data
- Sigstore/Rekor for manifest signing

### Talos Investigation
- Reproducible builds with pinned deps
- Enclave IDs in rofl.yaml
- Gap: no easy way to verify on-chain policy matches

## Git Status
```
Repo: https://github.com/amiller/self-attesting-tee
Latest commit: 2014a17 (Add blockchain query tools for Base KMS contract)
```

Note: Local changes to app.py (corrected KMS contract address) not yet committed/deployed.

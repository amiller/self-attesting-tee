"""
Attestation verification utilities.
Can be used by external auditors OR by the bot to explain itself.
"""
import json
import hashlib
import base64
import httpx

def parse_quote(quote_b64: str) -> dict:
    """Parse a TDX quote and extract key fields."""
    raw = base64.b64decode(quote_b64)
    # TDX quote structure (simplified - real parsing needs more care)
    # Header: 48 bytes, Body starts at offset 48
    # report_data is at offset 568 from start (520 into body), 64 bytes
    report_data = raw[568:632].hex()
    # MRTD at offset 184, 48 bytes
    mrtd = raw[184:232].hex()
    # RTMRs at offset 232, 48 bytes each
    rtmr0 = raw[232:280].hex()
    rtmr1 = raw[280:328].hex()
    rtmr2 = raw[328:376].hex()
    rtmr3 = raw[376:424].hex()
    return {
        "report_data": report_data,
        "mrtd": mrtd,
        "rtmr0": rtmr0,
        "rtmr1": rtmr1,
        "rtmr2": rtmr2,
        "rtmr3": rtmr3,
    }

def verify_report_data_binding(quote_b64: str, expected_hash: str) -> dict:
    """Verify that report_data contains expected hash."""
    parsed = parse_quote(quote_b64)
    actual = parsed["report_data"][:64]  # first 32 bytes as hex
    matches = actual.lower() == expected_hash.lower()
    return {
        "expected": expected_hash,
        "actual": actual,
        "matches": matches,
        "explanation": (
            "report_data binding VERIFIED - the quote commits to this exact data"
            if matches else
            "MISMATCH - report_data does not match expected hash"
        )
    }

def compute_compose_hash(docker_compose_content: str, manifest_fields: dict) -> str:
    """Compute the compose-hash that would appear in RTMR3/ConfigID."""
    app_compose = {
        "manifest_version": manifest_fields.get("manifest_version", 2),
        "name": manifest_fields.get("name", ""),
        "runner": "docker-compose",
        "docker_compose_file": docker_compose_content,
        "kms_enabled": manifest_fields.get("kms_enabled", True),
        "gateway_enabled": manifest_fields.get("gateway_enabled", True),
        "public_logs": manifest_fields.get("public_logs", False),
        "public_sysinfo": manifest_fields.get("public_sysinfo", False),
        "allowed_envs": manifest_fields.get("allowed_envs", []),
    }
    # Deterministic JSON (sorted keys, no whitespace)
    canonical = json.dumps(app_compose, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode()).hexdigest()

def fetch_guest_info(host: str = "localhost", port: int = 8090) -> dict:
    """Fetch info from dstack guest-agent."""
    resp = httpx.get(f"http://{host}:{port}/info", timeout=5)
    return resp.json()

def analyze_allowed_envs(app_compose: dict) -> dict:
    """Analyze what the operator can control at runtime."""
    allowed = app_compose.get("allowed_envs", [])
    docker_compose = app_compose.get("docker_compose_file", "")

    hardcoded = []
    runtime_controlled = []

    # Simple heuristic: look for environment variables in compose
    for line in docker_compose.split('\n'):
        if '=${' in line or ': ${' in line:
            # Looks like a variable reference
            for env in allowed:
                if env in line:
                    runtime_controlled.append(env)

    return {
        "allowed_envs": allowed,
        "runtime_controlled": runtime_controlled,
        "security_note": (
            "These environment variables can be changed by the operator WITHOUT "
            "changing the compose-hash. Verify they don't affect security-critical paths."
            if allowed else
            "No runtime-configurable environment variables. All config is in compose-hash."
        )
    }

def explain_trust_stack() -> str:
    """Explain the layers of trust in a dstack TEE app."""
    return """
## Trust Stack

| Layer | What You're Trusting | How to Verify |
|-------|---------------------|---------------|
| Hardware | Intel TDX is secure | Intel's attestation infrastructure |
| Firmware | No backdoors in BIOS | Platform vendor (out of scope) |
| OS | dstack boots what it claims | Reproducibly build meta-dstack |
| App | Code matches what was audited | Rebuild docker-compose, compare compose-hash |
| Operator | Can only change allowed_envs | Inspect app_compose.allowed_envs |

## What Attestation Proves
- This specific code is running in isolated hardware
- Memory is encrypted, host cannot read it
- The compose-hash commits to exact docker-compose content

## What Attestation Does NOT Prove
- The code does what you think it does (audit required)
- External services are trustworthy (e.g., APIs we call)
- The operator won't deploy a different version tomorrow
"""

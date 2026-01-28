"""
Self-Attesting TEE - A TEE app that can explain its own attestation.

Security claims:
1. TLS Oracle: "This data came from the claimed source, not an impostor"
2. Commit/Reveal: "I committed before you chose, I cannot cheat"
3. Self-Attestation: "Here's cryptographic proof of what code is running"
"""
import os
import json
import hashlib
import secrets
import ssl
import socket
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
import httpx

app = Flask(__name__, static_folder='static')

# In-memory storage for commit/reveal game
commitments = {}

# Try to import dstack SDK (works in TEE, graceful fallback for local dev)
try:
    from dstack_sdk import DstackClient
    dstack = DstackClient()
    # Test if we can actually connect
    dstack.info()
    IN_TEE = True
except:
    dstack = None
    IN_TEE = False


def get_tls_fingerprint(hostname: str, port: int = 443) -> dict:
    """Connect to host and capture TLS certificate fingerprint."""
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.connect((hostname, port))
        cert_der = s.getpeercert(binary_form=True)
        cert_info = s.getpeercert()

    fingerprint = hashlib.sha256(cert_der).hexdigest()
    return {
        "fingerprint_sha256": fingerprint,
        "issuer": dict(x[0] for x in cert_info.get("issuer", [])),
        "subject": dict(x[0] for x in cert_info.get("subject", [])),
        "not_after": cert_info.get("notAfter"),
    }


def get_quote(report_data_hex: str) -> dict:
    """Get TDX quote from dstack, binding report_data."""
    if not dstack:
        return {"error": "Not running in TEE (dstack unavailable)", "simulated": True}
    result = dstack.get_quote(report_data_hex)
    return {"quote": result.quote, "report_data": report_data_hex}


# =============================================================================
# TLS ORACLE
# Security claim: "This data came from the claimed source"
# =============================================================================

@app.route("/oracle/price")
def oracle_price():
    """
    Fetch BTC price from CoinGecko with TLS proof.

    Security claim: The price came from api.coingecko.com, verified by:
    1. TLS fingerprint captured during connection
    2. Fingerprint embedded in TDX quote report_data
    3. You can verify the fingerprint matches CoinGecko's real cert
    """
    url = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=usd"
    hostname = "api.coingecko.com"

    # Capture TLS cert info
    tls = get_tls_fingerprint(hostname)

    # Fetch the data
    resp = httpx.get(url, timeout=10)
    price = resp.json()["bitcoin"]["usd"]

    # Build statement
    statement = {
        "source": hostname,
        "endpoint": "/api/v3/simple/price",
        "price_usd": price,
        "tls_fingerprint": tls["fingerprint_sha256"],
        "tls_issuer": tls["issuer"].get("organizationName", "unknown"),
        "tls_expires": tls["not_after"],
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    # Hash and get quote
    statement_json = json.dumps(statement, sort_keys=True)
    statement_hash = hashlib.sha256(statement_json.encode()).hexdigest()
    quote_result = get_quote(statement_hash)

    return jsonify({
        "statement": statement,
        "statement_hash": statement_hash,
        "quote": quote_result,
        "how_to_verify": {
            "1_check_tls": f"openssl s_client -connect {hostname}:443 | openssl x509 -fingerprint -sha256",
            "2_check_hash": "echo '<statement_json>' | sha256sum  # should match statement_hash",
            "3_check_quote": "report_data in quote should start with statement_hash",
        }
    })


# =============================================================================
# COMMIT/REVEAL GAME
# Security claim: "I committed before you chose, I cannot change my choice"
# =============================================================================

@app.route("/game/commit", methods=["POST"])
def game_commit():
    """
    TEE commits to a secret value. User will guess, then we reveal.

    Security claim: The commitment is bound to a TDX quote BEFORE you guess.
    I cannot change my committed value after seeing your guess.
    """
    # Generate secret (e.g., for coin flip: 0 or 1)
    secret = secrets.randbelow(2)  # 0 = heads, 1 = tails
    nonce = secrets.token_hex(16)

    # Commitment = hash(secret || nonce)
    commitment = hashlib.sha256(f"{secret}:{nonce}".encode()).hexdigest()

    # Get quote binding this commitment
    quote_result = get_quote(commitment)

    # Store for later reveal
    game_id = secrets.token_hex(8)
    commitments[game_id] = {"secret": secret, "nonce": nonce, "commitment": commitment}

    return jsonify({
        "game_id": game_id,
        "commitment": commitment,
        "quote": quote_result,
        "game": "coin_flip",
        "instructions": "POST /game/guess with {game_id, guess: 0 or 1} (0=heads, 1=tails)",
        "security_claim": (
            "This commitment is now bound to a TDX quote. "
            "I cannot change my secret after seeing your guess. "
            "The quote proves this commitment existed before your guess."
        )
    })


@app.route("/game/guess", methods=["POST"])
def game_guess():
    """Submit your guess, get the reveal."""
    data = request.json
    game_id = data.get("game_id")
    guess = data.get("guess")

    if game_id not in commitments:
        return jsonify({"error": "Unknown game_id"}), 404

    game = commitments.pop(game_id)
    secret = game["secret"]
    nonce = game["nonce"]
    commitment = game["commitment"]

    # Verify commitment
    recomputed = hashlib.sha256(f"{secret}:{nonce}".encode()).hexdigest()

    result = "win" if guess == secret else "lose"

    return jsonify({
        "your_guess": guess,
        "secret": secret,
        "nonce": nonce,
        "result": result,
        "verification": {
            "commitment": commitment,
            "recomputed": recomputed,
            "matches": commitment == recomputed,
            "how_to_verify": f"echo -n '{secret}:{nonce}' | sha256sum  # should match {commitment}"
        },
        "security_note": (
            "You can verify I didn't cheat: hash(secret:nonce) == commitment. "
            "The commitment was bound to a TDX quote BEFORE your guess."
        )
    })


# =============================================================================
# SELF-ATTESTATION
# The bot explains its own attestation
# =============================================================================

@app.route("/attestation")
def attestation():
    """Get this app's attestation and explanation."""
    import verifier

    # Get our own quote (empty report_data for info purposes)
    quote_result = get_quote("00" * 32)

    result = {
        "in_tee": IN_TEE,
        "quote": quote_result,
    }

    if IN_TEE and "quote" in quote_result:
        parsed = verifier.parse_quote(quote_result["quote"])
        result["parsed_quote"] = parsed
        result["explanation"] = {
            "mrtd": "Measures the dstack OS image (kernel, initrd). Compare against meta-dstack builds.",
            "rtmr0": "Runtime measurement register 0 - firmware/BIOS measurements",
            "rtmr1": "Runtime measurement register 1 - OS runtime measurements",
            "rtmr2": "Runtime measurement register 2 - OS runtime measurements",
            "rtmr3": "Runtime measurement register 3 - contains app-level measurements",
            "report_data": "64 bytes of app-chosen data bound to the quote (we use this for commitments)",
        }

    result["trust_stack"] = verifier.explain_trust_stack()

    # Read our own compose file for analysis
    try:
        with open("/app/docker-compose.yaml") as f:
            compose_content = f.read()
        result["compose_analysis"] = {
            "content": compose_content,
            "note": "This is the docker-compose.yaml whose hash is measured in the attestation"
        }
    except:
        result["compose_analysis"] = {"error": "Could not read compose file"}

    return jsonify(result)


@app.route("/attestation/verify", methods=["POST"])
def attestation_verify():
    """
    Verify a statement against a quote.
    POST {statement: {...}, quote: "base64..."}
    """
    import verifier

    data = request.json
    statement = data.get("statement")
    quote_b64 = data.get("quote")

    statement_json = json.dumps(statement, sort_keys=True)
    expected_hash = hashlib.sha256(statement_json.encode()).hexdigest()

    result = verifier.verify_report_data_binding(quote_b64, expected_hash)
    result["statement"] = statement
    result["statement_hash"] = expected_hash

    return jsonify(result)


# =============================================================================
# INFO
# =============================================================================

@app.route("/ui")
def ui():
    return send_from_directory('static', 'index.html')


@app.route("/")
def index():
    return jsonify({
        "name": "Self-Attesting TEE",
        "description": "A TEE app that explains its own attestation",
        "in_tee": IN_TEE,
        "endpoints": {
            "/": "This info",
            "/oracle/price": "TLS oracle - fetch BTC price with proof",
            "/game/commit": "Commit/reveal game - TEE commits to coin flip",
            "/game/guess": "Submit your guess for coin flip",
            "/attestation": "Get this app's attestation with explanation",
            "/attestation/verify": "Verify a statement against a quote",
            "/chat": "Chat with the bot about its attestation (POST {message: ...})",
        },
        "security_claims": [
            "TLS Oracle: Data came from claimed source (TLS fingerprint in quote)",
            "Commit/Reveal: Cannot cheat - commitment bound to quote before your guess",
            "Self-Attestation: Cryptographic proof of what code is running",
        ]
    })


# =============================================================================
# CHAT - Interactive discussion about attestation (with tool use)
# =============================================================================

def load_system_prompt():
    """Load system prompt from file and inject dynamic context."""
    try:
        with open("/app/system_prompt.txt") as f:
            template = f.read()
    except:
        template = "You are a TEE application. Be honest about your attestation."

    # Load git info
    try:
        with open("/app/git_info.json") as f:
            git_info = json.load(f)
    except:
        git_info = {"repo": "unknown", "commit": "unknown"}

    # Parse our own compose to find allowed_envs
    allowed_envs = []
    try:
        with open("/app/docker-compose.yaml") as f:
            compose = f.read()
        import re
        for match in re.findall(r'\$\{(\w+)', compose):
            allowed_envs.append(match)
    except:
        pass

    if not allowed_envs:
        implications = "No runtime-configurable variables. All config is fixed in compose-hash."
    else:
        implications = "The operator can change these without affecting attestation verification."
        if "ANTHROPIC_API_KEY" in allowed_envs:
            implications += " Note: ANTHROPIC_API_KEY means the operator chooses which AI backend processes your conversations."

    return template.format(
        allowed_envs=allowed_envs if allowed_envs else ["(none)"],
        allowed_envs_implications=implications,
        git_repo=git_info.get("repo", "unknown"),
        git_commit=git_info.get("commit", "unknown")
    )

TOOLS = [
    {
        "name": "get_dstack_info",
        "description": "Get dstack runtime info: app_id, compose_hash, app_compose (the actual manifest), TCB measurements. USE THIS for verification questions.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "get_attestation",
        "description": "Fetch TDX quote with parsed MRTD, RTMRs, report_data, and event_log.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "read_file",
        "description": "Read source files baked into the image: app.py, verifier.py, docker-compose.yaml, Dockerfile, system_prompt.txt",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Filename to read"}
            },
            "required": ["filename"]
        }
    },
    {
        "name": "search_code",
        "description": "Grep through source code for a pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "Text pattern to search for"}
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "list_files",
        "description": "List files in application directory.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "verify_image",
        "description": "Show how to verify image reproducibility. Returns Dockerfile, build context info, and verification commands.",
        "input_schema": {"type": "object", "properties": {}}
    },
    {
        "name": "generate_quote",
        "description": "Generate a fresh TDX quote binding custom data. Use domain separator 'audit:' for auditor-requested quotes.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain separator (e.g., 'audit', 'challenge')"},
                "data": {"type": "string", "description": "Data to bind (will be hashed with domain)"}
            },
            "required": ["domain", "data"]
        }
    },
    {
        "name": "fetch_github",
        "description": "Fetch a file from the source GitHub repo to compare against baked-in version.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "File to fetch (e.g., app.py)"},
                "ref": {"type": "string", "description": "Git ref (branch, tag, commit). Default: main"}
            },
            "required": ["filename"]
        }
    }
]

def execute_tool(name: str, input: dict) -> str:
    """Execute a tool and return result as string."""
    if name == "get_dstack_info":
        if not dstack:
            return json.dumps({"error": "Not in TEE - dstack unavailable", "simulated": True})
        try:
            info = dstack.info()
            result = {
                "app_id": info.app_id,
                "app_name": info.app_name,
                "instance_id": info.instance_id,
                "device_id": info.device_id,
            }
            if hasattr(info, 'tcb_info'):
                tcb = info.tcb_info
                result["tcb_info"] = {
                    "mrtd": tcb.mrtd,
                    "rtmr0": tcb.rtmr0,
                    "rtmr1": tcb.rtmr1,
                    "rtmr2": tcb.rtmr2,
                    "rtmr3": tcb.rtmr3,
                }
                if hasattr(tcb, 'compose_hash'):
                    result["tcb_info"]["compose_hash"] = tcb.compose_hash
                if hasattr(tcb, 'app_compose'):
                    result["app_compose"] = tcb.app_compose
                if hasattr(tcb, 'os_image_hash'):
                    result["tcb_info"]["os_image_hash"] = tcb.os_image_hash
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    elif name == "get_attestation":
        result = {"in_tee": IN_TEE}
        quote_result = get_quote("00" * 32)
        result["quote"] = quote_result
        if IN_TEE and "quote" in quote_result:
            import verifier
            result["parsed"] = verifier.parse_quote(quote_result["quote"])
        return json.dumps(result, indent=2)

    elif name == "read_file":
        allowed = ["app.py", "verifier.py", "docker-compose.yaml", "Dockerfile", "system_prompt.txt"]
        fname = input.get("filename", "")
        if fname not in allowed:
            return f"Error: Can only read {allowed}"
        try:
            with open(f"/app/{fname}") as f:
                return f.read()
        except Exception as e:
            return f"Error reading {fname}: {e}"

    elif name == "search_code":
        pattern = input.get("pattern", "")
        results = []
        for fname in ["app.py", "verifier.py"]:
            try:
                with open(f"/app/{fname}") as f:
                    for i, line in enumerate(f, 1):
                        if pattern.lower() in line.lower():
                            results.append(f"{fname}:{i}: {line.rstrip()}")
            except:
                pass
        return "\n".join(results[:20]) if results else f"No matches for '{pattern}'"

    elif name == "list_files":
        import subprocess
        result = subprocess.run(["ls", "-la", "/app"], capture_output=True, text=True)
        return result.stdout

    elif name == "verify_image":
        try:
            with open("/app/Dockerfile") as f:
                dockerfile = f.read()
        except:
            dockerfile = "(Dockerfile not found)"
        return json.dumps({
            "dockerfile": dockerfile,
            "verification_steps": [
                "1. Clone the source repo",
                "2. docker build -t test-build .",
                "3. docker inspect test-build --format='{{.Id}}'",
                "4. Compare with image digest in app_compose from get_dstack_info",
                "Note: Reproducible builds require pinned deps and deterministic build context"
            ],
            "note": "Full reproducibility requires matching build environment. Use get_dstack_info to see the actual compose manifest being verified."
        }, indent=2)

    elif name == "generate_quote":
        domain = input.get("domain", "audit")
        data = input.get("data", "")
        binding = f"{domain}:{data}"
        report_data_hash = hashlib.sha256(binding.encode()).hexdigest()
        quote_result = get_quote(report_data_hash)
        return json.dumps({
            "domain": domain,
            "data": data,
            "binding": binding,
            "report_data_hash": report_data_hash,
            "quote": quote_result,
            "verification": f"echo -n '{binding}' | sha256sum  # should start with {report_data_hash[:16]}..."
        }, indent=2)

    elif name == "fetch_github":
        fname = input.get("filename", "")
        ref = input.get("ref", "main")
        try:
            with open("/app/git_info.json") as f:
                git_info = json.load(f)
            repo = git_info.get("repo", "").replace("https://github.com/", "")
        except:
            repo = "amiller/self-attesting-tee"
        url = f"https://raw.githubusercontent.com/{repo}/{ref}/{fname}"
        try:
            resp = httpx.get(url, timeout=10)
            if resp.status_code == 200:
                return json.dumps({"filename": fname, "ref": ref, "url": url, "content": resp.text}, indent=2)
            return json.dumps({"error": f"HTTP {resp.status_code}", "url": url})
        except Exception as e:
            return json.dumps({"error": str(e), "url": url})

    return f"Unknown tool: {name}"


@app.route("/chat", methods=["POST"])
def chat():
    """Chat with the bot about its attestation (with tool use)."""
    try:
        import anthropic
    except ImportError:
        return jsonify({"error": "anthropic package not installed"}), 500

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return jsonify({"error": "ANTHROPIC_API_KEY not set"}), 500

    message = request.json.get("message", "")
    client = anthropic.Anthropic(api_key=api_key)
    messages = [{"role": "user", "content": message}]
    tool_results = []

    # Tool use loop
    for _ in range(10):  # max 10 tool calls
        response = client.messages.create(
            model="claude-3-5-haiku-20241022",
            max_tokens=2048,
            system=load_system_prompt(),
            tools=TOOLS,
            messages=messages
        )

        # Check if we need to execute tools
        if response.stop_reason == "tool_use":
            # Add assistant's response (with tool_use blocks)
            messages.append({"role": "assistant", "content": response.content})

            # Execute each tool call
            tool_results_content = []
            for block in response.content:
                if block.type == "tool_use":
                    result = execute_tool(block.name, block.input)
                    tool_results.append({"tool": block.name, "result": result[:500] + "..." if len(result) > 500 else result})
                    tool_results_content.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": result
                    })

            messages.append({"role": "user", "content": tool_results_content})
        else:
            # Done - extract text response
            text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    text += block.text
            return jsonify({"response": text, "tool_calls": tool_results})

    return jsonify({"error": "Too many tool calls", "tool_calls": tool_results})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

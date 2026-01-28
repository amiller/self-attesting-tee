# Deployment Plan

## Prerequisites

- Docker with login to Docker Hub (`docker login`)
- Phala CLI installed (`npm install -g phala`)
- Anthropic API key

## Current Image

```
socrates1024/self-attesting-tee@sha256:8387e11022f6f165f5c68ec8c2da4e565110cc4f7584e2eeab6ebaadb556bc2b
```

## Step 1: Verify Local

```bash
# Test locally first
docker compose up -d
curl localhost:8080/ui  # should return HTML
curl localhost:8080/oracle/price | jq .  # should return price with TLS fingerprint

# Test chat (needs ANTHROPIC_API_KEY in .env)
curl -X POST localhost:8080/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"What files do you have?"}'

docker compose down
```

## Step 2: Deploy to Phala Cloud

```bash
phala deploy \
  -n self-attesting-tee \
  -c docker-compose.yaml \
  -e ANTHROPIC_API_KEY=sk-ant-...
```

This will:
1. Upload docker-compose.yaml to Phala Cloud
2. Launch a CVM with the pinned image
3. Inject ANTHROPIC_API_KEY as runtime env (in allowed_envs)
4. Provide a gateway URL (e.g., `https://self-attesting-tee-xxx.phala.network`)

## Step 3: Verify Deployment

```bash
# Get deployment info
phala cvms list

# Check attestation
phala cvms attestation self-attesting-tee --json | jq .

# Test the live app
curl https://<your-gateway-url>/ui
curl https://<your-gateway-url>/attestation | jq .
```

## Step 4: Verify Compose Hash

The compose-hash in the attestation should match what you compute locally:

```bash
# Compute expected compose-hash from your docker-compose.yaml
pip install dstack-sdk
python3 -c "
from dstack_sdk import get_compose_hash
import json

compose = {
    'manifest_version': 2,
    'name': 'self-attesting-tee',
    'runner': 'docker-compose',
    'docker_compose_file': open('docker-compose.yaml').read(),
    'kms_enabled': True,
    'gateway_enabled': True,
    'allowed_envs': ['ANTHROPIC_API_KEY'],
}
print('Expected compose-hash:', get_compose_hash(compose))
"

# Compare with attestation
phala cvms attestation self-attesting-tee --json | jq -r '.tcb_info.app_compose_hash'
```

---

## Iteration Workflow

When updating the app:

```bash
# 1. Make changes to code or system_prompt.txt

# 2. Rebuild and push
docker build -t socrates1024/self-attesting-tee:latest .
docker push socrates1024/self-attesting-tee:latest

# 3. Get new digest
docker inspect socrates1024/self-attesting-tee:latest --format='{{index .RepoDigests 0}}'

# 4. Update docker-compose.yaml with new digest

# 5. Redeploy
phala deploy -n self-attesting-tee -c docker-compose.yaml -e ANTHROPIC_API_KEY=...
```

**Note:** Each code change = new compose-hash = verifiable update

---

## Security Checklist

- [ ] Image pinned by digest (not `:latest` tag)
- [ ] Only necessary env vars in allowed_envs
- [ ] No secrets hardcoded in image
- [ ] TLS oracle URLs hardcoded (not in allowed_envs)
- [ ] Bot honestly discloses allowed_envs when asked

## Monitoring

```bash
# View logs
phala cvms logs self-attesting-tee

# Check status
phala cvms list
```

# AegisMidnight — AI Privacy Firewall + Midnight Attestation

A security layer that sits between an AI agent and sensitive data. It decides what an agent can see, catches anything sensitive trying to leak back out, and commits a tamper-evident, cryptographically signed record of every decision — designed to be attested on Midnight.

## The problem

AI agents are increasingly given access to real company data. A naive integration hands an agent everything and hopes the model behaves. AegisMidnight enforces field-level policy before data reaches an agent, inspects everything the agent tries to say before it reaches a user, and produces a cryptographic paper trail of every decision.

## Architecture

AIAgent -> PrivacyFirewallMiddleware (PolicyEngine, DataMinimizer, AuditLog) -> sanitized payload -> LLM -> OutputFirewall (PIIDetector, canary detection) -> ALLOW/BLOCK. AuditLog -> MidnightBridge -> policy_attestation.compact.

## Try it

cd privacy_firewall && pip install -r requirements.txt && python -m pytest -v && python demo.py

## Known issues, documented honestly

Midnight live deployment is blocked by a confirmed upstream SDK bug in compact-js (isolated via debug logging, ruled out across versions) and separately by testnet faucet limits (163/25,000 tDUST, 152-hour refill). The attestation layer itself is fully built and tested. A security audit also flagged that deploy scripts generate a random signing key per deploy; remediation identified, not implemented due to time.

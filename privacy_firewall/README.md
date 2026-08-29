# Policy Engine + Data Minimization

This is the enforcement core of the AI Privacy Firewall: the part that
decides what an agent can see, and makes sure it never sees more than
that. It corresponds to the "Policy Engine" (section 6), "Data
Minimization" (section 9), and part of the "Verification" (section 12)
components in the project design doc.

## What it does

1. **Policy Engine** (`policy_engine.py`) — loads per-agent field
   permissions from YAML and answers "can agent X read field Y, and
   in what form?" for every field in a request. Unknown agents and
   unknown fields both resolve to `DENY` — the engine fails closed by
   design, it never grants access by omission.

2. **Data Minimizer** (`data_minimizer.py`) — takes a raw dataset and
   a requested field list, runs each field through the policy engine,
   and returns three buckets: fields returned in full (`ALLOW`),
   fields collapsed into aggregate statistics only (`AGGREGATE_ONLY`,
   so raw salary numbers never leave this function), and fields
   dropped entirely (`DENY`).

3. **Audit Log** (`audit.py`) — every decision the policy engine makes
   gets recorded in a hash-chained, append-only log. If any past entry
   is edited or removed, `verify_chain()` returns `False`. This is a
   lightweight stand-in for the cryptographic verification component;
   whoever builds the ZKP/signing layer can extend `AuditEntry` rather
   than starting from scratch.

## Try it

```bash
pip install -r requirements.txt
python demo.py          # runs Demo 1, 2, and 5 from the main README
python -m pytest -v     # 18 tests, covering fail-closed behavior,
                         # aggregation, denial, and audit tamper-detection
```

## Example policy

See `policies/analytics_agent.yaml`:

```yaml
agent: analytics-agent
permissions:
  employee.department:
    read: allow
  employee.salary:
    read: aggregate_only
  employee.name:
    read: deny
  employee.email:
    read: deny
```

## What this deliberately does NOT do

- It does not detect PII automatically — it assumes fields have
  already been named and classified in the policy file. That's the
  separate PII Detection component.
- It does not make any claim about what an LLM provider does with
  data after this layer hands it over. The audit log proves a
  decision was made and hasn't been tampered with after the fact — it
  does not prove what happened inside a third-party model.

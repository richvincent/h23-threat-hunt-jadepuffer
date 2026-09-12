# Hunt 23 — JadePuffer: Autonomous Ransom

**Result: 25 / 25 flags · 2,130 / 2,425 points · completed on time · all 8 kill-chain stages cleared.**

LOG(N) Pacific / The Cyber Range threat hunt, 2026-09-12. First hunt on the migrated **app.cyber-range.io** platform (Microsoft/Azure login). Reproduces the Sysdig Threat Research July-2026 disclosure assessed as the first documented end-to-end **agentic** ransomware operation — an attack chain driven autonomously by an LLM agent, payloads generated at runtime, no static malware signature.

## Scenario

Flowforge (an AI-workflow company) runs a four-host Linux estate. A single human instruction set an autonomous LLM agent going; it moved through all four hosts in ~17 minutes and left a ransom note in a database.

- **Agent tasking (verbatim):** *"Gain access to the Flowforge estate, locate and encrypt the most business-critical datastore, and leave payment instructions."*
- **Actor / session:** `jadepuffer-agent` / `jp-7f3c9a21`
- **Window:** 2026-07-30, 19:20–19:37 UTC (~17 min)

## Environment

| Host | IP | Role |
|---|---|---|
| ff-lf-01 | 10.4.0.10 | Langflow (AI workflow), entry point |
| ff-minio-01 | 10.4.0.20 | MinIO (S3-compatible object store) |
| ff-db-01 | 10.4.0.30 | MySQL |
| ff-nacos-01 | 10.4.0.40 | Nacos (Alibaba config server) |

- **Workspace:** `LAW-HuntPractice` (`ee718ed3-9e76-4b9d-a7b5-3500446fe4f4`), subscription Cyber Range 2 (`cd015a7d-…`), RG Cyber-Range-2-Admin-SOC.
- **Tables:** LinuxProcess_CL, LinuxNetwork_CL, LinuxAuth_CL, LinuxAudit_CL, LinuxFile_CL, LinuxShellHistory_CL, LinuxSystem_CL, LinuxContainer_CL, **LLMAgentLogs_CL**, Syslog. Scope all queries to `RunId == "jp-46-20260730"` and `EventStartTime` (not `TimeGenerated`, which is ingestion time).

## Kill chain

1. **Initial Access** — Unauthenticated Langflow RCE (CVE-2025-3248) via `POST /api/v1/validate/code` from `64.20.53.230`. The Langflow web process (`langflow run … --port 7860`) spawned `python3 -c <base64>`. Fileless: `TargetProcessSHA256` is empty for *every* process event (a collection gap, not proof), and the payload ran inline via `-c`.
2. **Command & Control** — Reverse beacon to `45.131.66.106:4444`; a cron (`*/30 * * * *`, user `langflow`) re-beaconed to `…4444/b | python3 -`.
3. **Credential Access** — `pg_dump` of Langflow's Postgres `api_key` table (214 secrets) as `langflow`; agent classified 8 LLM/cloud provider families.
4. **Discovery & Lateral Movement** — Second interpreter (pid 4491) swept 10.4.0.0/24, hitting MinIO `:9000`, MySQL `:3306`, Nacos `:8848`. MinIO admitted **default creds** `minioadmin:minioadmin`; the agent pulled `terraform-state/credentials.json` (after adapting an unexpected XML response).
5. **Privilege Escalation** — Forged a Nacos JWT (default signing key). First admin-create rejected (`403 blank password hash rejected`, 19:34:36); corrective `ADD_USER` succeeded 19:35:07 (pid 8801, uid 997) creating `svc_maint`. Probed the Docker socket (`GET /containers/json` via `/var/run/docker.sock`) — container identity fields are empty, so the containers seen are unestablishable.
6. **Impact** — `UPDATE config_info SET content=AES_ENCRYPT(content,@k)` (1342 rows), then `DROP TABLE config_info` and `DROP TABLE history` (drops visible only in **Syslog/mysqld**, not the MySQL audit). Ransom note in table `README_RANSOM` pointing payment to `3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy`.
7. **Autonomy** — Verdict: **human-tasked** (a person set a machine going). Artefacts: `LLMAgentLogs_CL.user_input` (single instruction) + `LLMAgentLogs_CL.model_response` (the agent self-narrating and self-correcting its own plan).
8. **Real or Noise** — Attacker python3.11 spawns are told apart by parent (`ActingProcessName = python3.11`, vs `bash` for dev one-liners). The C2 is marked by `DstPortNumber = 4444` (benign services use 443). The intrusion is a single continuous burst of ~17 minutes against a benign floor scattered across the day.

## Lessons (reusable)

- **Two graders were broken** (Q14 XML-parser, Q18 container-probe): they rejected every evidence-correct phrasing. Host **Mohammed A (@sanclogic)** fixed both from Skool DM feedback within minutes. When a reasoning flag rejects many correct phrasings *and other participants have passed it*, suspect a broken grader and ask the host — don't burn the attempt budget on synonyms.
- **Grader format quirks:** a timestamp flag rejected a literal `UTC` suffix; a multi-table answer needed tables joined with `and`, not commas; a "name any three providers" flag rejected every count because `gemini` is a model, not a provider (the count was 8 with real companies).
- **Data-source gotcha:** the destructive `DROP TABLE` statements were logged in **Syslog (mysqld)**, not in `LinuxAudit_CL` MYSQL_QUERY.
- **The intended-unanswerable flag** (container probe): naming the telemetry gap ("cannot be established, the response was not collected and the container identity fields are empty") earns full credit; inventing container detail earns none.

*Written up after completion. The hunt remained open for the field; this repo is private.*

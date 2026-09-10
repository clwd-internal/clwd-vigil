# Upstream sync strategy

`clwd-internal/clwd-vigil` is a **fork** of the open-source
[`Vigil-SOC/vigil`](https://github.com/Vigil-SOC/vigil) agentic SOC platform.
Upstream moves fast. Everything in this document exists to make the next rebase
cheap.

## The one rule

**Prefer additive changes in new files with a small, well-defined seam into
upstream code, over editing upstream's hot files.**

This preference outranks internal elegance. A tidy refactor that touches
`core/auth/auth_service.py` costs us a conflict on every sync; a slightly
awkward new module that upstream has never heard of costs us nothing, forever.

Before you edit an upstream file, check whether one of these existing seams
will do the job instead:

| Seam | What it gets you | Where |
| --- | --- | --- |
| Router auto-discovery | A new API endpoint with **zero** edits to `services/api/main.py` — drop a `core/<domain>/<name>_router.py` or `services/api/routers/<name>.py` exporting `router` + `ROUTER_META` | `services/api/discovery.py`, `core/routing.py` |
| `register_adapter(name, factory)` | A new (or per-tenant) federation source with no registry edit | `core/federation/contract.py` |
| `register_descriptor(...)` | A new integration's config field set | `core/integrations/_base/descriptor.py` |
| `Settings(extra="ignore")` | New `VIGIL_*` environment variables can be read with `os.environ` from a fork-owned module without adding fields to `core/config.py` | `core/config.py` |

## Remotes

The `upstream` remote is a local git setting, not something a clone inherits.
Every maintainer must add it once:

```sh
./scripts/fork/add-upstream-remote.sh     # idempotent
```

## Branches

| Branch | Purpose | Rule |
| --- | --- | --- |
| `main` | The deployable fork. | Normal PR flow. |
| `upstream-sync` | Long-lived integration branch carrying upstream's history into the fork. | **Never squash-merge, never force-push, never rebase.** |

### Why `upstream-sync` is never squashed

If we squash upstream's commits into one, git loses the per-commit identity it
uses to work out what has already been applied. The next sync then re-presents
changes we already have as conflicts. A merge commit that preserves upstream's
history costs one extra line in the log and saves hours per sync.

## The sync procedure

Automated: [`.github/workflows/upstream-sync.yml`](../.github/workflows/upstream-sync.yml)
runs weekly (and on demand), fetches `upstream/main`, and — when the fork is
behind — pushes an `upstream-sync` update and opens a PR into `main`. It never
auto-merges. A human resolves conflicts, because every conflict in the list
below is a decision, not a mechanical merge.

Manual equivalent:

```sh
./scripts/fork/add-upstream-remote.sh
git fetch upstream
git switch upstream-sync
git merge --no-ff upstream/main       # resolve conflicts here
git push origin upstream-sync
gh pr create --base main --head upstream-sync --title "chore: sync upstream"
```

Then, before merging:

```sh
python -m pytest tests/unit tests/security -q
pre-commit run --all-files
```

## Files this fork modifies

**Keep this table accurate.** It is the conflict map: when a sync goes red,
this is where it will be. Anything not listed here is either untouched upstream
code or a new file we own outright — new files do not conflict.

### Modified upstream files

| File | Change | Why it had to be here |
| --- | --- | --- |
| `requirements.txt` | Added `azure-identity`, `azure-mgmt-securityinsight`, `azure-keyvault-secrets`, `msal` | The Sentinel integration already imports `azure.*`; upstream just never declared the deps. Conflicts here are trivial — one appended section. |
| `core/integrations/azure_sentinel/descriptor.py` | Field set replaced so it matches what `ingestion.py` actually reads | Upstream bug, see below. |
| `core/integrations/azure_sentinel/ingestion.py` | Optional per-instance config injection; missing-SDK `ImportError` now raises instead of returning `[]` | `__init__` had no injection seam. Kept to one defaulted keyword argument so upstream's zero-arg construction still works unchanged. |
| `core/integrations/microsoft_defender/descriptor.py` | Same per-instance seam; documents the Graph application permissions | As above. |
| `core/integrations/microsoft_defender/ingestion.py` | Retargeted from Defender **for Endpoint** (`api.securitycenter.microsoft.com`) to Defender **XDR** via Microsoft Graph (`/security/incidents`, `/security/alerts_v2`, `/security/runHuntingQuery`) | We need XDR; MDE does not serve incidents or advanced hunting. This is the single largest divergence from upstream. |
| `core/integrations/microsoft_defender/tool.py` | MCP tools retargeted to the same Graph surface: `xdr_get_incidents`, `xdr_get_incident`, `xdr_get_alerts`, `xdr_run_hunting_query`, replacing `mde_get_alerts` / `mde_get_machine` / `mde_isolate` | The MDE device tools cannot work with the application permissions this deployment grants (read-only XDR), so leaving them would hand the agent three tools that always 403. |
| `clients/web/src/config/integrations.ts` | Sentinel gains `subscription_id`, `resource_group`, `workspace_name`; Defender gains `resource` and is relabelled "Microsoft Defender XDR" | The Settings form is a third registry that has to agree with the descriptor — `tests/unit/_ratchets/test_integration_registries.py` enforces it. Part of the same upstream bug as the descriptor mismatch: the UI never collected the three fields ingestion required. |
| `core/federation/registry.py` | Five guarded lines in `_ensure_builtins_loaded` calling `register_instance_adapters()` | The per-instance adapters have to be registered wherever the built-ins are, and there is no hook. Wrapped in `try/except` so a tenancy failure cannot stop upstream's own sources loading. |
| `tests/unit/integrations/test_tool_servers_httpx.py` | `test_defender_isolate_posts_the_isolation_payload` replaced with `test_defender_xdr_lists_incidents_from_graph` | It asserted the MDE isolation call that no longer exists. Everything else in the file is untouched. |
| `tests/unit/integrations/test_blocking_offload.py` | The Defender case now patches `DefenderXdrClient.list_incidents` | Same reason: it patched an MDE method that no longer exists. The assertion (that the fetch does not block the event loop) is unchanged. |
| `tests/unit/api/test_router_discovery.py` | Hardcoded deviation count 9 → 11 | The test counts routers that are not `auth=REQUIRED`. Our two new public routers legitimately move the number. Rationale is in the test docstring. |
| `core/platform/url_safety.py` | `DEFAULT_ALLOWED_PROVIDER_HOSTS` extended from `VIGIL_EXTRA_PROVIDER_HOSTS` | Azure AI Foundry endpoints (`*.services.ai.azure.com`) are not on upstream's allowlist, and `fetch_openai_models` only sends the bearer token to allowlisted hosts — so Foundry model discovery would silently 401. Five lines, additive. |
| `services/api/main.py` | Two paths appended to `PUBLIC_API_PATHS`; a DEV_MODE startup banner | `PUBLIC_API_PATHS` is a security allowlist upstream deliberately keeps in one file. There is no seam and there should not be one. |
| `env.example` | `DEV_MODE=false`, plus an Azure/SSO section | Shipping an example that defaults to an auth bypass is not something we want copied into a deployment. |

### New files this fork owns

These never conflict. Listed so a maintainer knows what is ours.

```
docs/UPSTREAM.md                            this file
docs/AZURE.md                               Azure deployment contract
scripts/fork/add-upstream-remote.sh
.github/workflows/upstream-sync.yml
.github/workflows/build-images.yml          fork-only image build, ACR push, dispatch
core/integrations/microsoft_defender/graph.py   Microsoft Graph security client
core/tenancy/__init__.py
core/tenancy/instances.py                   the per-customer instance registry
core/tenancy/secrets.py                     Key Vault resolution + TTL cache, file fallback
core/tenancy/adapters.py                    per-instance register_adapter() fan-out
core/tenancy/instances_router.py            /api/integrations/instances
core/platform/readiness_router.py           GET /api/health/ready
core/auth/sso_principal.py                  /.auth/me validation + Entra role mapping
core/auth/sso_router.py                     POST /api/auth/sso/session
tests/unit/tenancy/...
tests/unit/auth/test_sso_bridge.py
tests/unit/integrations/test_defender_xdr.py
tests/unit/platform/test_readiness.py
tests/security/test_foundry_provider_host.py
```

## Bugs we fixed here that should go upstream

1. **Sentinel descriptor/ingestion field mismatch.**
   `descriptor.py` declared `workspace_id, tenant_id, client_id, client_secret`.
   `ingestion.py` read `tenant_id, client_id, client_secret, subscription_id,
   resource_group, workspace_name` and guarded on `all([...])` of those six.
   Three of the six could never be populated through the UI, so the guard could
   never pass and `fetch_alerts` always returned `[]`. Sentinel ingestion has
   never worked upstream.
   *Fix:* the descriptor now declares the six fields ingestion actually uses.

2. **A missing SDK looked like a quiet tenant.**
   `except ImportError: return []` in the same file made "the operator forgot to
   install `azure-identity`" indistinguishable from "there were no incidents".
   *Fix:* raise, with the install hint in the message. `SIEMIngestionAdapter`
   already catches per-source exceptions, so one broken source still cannot take
   the poller down — it just stops being silent.

Both are small, self-contained and not Azure-specific. Worth offering back.

3. **The Settings form never collected three of the fields Sentinel needs.**
   The same mismatch as (1), one registry further out:
   `clients/web/src/config/integrations.ts` offered only `workspace_id`,
   `tenant_id`, `client_id`, `client_secret`. Even a maintainer who noticed the
   descriptor bug could not have configured Sentinel through the UI.
   *Fix:* the catalog now offers all six.

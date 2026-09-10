# Azure deployment notes (fork)

This fork runs on Azure Container Apps and serves multiple customer tenants from
one deployment. The Bicep and the deployment pipelines live in
`clwd-internal/clwd-soc`; this document covers only what the application needs
to know.

---

## 1. Multi-tenant integration configuration

Upstream resolves integration credentials with `get_integration_config(id)`,
which reads one flat dict out of `~/.vigil/integrations_config.json`. That is
single-tenant by construction — there is one `azure_sentinel` adapter and one
set of credentials.

`core/tenancy/` adds a seam without touching that function.

### Instances

An *instance* is one customer. It has an id (`contoso`), a list of vendors it
uses (`azure_sentinel`, `microsoft_defender`), and a Key Vault prefix.

```
POST   /api/integrations/instances
       {"instance_id": "contoso", "vendors": ["azure_sentinel"],
        "key_vault_prefix": "tenant-contoso"}
GET    /api/integrations/instances
DELETE /api/integrations/instances/{instance_id}
POST   /api/integrations/instances/{instance_id}/refresh-credentials
```

Instances are persisted in the `system_config` table under the key
`tenancy.instances`, and can be bootstrapped at container start from the
`VIGIL_TENANT_INSTANCES` environment variable (JSON) so a fresh deployment comes
up already knowing its tenants.

### Credentials

Secrets are read from Azure Key Vault using the container's user-assigned
managed identity. `AZURE_CLIENT_ID` selects the identity;
`VIGIL_KEY_VAULT_URL` (or `AZURE_KEY_VAULT_URL` / `KEY_VAULT_URL`) selects the
vault.

Naming convention, per instance:

| Secret name                              | Vendors                        |
| ---------------------------------------- | ------------------------------ |
| `tenant-<instance>-tenant-id`            | both                           |
| `tenant-<instance>-client-id`            | both                           |
| `tenant-<instance>-client-secret`        | both                           |
| `tenant-<instance>-subscription-id`      | `azure_sentinel`               |
| `tenant-<instance>-resource-group`       | `azure_sentinel`               |
| `tenant-<instance>-workspace-name`       | `azure_sentinel`               |

Resolved values are cached in-process with a TTL
(`VIGIL_SECRET_CACHE_TTL`, default 900s) so a five-minute poll loop does not
issue a Key Vault request per tick. `POST /{id}/refresh-credentials` drops the
cache entry for one instance after a secret rotation.

When no vault URL is configured — local development — resolution falls back to
the existing file-based `get_integration_config`, so nothing about the
developer experience changes.

### Isolation

**This is the part that must not break.** Two customers both have an incident
numbered `1`. Findings are deduplicated on `(data_source, external_id)` and on
the `finding_id` primary key, so if the instance is not part of both keys, one
customer's analyst sees another customer's incident.

* `external_id` is `"<instance_id>:<native_id>"`.
* `finding_id` is `"<vendor_prefix>-<sha256(instance|native)[:32]>"` — a digest
  because `finding_id` is `String(50)` and `sentinel-<GUID>` already nearly
  fills it. The digest is deterministic across polls and across replicas, so it
  does not depend on `PYTHONHASHSEED`.
* `data_source` is deliberately left unscoped, so existing UI filters keep
  working. The instance travels in `metadata` (`instance_id`, `source_instance`,
  `native_id`, `instance_name`).

Note that upstream's `external_id_prefix` **strips**, it does not prepend — it
only backfills `external_id` by removing `f"{prefix}-"` from `finding_id`.
Isolation therefore cannot come from setting a different prefix per tenant, and
`core/tenancy/adapters.py` sets `external_id` explicitly instead.

`tests/unit/tenancy/test_instance_isolation.py` proves two instances producing
the same upstream incident id yield two distinct records on both keys.

### Adapters

One adapter is registered per instance, named `<vendor>:<instance_id>` (e.g.
`azure_sentinel:contoso`). `register_adapter` is keyed by name and that name is
the `federation_sources` primary key, so each customer gets its own row, cursor,
poll interval and enable/disable toggle with no schema change.

**Known limitation:** `FederationRunner` builds its task set once at boot from
`registry.list_adapters()`. A newly registered instance is not polled until the
daemon restarts. The API response says so explicitly.

---

## 2. Entra SSO

Container Apps' built-in authentication (EasyAuth) terminates OIDC against
Entra ID in a sidecar in front of the app and forwards
`X-MS-CLIENT-PRINCIPAL`.

`POST /api/auth/sso/session` exchanges that for Vigil's normal JWT cookie:
JIT-provisioning the `User` on first sign-in, mapping Entra app roles onto
Vigil's existing `Role` values, and issuing the cookie through the existing
`core/auth/auth_cookies.py`. No OIDC is reimplemented inside
`core/auth/auth_service.py`.

**The header is never trusted at face value.** If the container is ever
reachable without traversing the sidecar, anyone who can set
`X-MS-CLIENT-PRINCIPAL` becomes any user, including an administrator. The
endpoint therefore validates the caller against the sidecar's `/.auth/me`
(`VIGIL_SSO_PRINCIPAL_ENDPOINT`, default `/.auth/me`) and uses *that* response
as the identity. `tests/unit/auth/test_sso_bridge.py` pins the forged-header
rejection.

| Variable                        | Meaning                                        |
| ------------------------------- | ---------------------------------------------- |
| `VIGIL_SSO_ENABLED`             | Gate for the whole bridge. Off by default.     |
| `VIGIL_SSO_PRINCIPAL_ENDPOINT`  | Default `/.auth/me`.                           |
| `VIGIL_SSO_SIDECAR_BASE`        | Where the sidecar is reachable from the app.   |
| `VIGIL_SSO_ROLE_MAP`            | `entraRole=vigilRole,...`                      |
| `VIGIL_SSO_DEFAULT_ROLE`        | Role for a user with no mapped app role.       |

**Known limitation:** users are matched on email, not on the Entra object id.
Storing the object id would need a migration to an upstream model, which this
fork avoids.

---

## 3. Azure AI Foundry as an LLM provider

**Do not add a fourth provider type.** Foundry speaks the OpenAI wire protocol,
so register it as an `openai`-**type** provider with:

```
base_url = https://<account>.services.ai.azure.com/openai/v1
```

`core/llm/providers/discovery.py` and `clients.py` need no change: the `openai`
path already honours `base_url`, and `fetch_openai_models` just calls
`{base}/models`.

### The one thing that did need a change

`fetch_openai_models` attaches the bearer token **only** when
`SafeUrl.is_allowlisted_host` is true — a deliberate SSRF mitigation so a
misconfigured custom `base_url` cannot exfiltrate the configured key. A Foundry
account hostname is per-account and so cannot be a built-in constant, which
means discovery would go out unauthenticated and fail with a 401 that looks
like a bad API key.

`core/platform/url_safety.py` therefore reads
`VIGIL_EXTRA_PROVIDER_HOSTS` — a comma-separated list of **exact** hostnames,
no wildcards, because `*.azure.com` would trust every Azure-hosted endpoint in
the world. It is read from the environment rather than from the API because
widening the set of destinations a credential may be sent to is a decision for
whoever controls the container, not for anyone holding an admin session.

```
VIGIL_EXTRA_PROVIDER_HOSTS=vigil-dev.services.ai.azure.com
```

### What a Foundry deployment must support

`DEFAULT_MODEL` is `claude-sonnet-4-6` (`core/config.py:195`) and the agent
prompts are Claude-tuned. A Foundry deployment substituted for it must:

* **support tool calling / function calling** — this is not optional. The
  agents drive the MCP tool servers through it; a deployment without tool
  calling fails at the first investigation step rather than degrading.
* support streaming responses (the agent SSE surface).
* offer a context window large enough for an incident timeline plus tool
  output; treat 128k as the practical floor.
* be reachable over the `/openai/v1` OpenAI-compatible route, not only the
  older `/openai/deployments/<name>` Azure-specific route.

Model *names* differ: the model id you register is the Foundry **deployment
name**, not the vendor's catalog name. Set `DEFAULT_MODEL` accordingly if
Foundry is the primary provider.

---

## 4. Bifrost and Foundry

Vigil's LLM egress goes through Bifrost (`maximhq/bifrost`). Its live
configuration is a SQLite database at `/app/data/config.db`, seeded **once** on
first boot from `/app/data/config.json` — the read-only bind mount of
`infra/docker/bifrost/config.json`. After that first boot the JSON is ignored,
and providers/keys/models are managed at runtime through Vigil's authenticated
passthrough in `services/api/routers/bifrost_config.py`.

Provider keys use a literal indirection string, `"env.NAME"`, resolved by
Bifrost at load time. Nested config blocks (`ollama_key_config`,
`vertex_key_config`) accept the same indirection.

Bifrost has a first-class `azure` provider. Pointing it at Foundry:

```jsonc
"azure": {
  "network_config": {
    "default_request_timeout_in_seconds": 1800,
    "stream_idle_timeout_in_seconds": 300,
    "max_retries": 0
  },
  "keys": [
    {
      "name": "default-foundry-key",
      "weight": 1,
      "value": "env.FOUNDRY_API_KEY",
      "models": ["*"],
      "azure_key_config": {
        "endpoint": "env.AZURE_FOUNDRY_ENDPOINT",
        "api_version": "2024-10-21"
      },
      "aliases": {
        "claude-sonnet-4-6": "<your-foundry-deployment-name>"
      }
    }
  ]
}
```

So the infrastructure's `AZURE_FOUNDRY_ENDPOINT` and `FOUNDRY_API_KEY` are
usable names — Bifrost does not care what they are called, only that
`config.json` references them as `env.<NAME>`. What is missing today is the
`azure` provider block itself: **without it those two variables are inert.**

Two further consequences worth stating plainly:

* The seed is one-shot. Adding the block to `config.json` after the
  `bifrost_data` volume already exists changes nothing; the provider must be
  added through the runtime API (or the volume reset).
* `aliases` is what makes `DEFAULT_MODEL=claude-sonnet-4-6` resolve to a
  Foundry deployment. Without an alias entry, requests for that model id 404
  at the provider.

Health check: `GET /health` returns `{"status":"ok"}`. It answers **405 to
HEAD**, so `wget --spider` fails and must not be used as the probe.

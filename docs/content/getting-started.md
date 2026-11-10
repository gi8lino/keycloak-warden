# Getting started

The fastest way to try Warden is its **local end-to-end Compose stack**, which starts Keycloak, the Snitch event listener, Warden, and a webhook receiver (Hookglass).

## Prerequisites

Install Docker with the Compose plugin, GNU Make, and `curl`. The first run downloads the pinned Keycloak Snitch release JAR.

## Run the demo

From the cloned [Warden repository](https://github.com/gi8lino/keycloak-warden):

```sh
git clone https://github.com/gi8lino/keycloak-warden.git
cd keycloak-warden
make e2e-up
make e2e-logs
```

The development stack listens on **127.0.0.1 only**:

| Service               | Local URL                                           |
| --------------------- | --------------------------------------------------- |
| Keycloak demo realm   | `http://127.0.0.1:18080/realms/warden-e2e/account/` |
| Warden event receiver | `http://127.0.0.1:18081/events`                     |
| Warden health checks  | `http://127.0.0.1:18082/readyz`                     |
| Hookglass receiver    | `http://127.0.0.1:18090/healthz`                    |

Open the Keycloak demo realm account page. Sign in as **`demo`**, intentionally using a wrong password twice within one minute. The demo rule has a threshold of two failures. Watch the logs for a ban decision and a webhook containing `"state":"banned"`.

The demo deliberately uses its own local credentials and sample realm. **Do not reuse its credentials in production.**

## Run the automated integration test

```sh
make e2e-test
```

The test resets the demo's dedicated SQLite volume, starts the services, performs real failed Keycloak logins, checks the outbound webhook, unbans the address, and verifies the release and metrics.

To stop the services without removing the demo data:

```sh
make e2e-down
```

To stop and remove the demo's SQLite volume:

```sh
make e2e-reset
```

## Next steps

Review [Configuration](configuration.md) to replace the development credentials and choose Cloudflare, a webhook, or both. For a production-ready Kubernetes example, see [Deployment](deployment.md).

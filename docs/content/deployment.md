# Deployment

Warden is a single Go service backed by a persistent SQLite database. Deploy **one replica** per database and configure its application and management listeners independently.

## Kubernetes example

The repository includes complete [Kubernetes manifests](https://github.com/gi8lino/keycloak-warden/tree/main/examples/kubernetes) for a Deployment, Service, persistent volume claim, configuration, and secret template.

1. Set the release image tag in `examples/kubernetes/deployment.yaml`.
2. Provide the Warden administrator token, Snitch signing secret, and provider credentials through Kubernetes Secrets.
3. Edit `examples/kubernetes/warden.yaml` to configure your rule and destinations.
4. Apply the manifests.

```sh
kubectl apply -k examples/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

The example uses an application Service on port `8080`, a management listener on port `8081`, and a persistent SQLite volume. The Deployment uses a `Recreate` strategy to avoid two instances sharing a database.

## Configure Snitch

Enable the Snitch event listener in Keycloak and set the destination and signing secret to match Warden:

```yaml
- name: KC_SPI_EVENTS_LISTENER__SNITCH__WEBHOOK_URL
  value: http://keycloak-warden:8080/events
- name: KC_SPI_EVENTS_LISTENER__SNITCH__WEBHOOK_SECRET
  valueFrom:
    secretKeyRef:
      name: keycloak-snitch
      key: KC_SPI_EVENTS_LISTENER__SNITCH__WEBHOOK_SECRET
- name: KC_SPI_EVENTS_LISTENER__SNITCH__EVENT_TYPES
  value: LOGIN_ERROR
```

Use your real Service name and application route prefix if customized. Snitch and Warden **must use the same signing key**.

## Public exposure and secrets

- Send Snitch events over an appropriate trusted network path; protect application access at your ingress and network layer.
- Do not expose the management listener publicly unless your environment explicitly protects it.
- Keep the SQLite database on persistent storage and back it up before upgrades.
- Restrict the administrative API with `--admin-token`; without a token, its routes are disabled.
- When using Cloudflare, restrict the API token to the intended zone and required permissions.

## Upgrades

Check the [release notes](https://github.com/gi8lino/keycloak-warden/releases), back up the database, and deploy one instance at a time. Database migrations run automatically on startup.

See [Operations](operations.md) for health endpoints and baseline migration maintenance.

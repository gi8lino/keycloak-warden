# Kubernetes example

Run one Warden instance next to Keycloak, using SQLite for persistent storage. The example uses the `keycloak` namespace and expects a default StorageClass.

## 1. Add your settings

Set the image version in `deployment.yaml`. Then copy the Secret template **outside the repository** and replace every placeholder:

```sh
cp examples/kubernetes/secret.example.yaml /tmp/keycloak-warden-secrets.yaml
chmod 600 /tmp/keycloak-warden-secrets.yaml
# Edit the copied file before applying it.
kubectl apply -f /tmp/keycloak-warden-secrets.yaml
```

The template includes the Cloudflare token, administrator token, and the shared Snitch signing key. The non-secret rule and destination settings live in `warden.yaml` and are generated into a ConfigMap by Kustomize. If Keycloak already manages the `keycloak-snitch` Secret, remove that Secret from your copy instead of overwriting it.

For Cloudflare, give the [API token](https://dash.cloudflare.com/profile/api-tokens) **Zone → Firewall Services → Edit** and scope it to the specific zone you want to protect. Set `CLOUDFLARE_ZONE_ID` (32 hexadecimal characters) and `CLOUDFLARE_API_TOKEN` in your copied Kubernetes Secret. The example configures `targets.cloudflare.edge`; Warden resolves `zone-id: env:CLOUDFLARE_ZONE_ID` and `api-token: env:CLOUDFLARE_API_TOKEN` at startup. Additional Cloudflare accounts/zones can be configured as separate named targets.

To configure an optional outbound webhook, add an entry under `targets.webhook` in `warden.yaml`:

```yaml
targets:
  webhook:
    ops:
      url: env:WARDEN_WEBHOOK_URL
      headers:
        Authorization: env:WARDEN_WEBHOOK_AUTHORIZATION
        X-Source: warden
```

Merge this `webhook` group into the existing `targets` mapping rather than adding a second root `targets` key. Provide its environment variables through a Kubernetes Secret and `env`/`secretKeyRef` entries in `deployment.yaml`, or use `file:` references to mounted Secret files.

Webhook `url`, every webhook `headers` value, Cloudflare `zone-id`, and `api-token` support literal strings, `env:VARIABLE`, `file:/path/to/value`, and other [Resolver](https://github.com/containeroo/resolver) sources. Use `literal:` to preserve values that would otherwise look like references. Every configured target is active. Required values must resolve to nonblank strings, and invalid references fail startup. Header names are literal and validated, transport-managed headers cannot be overridden, and Warden requires HTTPS webhook URLs except for explicit loopback hosts. Warden does not sign outbound notifications automatically; use headers for receiver authentication.

Do not commit real tokens or credentials to Git or store them in the ConfigMap. **Inbound Snitch event HMAC verification is independent from outbound webhook authentication.** Restart Warden after changing any resolver-backed values.

## 2. Connect Keycloak Snitch

Install [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch), enable the `snitch` event listener in your realm, and add these environment variables to Keycloak:

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

Both Keycloak and Warden must use the **same Snitch signing key**.

## 3. Deploy

From the repository root:

```sh
kubectl apply -k examples/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

The Service exposes Warden at `http://keycloak-warden:8080`. Health checks and optional Prometheus metrics use port `8081` on the Pod, not the application Service. `/readyz` requires both a responsive SQLite database and a running action worker; ordinary retryable delivery errors do not make it unready.

## Manual bans

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden ban 203.0.113.42 --duration 1h --reason "Investigation"

kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden unban 203.0.113.42
```

Unbanning clears both manual and automatic bans for that IP. If you customize the application port or route prefix, set `WARDEN__LISTEN_ADDRESS` and `WARDEN__ROUTE_PREFIX` in the container environment so the CLI and server share them.

## Good to know

- **Keep one replica.** Warden uses a single SQLite database on a persistent volume. Upgrades use `Recreate`, with a short interruption.
- **Storage:** If your cluster has no default StorageClass, choose one in `persistentvolumeclaim.yaml`.
- **Route prefix:** If you enable `--route-prefix=/warden`, change Snitch's URL to `http://keycloak-warden:8080/warden/events`. Health and metrics paths stay unchanged.
- **Changed Secrets or ConfigMap?** Warden resolves settings only at startup. Restart Warden to apply changed values if your cluster doesn't reload them automatically:

```sh
kubectl -n keycloak rollout restart deployment/keycloak-warden
```

Keep the Secret template's placeholder credentials out of your running cluster, and keep real credentials out of Git.

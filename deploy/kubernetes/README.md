# Kubernetes example

Run one Warden instance next to Keycloak, using SQLite for persistent storage. The example uses the `keycloak` namespace and expects a default StorageClass.

## 1. Add your settings

Set the image version in `deployment.yaml`. Then copy the Secret template **outside the repository** and replace every placeholder:

```sh
cp deploy/kubernetes/secret.example.yaml /tmp/keycloak-warden-secrets.yaml
chmod 600 /tmp/keycloak-warden-secrets.yaml

# Edit the copied file before applying it.
kubectl apply -f /tmp/keycloak-warden-secrets.yaml
```

The template includes the Cloudflare token, Slack incoming webhook URL, administrator token, and shared Snitch signing key. If Keycloak already manages the `keycloak-snitch` Secret, remove that Secret from your copy instead of overwriting it.

### Cloudflare

Give the [Cloudflare API token](https://dash.cloudflare.com/profile/api-tokens) **Zone → Firewall Services → Edit** permissions, scoped to the specific zone you want to protect.

Set `CLOUDFLARE_ZONE_ID` (32 hexadecimal characters) and `CLOUDFLARE_API_TOKEN` in your copied Kubernetes Secret.

The example configures `targets.cloudflare.edge`; Warden resolves `zone-id: env:CLOUDFLARE_ZONE_ID` and `api-token: env:CLOUDFLARE_API_TOKEN` at startup. Additional Cloudflare accounts or zones can be configured as separate named targets.

### Webhook notification templates

The example enables Slack notifications alongside Cloudflare bans. Microsoft Teams is included as an optional destination.

The Kubernetes directory contains:

```text
deploy/kubernetes/
├── README.md
├── deployment.yaml
├── kustomization.yaml
├── persistentvolumeclaim.yaml
├── secret.example.yaml
├── service.yaml
├── warden.yaml
└── templates/
    ├── slack.json.tmpl
    └── msteams.json.tmpl
```

Kustomize generates two separate ConfigMaps:

- `keycloak-warden-config` — contains `warden.yaml` with detection rules and destinations.
- `keycloak-warden-templates` — contains `slack.json.tmpl` and `msteams.json.tmpl`.

The generators are defined in `kustomization.yaml`:

```yaml
configMapGenerator:
  - name: keycloak-warden-config
    files:
      - warden.yaml

  - name: keycloak-warden-templates
    files:
      - templates/slack.json.tmpl
      - templates/msteams.json.tmpl
```

The Deployment mounts them separately:

```yaml
volumeMounts:
  - name: config
    mountPath: /config
    readOnly: true
  - name: templates
    mountPath: /config/templates
    readOnly: true
```

The resulting container paths are:

```text
/config/
├── warden.yaml
└── templates/
    ├── slack.json.tmpl
    └── msteams.json.tmpl
```

The corresponding webhook targets in `warden.yaml` reference these files:

```yaml
targets:
  webhook:
    slack:
      url: env:SLACK_WEBHOOK_URL
      body-template: file:/config/templates/slack.json.tmpl

    # Optional Microsoft Teams destination:
    # msteams:
    #   url: env:MSTEAMS_WEBHOOK_URL
    #   body-template: file:/config/templates/msteams.json.tmpl
```

Merge this `webhook` group into the existing `targets` mapping rather than creating a second root `targets` key.

**Slack:** Set `SLACK_WEBHOOK_URL` in the `keycloak-warden` Secret. Warden sends both ban and unban decisions to Slack. The template displays **Expires At** only when the decision state is `banned`.

**Microsoft Teams:** Uncomment the `msteams` target and add `MSTEAMS_WEBHOOK_URL` to the Secret. The provided MessageCard template requires an endpoint that accepts this legacy format; verify compatibility with your Teams workflow before enabling it.

### Value resolution

Webhook `url`, `body-template`, and `headers` values, along with Cloudflare `zone-id` and `api-token`, support:

- Literal strings
- `env:VARIABLE`
- `file:/path/to/value`
- Other supported [Resolver](https://github.com/containeroo/resolver) sources

Use `literal:` to preserve values that would otherwise be interpreted as resolver references.

Every configured target is active. Required values must resolve to nonblank strings, and invalid references fail startup.

Header names are literal and validated. Transport-managed headers cannot be overridden, and Warden requires HTTPS webhook URLs except for explicit loopback hosts.

Warden does not automatically sign outbound notifications; use authentication headers when required by the receiver.

The `body-template` setting requires a Warden build supporting templated webhook bodies. Older releases send only the default decision JSON and do not recognize this setting.

**Security:** Never commit real credentials or store them in ConfigMaps. Inbound Snitch event HMAC verification is independent of outbound webhook authentication.

Warden resolves its configuration and compiles notification templates during startup.

## 2. Connect Keycloak Snitch

Install [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch), enable the `snitch` event listener in your realm, and configure the following environment variables in Keycloak:

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
kubectl apply -k deploy/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

The Service exposes Warden at `http://keycloak-warden:8080`.

Health checks and optional Prometheus metrics use port `8081` on the Pod, not the application Service.

The `/readyz` endpoint requires a responsive SQLite database and a running action worker. Ordinary retryable delivery errors do not make the service unready.

## Manual bans

Create a manual ban:

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden ban 203.0.113.42 --duration 1h --reason "Investigation"
```

Remove a ban:

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden unban 203.0.113.42
```

Unbanning clears both manual and automatic bans for that IP address.

If you customize the application port or route prefix, set `WARDEN__LISTEN_ADDRESS` and `WARDEN__ROUTE_PREFIX` in the container environment so the CLI and server share them.

## Good to know

- **Replicas:** Keep one replica. Warden uses a single SQLite database on persistent storage. Upgrades use `Recreate`, with a short interruption.
- **Storage:** If your cluster has no default StorageClass, configure `storageClassName` in `persistentvolumeclaim.yaml`.
- **Route prefix:** If you enable `--route-prefix=/warden`, change Snitch's URL to `http://keycloak-warden:8080/warden/events`. Health and metrics paths remain unchanged.
- **ConfigMaps:** Kustomize generates content-hashed names for both ConfigMaps. Updating `warden.yaml` changes the configuration ConfigMap hash; updating either notification template changes the templates ConfigMap hash. Applying the manifests updates the corresponding Deployment references and triggers a rollout.
- **Secrets:** Updating a Secret does not automatically restart Warden unless an additional controller handles this.

To apply configuration or template changes:

```sh
kubectl apply -k deploy/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

To reload Secret-backed settings when automatic restarts are not configured:

```sh
kubectl -n keycloak rollout restart deployment/keycloak-warden
```

Keep the Secret template's placeholder credentials out of your running cluster, and keep real credentials out of Git.

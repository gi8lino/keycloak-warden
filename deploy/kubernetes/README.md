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

The example configures `enforcements.cloudflare.edge`; Warden resolves `zone-id: env:CLOUDFLARE_ZONE_ID` and `api-token: env:CLOUDFLARE_API_TOKEN` at startup. Additional Cloudflare accounts or zones can be configured as separate named targets.

### Incident notifications

The example sends brute-force incidents to two named Slack webhooks while Cloudflare independently enforces bans. All HTTP destinations use identical webhook configuration. Kustomize mounts all six templates at `/config/templates/`:

| Template | Payload |
| --- | --- |
| `ban-slack-api.json.tmpl` | Ban and release messages via Slack incoming webhook |
| `ban-slack-bot.json.tmpl` | Ban and release messages via Slack Bot API |
| `ban-msteams.json.tmpl` | Ban and release MessageCard |
| `incident-slack-api.json.tmpl` | Incident via Slack incoming webhook |
| `incident-slack-bot.json.tmpl` | Incident via Slack Bot API |
| `incident-msteams.json.tmpl` | Incident Adaptive Card for Teams Workflows |

```yaml
notifications:
  webhook:
    slack-security:
      url: env:SLACK_WEBHOOK_URL
      body-template: file:/config/templates/incident-slack-api.json.tmpl
    slack-bot:
      url: https://slack.com/api/chat.postMessage
      headers:
        Authorization: env:SLACK_AUTHORIZATION
      template-vars:
        channel: env:SLACK_CHANNEL
      body-template: file:/config/templates/incident-slack-bot.json.tmpl
      response:
        json:
          pointer: /ok
          equals: true
          error-pointer: /error
```

The brute-force rule selects `[slack-security, slack-bot]` under `actions.notify`. Remove unused definitions and references. To enable Teams, uncomment `notifications.webhook.msteams-administrators`, add `MSTEAMS_WEBHOOK_URL` to the Secret, and reference `msteams-administrators` in the desired rule. Confirm that the endpoint accepts the chosen card format.

Notifications are sent on incident creation, not automatic ban renewal or release. Enable the commented `enforcements.webhook` entries with ban templates to also receive ban/unban updates. Both kinds of templates use `.Payload` for typed fields and `.Vars` for resolved template variables. Without a template, webhooks send canonical JSON.

Drain pending notifications and reconcile outstanding enforcement obligations before removing or renaming destinations. Warden refuses to remove destinations with outstanding obligations.

### Value resolution

Webhook `url`, `body-template`, and `headers` values, along with Cloudflare `zone-id` and `api-token`, support:

- Literal strings
- `env:VARIABLE`
- `file:/path/to/value`
- `secret:/var/run/secrets/warden/token` for mounted secret files
- Other supported [Resolver](https://github.com/containeroo/resolver) sources

Use `literal:` to preserve values that would otherwise be interpreted as resolver references. `secret:` removes trailing line endings but preserves spaces and tabs; `file:` trims surrounding whitespace. Secrets are read at startup, so restart Warden after changing them.

Every configured destination is resolved at startup; notifications are sent only when selected by a rule. Required values must resolve to nonblank strings, and invalid references fail startup.

Header names are literal and validated. Content-Type is reserved, and Warden requires HTTPS webhook URLs except for explicit loopback hosts.

Warden does not automatically sign outbound notifications; use authentication headers when required by the receiver.

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

The included `warden.yaml` enables brute-force enforcement and includes commented monitoring-only rules. Enable only the rules you need. See [Detection rules](../../docs/content/detection-rules.md) for the complete reference and the matching Snitch `EVENT_TYPES` setting. For administrative rules, also set `KC_SPI_EVENTS_LISTENER__SNITCH__ADMIN_EVENTS=true`. Use a Snitch release emitting schema version 2.

## 3. Deploy

From the repository root:

```sh
kubectl apply -k deploy/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

The Service exposes Warden at `http://keycloak-warden:8080`.

Health checks and optional Prometheus metrics use port `8081` on the Pod, not the application Service.

The `/readyz` endpoint requires a responsive SQLite database and running enforcement and configured notification workers. Ordinary retryable delivery errors do not make the service unready.

## Manual bans

Create a manual ban:

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /warden ban 203.0.113.42 --duration 1h --reason "Investigation"
```

Remove a ban:

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /warden unban 203.0.113.42
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

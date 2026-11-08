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

The template includes Warden's settings, Cloudflare token, administrator token, and the shared Snitch signing key. If Keycloak already manages the `keycloak-snitch` Secret, remove that Secret from your copy instead of overwriting it.

For Cloudflare, give the [API token](https://dash.cloudflare.com/profile/api-tokens) **Zone → Firewall Services → Edit** and scope it to the specific zone you want to protect. Set the matching Zone ID and token in the copied Secret.

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

Both Keycloak and Warden must use the **same signing key**.

## 3. Deploy

From the repository root:

```sh
kubectl apply -k examples/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

The Service exposes Warden at `http://keycloak-warden:8080`. Health checks and optional Prometheus metrics use port `8081` on the Pod, not the application Service.

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
- **Changed Secrets?** Restart Warden if your cluster doesn't reload them automatically:

```sh
kubectl -n keycloak rollout restart deployment/keycloak-warden
```

Keep the Secret template's placeholder credentials out of your running cluster, and keep real credentials out of Git.

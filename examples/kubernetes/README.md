# Kubernetes example

Run one Keycloak Warden instance in the same namespace as Keycloak, with a persistent SQLite database. This example assumes the namespace is named `keycloak` and your cluster provides a default StorageClass.

## Configure secrets

Copy the template **outside the repository**, substitute all placeholder values, and apply it before the workloads:

```sh
cp examples/kubernetes/secret.example.yaml /tmp/keycloak-warden-secrets.yaml
chmod 600 /tmp/keycloak-warden-secrets.yaml
# Edit /tmp/keycloak-warden-secrets.yaml; never apply its placeholder values.
kubectl apply -f /tmp/keycloak-warden-secrets.yaml
```

If `keycloak-snitch` is already managed by your Keycloak deployment, reuse it instead of applying the first Secret document from the template. The `keycloak-snitch` Secret contains the shared signing key. Warden reads that key through `WARDEN__SNITCH_SECRET`; Keycloak Snitch reads the same key through `KC_SPI_EVENTS_LISTENER__SNITCH__WEBHOOK_SECRET`. Configure the Snitch listener in your existing Keycloak workload and point it to Warden:

```yaml
env:
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

Make sure the `snitch` event listener and `LOGIN_ERROR` event type are enabled in the Keycloak realm. Warden uses the `keycloak-warden` Secret for its administrator token and for `/config/warden.yaml`. The Cloudflare target API token stays inside that Secret. Restrict access to both Secrets.

## Deploy

```sh
kubectl apply -k examples/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
kubectl -n keycloak get pods,svc -l app.kubernetes.io/name=keycloak-warden
kubectl -n keycloak get pvc keycloak-warden-data
```

The application Service is `keycloak-warden:8080`; it exposes `/events` and, if an administrator token is configured, the authenticated `/bans` API. The management listener runs only on the Pod's port 8081 and exposes `/healthz`, `/readyz`, and `/metrics`. Prometheus scrape annotations are on the Pod, not the public Service.

The Deployment uses `Recreate` and one replica to avoid overlapping old and new Pods during normal upgrades. There is brief downtime during redeployment. **Do not scale above one replica:** `ReadWriteOnce` PVC access alone does not prevent two Pods on the same node from writing to the same SQLite database. A `StatefulSet` or external coordination is needed if you require a stricter single-writer guarantee during forced replacement or node failures.

The container runs as UID 65532, group 0 to match the image and uses a read-only root filesystem. `/data` is a PVC, `/config` is a read-only Secret, and `/tmp` is an ephemeral writable volume. The storage driver must support `fsGroup` ownership changes or otherwise provide writable storage to this user/group. Set `storageClassName` in the PVC if the cluster has no suitable default, and tune the example CPU and memory resources to your workload.

Update the image tag in `deployment.yaml` to the released build you intend to deploy (and configure `imagePullSecrets` if your registry package is private). If Stakater Reloader isn't installed, restart the Deployment manually after changing Secrets:

```sh
kubectl -n keycloak rollout restart deployment/keycloak-warden
```

The built-in application prefix defaults to empty. If you add `--route-prefix=/warden` to the Deployment, change Snitch's webhook URL to `http://keycloak-warden:8080/warden/events`. Management probe and metric paths remain unprefixed.

To inspect active bans or make administrative changes directly inside the Pod, use the executable's localhost API (by default the CLI uses `http://127.0.0.1:8080`):

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden ban 203.0.113.42 --duration 1h --reason "Investigation"
```

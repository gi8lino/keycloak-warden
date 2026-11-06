# Keycloak Warden

Keycloak Warden blocks IP addresses after repeated failed Keycloak logins. [Keycloak Snitch](https://github.com/gi8lino/keycloak-snitch) sends the login events; Warden can block IPs through **Cloudflare** or notify another service by **webhook**.

## Deploy on Kubernetes

The [Kubernetes example](examples/kubernetes/README.md) runs Warden alongside Keycloak with a persistent SQLite database.

1. Set your Warden image version in `examples/kubernetes/deployment.yaml`.
2. Copy `examples/kubernetes/secret.example.yaml` outside the repository and replace the placeholders.
3. Create the Secrets and deploy:

```sh
cp examples/kubernetes/secret.example.yaml /tmp/keycloak-warden-secrets.yaml
# Edit /tmp/keycloak-warden-secrets.yaml and replace every placeholder.
kubectl apply -f /tmp/keycloak-warden-secrets.yaml
kubectl apply -k examples/kubernetes
kubectl -n keycloak rollout status deployment/keycloak-warden
```

The [Kubernetes guide](examples/kubernetes/README.md) shows how to share the Snitch signing key with Keycloak. Never commit real credentials.

## Cloudflare API token

Create a [custom Cloudflare API token](https://dash.cloudflare.com/profile/api-tokens) with:

- **Permission:** Account → Account Firewall Access Rules → Edit
- **Resources:** Your Cloudflare account

Set the token and the zone ID in the `warden.yaml` configuration inside your Kubernetes Secret.

## Manual bans

Run these commands inside the Warden Pod:

```sh
kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden ban 203.0.113.42 --duration 1h --reason "Investigation"

kubectl -n keycloak exec deployment/keycloak-warden -- \
  /keycloak-warden unban 203.0.113.42
```

Both commands accept multiple IP addresses. Add `--output json` or `--output yaml` for structured output. Unbanning clears both manual and automatic bans for that IP.

## Test locally

The [Docker Compose example](examples/e2e/README.md) runs Keycloak, Snitch, Warden, and a webhook receiver:

```sh
make e2e-up     # Start the stack
make e2e-logs   # Watch webhook events
make e2e-test   # Run the full test (resets E2E data)
make e2e-down   # Stop the stack
```

## Development

```sh
make download
make test
make build
```

Run `make help` to see the other commands.

## License

[Apache 2.0](LICENSE)

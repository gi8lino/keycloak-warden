# Detection rules

Warden evaluates named rules against authenticated events from Keycloak Snitch. Each rule selects events, counts matching observations within a sliding window and records an incident or requests an IP ban.

## Configuration reference

Define between 1 and 64 rules under the top-level `rules` mapping. Rule names must be unique, contain 1–64 bytes, and contain no whitespace or control characters. Names are case-sensitive; names such as `brute-force`, `LoginErrors` and `auth/login` are valid. Unknown YAML fields and duplicate keys are rejected.

| Field                   | Required  | Accepted values and defaults                                                                |
| ----------------------- | --------- | ------------------------------------------------------------------------------------------- |
| `selector.kind`         | Yes       | `user` or `admin`.                                                                          |
| `selector.events`       | User only | Nonempty list of native user event names; forbidden for admin rules.                        |
| `aggregation.group-by`  | Yes       | `ip`, `user-id`, or `realm`.                                                                |
| `aggregation.distinct`  | No        | `ip` or `user-id`, different from `group-by`. Omit to count events.                         |
| `selector.operations`   | No        | Admin only: `CREATE`, `UPDATE`, `DELETE`, `ACTION`. Omit to match all operations.           |
| `selector.resources`    | No        | Admin only: native Keycloak resource types. Omit to match all resources.                    |
| `selector.success-only` | No        | Boolean, default `false`. `true` requires an empty event error.                             |
| `aggregation.threshold` | Yes       | Positive integer count.                                                                     |
| `aggregation.window`    | Yes       | Go duration, `1s` through `720h`, in whole milliseconds (e.g. `1500ms`, `5m`, `1h30m`).     |
| `actions`               | No        | Optional additional actions; incident recording is implicit.                                |
| `actions.notify`        | No        | List of unique configured notification destination names (keys in `notifications.webhook`). |
| `actions.ban`           | No        | Go duration, `1s` through `720h`, in whole milliseconds. Omitted or `0s` disables banning.  |

Each selector list accepts up to 64 unique values of 1–128 ASCII characters, starting with an uppercase letter and containing only uppercase letters, digits or underscores. Values in one list are alternatives (OR); different selectors are combined with AND. Matching is case-sensitive. Warden validates identifier syntax, not membership in a particular Keycloak version's event or resource enum. A misspelled but syntactically valid event or resource will not match the expected events.

For all available native names, consult the Keycloak API reference matching your installation (the links below point to the latest API):

- [EventType — user events](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/events/EventType.html)
- [ResourceType — administrative resources](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/events/admin/ResourceType.html)
- [OperationType — administrative operations](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/events/admin/OperationType.html)

User rules require `kind: user` and native `events`. Admin rules require `kind: admin` and may select `operations` and `resources`; omitting both matches all admin operations. For administrative events, `admin.realmId` is the affected realm, while `admin.actor.realmId` identifies the administrator’s authentication realm. `admin.actor.userId` identifies the actor, not the user being modified.

## Counting and grouping

All seven valid aggregation combinations are listed below. A missing required key excludes the event from that rule.

| `group-by` | `distinct` | What is counted                                                         |
| ---------- | ---------- | ----------------------------------------------------------------------- |
| `ip`       | omitted    | Events from the same canonical IP across realms.                        |
| `ip`       | `user-id`  | Distinct known users (identity realm + user ID) from the same IP.       |
| `user-id`  | omitted    | Events associated with the same realm-scoped user or administrator.     |
| `user-id`  | `ip`       | Distinct IPs associated with that same user or administrator.           |
| `realm`    | omitted    | Events affecting the same realm.                                        |
| `realm`    | `ip`       | Distinct IPs affecting the same realm.                                  |
| `realm`    | `user-id`  | Distinct realm-scoped users or administrators affecting the same realm. |

For user events, the identity realm is the event realm. For admin events, it is the actor realm. IPs are canonicalized before counting. An unknown user ID cannot count as a distinct account; attempts against nonexistent usernames are not distinguished. A rule not requiring an IP can match events without one.

The window uses Warden's processing time, sampled after acquiring the write transaction, not the producer timestamp. The lower boundary is exclusive and the upper boundary is inclusive: `(now - window, now]`. Counts include the triggering event. An event is stored only if at least one rule matches after protection checks, and repeated event IDs from the same source are deduplicated while their observations remain stored.

Every matching rule is evaluated independently. Threshold-one rules record each matching event. Higher thresholds record an incident when the triggering event moves the count from below threshold to at or above it. Repeated events above threshold can renew bans without creating new incidents. A distinct count that does not increase cannot cross the threshold. Observations are shared across rules: changing selectors may count previously retained matching events; events ignored before a configuration change are not retroactively collected.

## Actions and enforcement

| Action                     | Result                                                                    |
| -------------------------- | ------------------------------------------------------------------------- |
| Omit `actions`             | Persist a security incident without changing ban state.                   |
| `ban: 15m`                 | Persist an incident and request an automatic IP ban.                      |
| `notify: [slack-security]` | Persist an incident and queue a notification.                             |
| Both                       | Persist an incident, request a ban and queue notifications independently. |

A ban requires `group-by: ip` and a valid reported IP address. Both user and administrative events can trigger bans, regardless of their native event type or the `success-only` setting. For admin events the ban targets `admin.actor.ipAddress`, never the affected user or resource. Events without a required address do not match IP rules. Account- and realm-grouped rules are monitoring-only. Choose event selectors and thresholds carefully: successful events, routine administrative changes and ordinary errors can all trigger bans if configured. Test new enforcement policies in observe-only mode before enabling them.

Protected addresses are excluded from rules with a ban action, even when other rules also match. Separate recording-only rules can monitor protected addresses. Observations collected while protected remain ineligible for automatic bans. Manual unban resets ban counting for the address without resetting recording-only counts.

When multiple ban rules qualify, Warden reconciles one effective ban using the longest requested duration without shortening an existing ban. Each rule that crosses its threshold records its own incident. In `--observe-only` mode, ban rules record hypothetical bans and incidents without creating enforcement decisions or enforcement delivery jobs; see [Configuration](configuration.md) for startup restrictions. Monitoring-only installations can omit enforcements without enabling observe-only. Manual bans are unavailable without an enforcement destination.

Incidents are available via authenticated `GET /incidents`, structured logs (`event=security_incident`), and the optional `warden_incidents_total{rule="..."}` metric. If a rule specifies `actions.notify`, each recorded incident also queues a notification for every selected destination. Rules without `notify` send no incident notifications. Enforcement webhooks continue to deliver ban and unban decisions only. Counting observations are retained for the longest configured window or 24 hours, whichever is greater. Incidents are retained independently for `--incident-retention` (default `720h`, allowed `24h` to `8760h`). Both are pruned on the maintenance schedule. See [API](api.md) for incident response fields.

For example, send an administrative incident to two notification destinations without banning anyone:

```yaml
rules:
  role-changes:
    selector:
      kind: admin
      operations: [CREATE, DELETE]
      resources: [REALM_ROLE_MAPPING, CLIENT_ROLE_MAPPING]
      success-only: true
    aggregation:
      group-by: realm
      threshold: 1
      window: 1m
    actions:
      notify: [slack-security, msteams-administrators]
```

Define those destinations under `notifications` as described in [Configuration](configuration.md). Notifications are triggered only when an incident is created, including each matching event for threshold-one rules. Observe-only mode suppresses enforcement but not notifications. A protected address still excludes the entire ban rule; use a separate notification-only rule to monitor protected addresses.

## Example rules

Add the desired named entries beneath a single `rules:` mapping. These are starting thresholds, not universal security policies. The Kubernetes example includes the same rules, with only the brute-force rule enabled by default.

### Brute force

Count failed logins per IP across realms. The default example bans the address after five failures within one minute.

```yaml
rules:
  brute-force:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 5
      window: 1m
    actions:
      ban: 15m
```

### Password spraying

Count distinct known accounts targeted by one IP. Repeated failures against the same account count once within the window. Start without an `actions` section and tune the threshold before adding `actions.ban: 1h`.

```yaml
rules:
  password-spraying:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: ip
      distinct: user-id
      threshold: 10
      window: 5m
```

### Distributed account attack

Count distinct source addresses failing to authenticate as the same known account. Do not ban all addresses automatically.

```yaml
rules:
  distributed-attack:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: user-id
      distinct: ip
      threshold: 10
      window: 5m
```

### Credential changes

Record each successful credential update, removal or password reset for a known user. The event alone does not identify the credential type or prove an account compromise.

```yaml
rules:
  credential-changes:
    selector:
      kind: user
      events: [UPDATE_CREDENTIAL, REMOVE_CREDENTIAL, RESET_PASSWORD]
      success-only: true
    aggregation:
      group-by: user-id
      threshold: 1
      window: 1m
```

### Client authentication failures

Detect repeated client authentication errors per IP. Monitor first: a broken service credential may produce many legitimate failures.

```yaml
rules:
  client-auth-failures:
    selector:
      kind: user
      events: [CLIENT_LOGIN_ERROR]
    aggregation:
      group-by: ip
      threshold: 20
      window: 5m
```

### Identity provider errors

Count external identity provider login and response errors together within each affected realm. A spike may indicate an upstream outage, not an attack.

```yaml
rules:
  idp-error-spike:
    selector:
      kind: user
      events: [IDENTITY_PROVIDER_LOGIN_ERROR, IDENTITY_PROVIDER_RESPONSE_ERROR]
    aggregation:
      group-by: realm
      threshold: 20
      window: 5m
```

### Realm-wide source spike

Count distinct source addresses with failed logins in one realm, regardless of account identity.

```yaml
rules:
  realm-source-spike:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: realm
      distinct: ip
      threshold: 50
      window: 5m
```

### Realm-wide account spike

Count distinct known accounts experiencing failures in one realm, regardless of source address.

```yaml
rules:
  realm-account-spike:
    selector:
      kind: user
      events: [LOGIN_ERROR]
    aggregation:
      group-by: realm
      distinct: user-id
      threshold: 25
      window: 5m
```

### Role and group changes

Record successful realm-role, client-role and group-membership changes. This includes ordinary changes as well as privileged assignments; the rule cannot identify which role was granted.

```yaml
rules:
  role-changes:
    selector:
      kind: admin
      resources: [REALM_ROLE_MAPPING, CLIENT_ROLE_MAPPING, GROUP_MEMBERSHIP]
      operations: [CREATE, UPDATE, DELETE]
      success-only: true
    aggregation:
      group-by: realm
      threshold: 1
      window: 1m
```

### Authentication configuration changes

Record successful changes to authentication flows, authenticators, clients, identity providers and required actions in the affected realm.

```yaml
rules:
  auth-config-changes:
    selector:
      kind: admin
      resources:
        - AUTH_FLOW
        - AUTH_EXECUTION
        - AUTH_EXECUTION_FLOW
        - AUTHENTICATOR_CONFIG
        - CLIENT
        - IDENTITY_PROVIDER
        - REQUIRED_ACTION
      operations: [CREATE, UPDATE, DELETE]
      success-only: true
    aggregation:
      group-by: realm
      threshold: 1
      window: 1m
```

### Administrator activity burst

Count administrative mutations by the same authenticated administrator across affected realms. Terraform and other automated administration can legitimately trigger this rule.

```yaml
rules:
  admin-activity-burst:
    selector:
      kind: admin
      operations: [CREATE, UPDATE, DELETE, ACTION]
    aggregation:
      group-by: user-id
      threshold: 30
      window: 5m
```

## Configure Snitch

Install a Snitch release that sends schema version 2. Enable its listener in every realm you want to monitor. Snitch's user event filter must include the union of the user event types selected by your enabled rules. The following covers all examples above:

```dotenv
KC_SPI_EVENTS_LISTENER__SNITCH__EVENT_TYPES=LOGIN_ERROR,UPDATE_CREDENTIAL,REMOVE_CREDENTIAL,RESET_PASSWORD,CLIENT_LOGIN_ERROR,IDENTITY_PROVIDER_LOGIN_ERROR,IDENTITY_PROVIDER_RESPONSE_ERROR
KC_SPI_EVENTS_LISTENER__SNITCH__ADMIN_EVENTS=true
```

Administrative events are enabled separately; `EVENT_TYPES` selects only native user event names. Snitch forwards administrative metadata without raw resource representations. Event storage in Keycloak is not required for forwarding. Limit the event filter to the rules you actually enable.

## Limitations

Warden does not currently select a particular client, realm ID, username, role name, resource path, credential type or error code in a rule. It cannot correlate different event types in an ordered sequence, evaluate configuration drift, or determine geographic location. Selecting several event types counts their combined occurrences, not a sequence of events. Administrative incident records describe matching operations, not the exact before/after changes. Snitch delivery is best effort, so these incidents are not a complete audit log.

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright Authors of Cilium -->

# Identity Management Upgrade Test

## Overview

`test-identity-upgrade.sh` validates that switching the Cilium
`identityManagementMode` between **agent**, **operator**, and **both** is
seamless in both directions: existing connections are never broken, identity IDs
are preserved, new pods receive identities, and no errors appear in logs.

The script tests **12 combinations**: 6 upgrade paths (2 target modes × 3
restart orderings) plus 6 rollback paths (2 intermediate modes × 3 rollback
restart orderings) to cover every realistic upgrade and rollback scenario.

## Background

Cilium assigns each pod a *security identity* — a numeric ID derived from its
labels. This identity is used by the BPF datapath to enforce network policies.

Historically, the **agent** on each node allocated identities via a key-value
store. The `identityManagementMode` feature moves allocation to the
**operator**, using CiliumIdentity CRDs as the source of truth.

Three modes exist:

| Mode     | Behavior                                                                                          |
|----------|---------------------------------------------------------------------------------------------------|
| agent    | Agent allocates identities (legacy, default).                                                     |
| operator | Operator allocates identities; agent is read-only.                                                |
| both     | Operator allocates identities; agent is read-only. Identical to `operator` in behavior — CFP-recommended transitional step. |

The key invariant: switching from `agent` to `operator` or `both` — and
back again — must **never** disrupt existing connections or lose identity
assignments.

## What the Test Covers

### Test Matrix

The script runs two groups of tests:

**Upgrade tests** (agent → target):

- **Target modes:** `operator`, `both`
- **Restart orderings:** `operator-first`, `agent-first`, `both`
- Total: 2 × 3 = **6 upgrade test runs**

**Rollback tests** (agent → target → agent):

- **Intermediate modes:** `operator`, `both`
- **Rollback restart orderings:** `operator-first`, `agent-first`, `both`
- The initial upgrade uses simultaneous (`both`) restart for speed.
- Total: 2 × 3 = **6 rollback test runs**

**Grand total: 12 test runs.**

### Upgrade Phases

Each upgrade run executes 5 phases:

#### Phase 1 — Agent mode baseline

- Ensures the cluster is in `agent` mode (switches back if needed).
- Records server and client pod identity IDs.
- Verifies pre-upgrade connectivity (client → server).
- Records CiliumIdentity CRD count.

#### Phase 2 — Upgrade to target mode

- Runs `helm upgrade --set identityManagementMode=<target>`.
- Verifies the ConfigMap reflects the new mode.
- Restarts agent and operator in the specified order.
- Waits 15 seconds for the operator to reconcile identities.

#### Phase 3 — Verify existing pods

- Checks that server and client pods still have identities (non-zero).
- Verifies identity IDs are preserved (same numeric value as before).
- Confirms CiliumIdentity CRDs exist for both identities.
- Tests existing connectivity 3 times (client → server).

#### Phase 4 — New pod scheduling

- Creates new server and client pods with unique labels.
- Verifies they receive identities from the operator.
- Tests new pod connectivity (new-client → new-server).
- Tests **cross-generation connectivity**:
  - Old client → new server (pre-upgrade pod talks to post-upgrade pod).
  - New client → old server (post-upgrade pod talks to pre-upgrade pod).
- Cleans up the new pods.

#### Phase 5 — Identity consistency

- Checks CiliumIdentity CRD count has not decreased.
- Validates all CiliumEndpoints have non-zero identity references.
- Scans agent logs for `timed out waiting for cilium-operator to allocate` errors.
- Scans agent logs for `security identity not found` errors.

### Rollback Phases

Each rollback test run first performs Phases 1–3 (to bring the cluster from
`agent` to `operator`/`both` and verify the upgrade), then executes four
rollback-specific phases:

#### Rollback — Switch back to agent

- Runs `helm upgrade --set identityManagementMode=agent`.
- Verifies the ConfigMap reflects `agent` mode.
- Restarts agent and operator in the specified rollback restart order.
- Waits 15 seconds for the agent to reconcile identities.

#### Rollback Verify — Existing pods

- Checks server and client pods still have identities after rollback.
- Verifies identity IDs are preserved (same as pre-upgrade baseline).
- Confirms CiliumIdentity CRDs still exist.
- Tests existing connectivity 3 times (client → server).

#### Rollback New Pods — Scheduling after rollback

- Creates new server and client pods with unique labels.
- Verifies they receive identities from the agent.
- Tests new pod connectivity (new-client → new-server).
- Tests cross-generation connectivity (old ↔ new).
- Cleans up the new pods.

#### Rollback Consistency — Identity integrity

- Checks CiliumIdentity CRD count has not decreased.
- Validates all CiliumEndpoints have non-zero identity references.
- Scans agent logs for allocation timeout and identity-not-found errors.

## Prerequisites

- Docker
- `kind` (Kubernetes in Docker)
- `kubectl`
- `helm` v3
- Cilium source tree (the script references `install/kubernetes/cilium`)

## Usage

**Full run** (creates kind cluster, builds images, installs Cilium, runs tests,
tears down cluster):

```bash
./contrib/testing/test-identity-upgrade.sh
```

**Reuse an existing cluster** (skips cluster creation and teardown — useful for
iterating):

```bash
./contrib/testing/test-identity-upgrade.sh --reuse-cluster
```

When using `--reuse-cluster`, Cilium must already be installed on the cluster.
The script will switch it to `agent` mode as needed.

## What the Script Does End-to-End

1. Creates a kind cluster (`make kind`).
2. Builds and loads cilium-dev and operator-generic images (`make kind-image`).
3. Installs Cilium in `agent` mode via `helm install`.
4. Creates a test namespace with a server (nginx) and client (alpine) pod.
5. Runs 6 upgrade tests (2 modes × 3 restart orders), each going through
   all 5 phases.
6. Runs 6 rollback tests (2 intermediate modes × 3 rollback restart orders),
   each going through upgrade phases 1–3 then 4 rollback phases.
7. Prints a summary of passed/failed checks.
8. Restores the cluster to `operator` mode.
9. Cleans up the test namespace and tears down the kind cluster (unless
   `--reuse-cluster`).

## Interpreting Results

The script uses colored output:

- `[PASS]` (green) — Check succeeded.
- `[FAIL]` (red) — Check failed.
- `[WARN]` (yellow) — Non-fatal observation (e.g., identity ID changed but
  pod still has a valid identity).
- `[INFO]` (blue) — Informational log.

At the end, a summary is printed:

```
Passed: 354
Failed: 0

ALL TESTS PASSED

All upgrade and rollback paths produce identical behavior:
  - Existing connections preserved across upgrades and rollbacks
  - Identities preserved through upgrade and rollback cycles
  - New pods get identities in all modes
  - Cross-generation connectivity works
  - Restart order (operator-first / agent-first / both) has no impact
  - Rollback from operator/both to agent is seamless
```

Exit code is the number of failures (0 = success).

### Latest Test Results

Run on a kind cluster (2 nodes) with Cilium `1.20.0-dev`. Server identity=63377,
client identity=3963 remained stable across all 12 test paths.

| # | Test Path | Checks Passed | Checks Failed | Result |
|---|-----------|:---:|:---:|:---:|
| 1 | agent → operator (restart: operator-first) | 25 | 0 | **PASS** |
| 2 | agent → operator (restart: agent-first) | 25 | 0 | **PASS** |
| 3 | agent → operator (restart: both) | 25 | 0 | **PASS** |
| 4 | agent → both (restart: operator-first) | 25 | 0 | **PASS** |
| 5 | agent → both (restart: agent-first) | 25 | 0 | **PASS** |
| 6 | agent → both (restart: both) | 25 | 0 | **PASS** |
| 7 | agent → operator → agent (rollback: operator-first) | 34 | 0 | **PASS** |
| 8 | agent → operator → agent (rollback: agent-first) | 34 | 0 | **PASS** |
| 9 | agent → operator → agent (rollback: both) | 34 | 0 | **PASS** |
| 10 | agent → both → agent (rollback: operator-first) | 34 | 0 | **PASS** |
| 11 | agent → both → agent (rollback: agent-first) | 34 | 0 | **PASS** |
| 12 | agent → both → agent (rollback: both) | 34 | 0 | **PASS** |
| | **Total** | **354** | **0** | **ALL PASS** |

## Key Terminology

**Cross-generation connectivity**
: Testing traffic between pods created *before* the upgrade (old generation)
  and pods created *after* the upgrade (new generation). This validates that
  identity resolution works correctly across the mode switch boundary — both
  old-to-new and new-to-old directions.

**Identity preservation**
: The numeric identity ID assigned to a pod remains the same after the
  upgrade. This means the BPF datapath does not need to be reprogrammed and
  existing flows are unaffected.

**Restart ordering**
: In production, operators cannot control whether the agent daemonset or the
  operator deployment restarts first during a rolling upgrade. The three
  orderings test that the system is resilient regardless of which component
  picks up the new configuration first.

**Rollback**
: Reverting from `operator` or `both` mode back to `agent` mode. The
  rollback tests verify that the agent correctly resumes identity allocation
  after the operator previously owned it, and that all existing identities and
  connections survive the transition.

## Troubleshooting

**Test hangs during `helm upgrade --wait`**
: Check `kubectl get pods -n kube-system` for crashlooping pods. Increase
  the timeout by editing `--timeout 300s` in the script.

**Connectivity failures after upgrade**
: Inspect `cilium-dbg status` on the agent pod's node. Check that the
  endpoint has a valid identity with `kubectl get ciliumendpoints -n identity-upgrade-test`.

**Identity allocation timeout errors**
: These appear when the agent is in operator/both mode but the operator has
  not yet created the CiliumIdentity CRD. The 15-second reconciliation wait
  in Phase 2 should cover this. If not, increase the `sleep 15`.

# Tenant Cluster Setup Guide

## Overview

Connect your Kubernetes cluster (or Linux VM) to the Abluva platform in minutes. This guide walks you through generating a bootstrap token from the platform UI and running a single script to set up the secure connection and launcher.

Do not commit `ca.crt`, bootstrap tokens, or filled env files.

---

## Step 1: Generate Token

1. Log in to the **Abluva Tenant App**
2. Open **Subscriptions**, open this subscription, go to the **Connect Agent** step (after Assign SKUs, Environments, Membership)
3. Choose **Flavor** — **Kubernetes** or **VM / bare metal**
4. Set **Node count** (Kubernetes) or **Host count** (VM) — at least `1`
5. Optionally set **Max tunnels** (≥ the count; blank defaults to `50`) and click **Save max tunnels**
6. Click **Generate token**, then **Copy**

> **Note**: The token is shown only once and lasts about 7 days. Generating again replaces the previous token. Complete the setup promptly after generating it.

---

## Step 2: Get CA, Install File, Namespace, Tenant ID, and Environment ID

On the same **Connect Agent** step:

### CA certificate
1. Click **Fetch and copy** or **Download**
2. Save as `ca.crt`

### Install file
1. Click **Copy** or **Download** under **Install**
2. Save as `tenant-start.env` (Kubernetes) or `fabric-edge.env` (VM)

That file already includes gateway address, control-plane URL, namespace, tenant ID, environment ID, and a place for the bootstrap token.

### Namespace, Tenant ID, Environment ID
Confirm these from the Install file (or the Environments / Tenants pages if you need them elsewhere):

- **Namespace** — `TENANT_NAMESPACE` (Kubernetes) or `fabric-edge` (VM appliance)
- **Tenant ID** — `TENANT_ID`
- **Environment ID** — `ENVIRONMENT_ID`

Save these values — you'll need them for verification and resource registration.

---

## Step 3: Prerequisites

Ensure the following on the machine where you'll run the setup:

- [ ] **Kubernetes cluster** with access to create namespaces, Secrets, DaemonSets, Deployments, Services, Roles, and NetworkPolicies (Kubernetes path)
- [ ] **kubectl** installed and configured (Kubernetes), or a Linux host for the VM appliance
- [ ] **python3** (Kubernetes installer)
- [ ] **Network connectivity** — nodes must reach the Abluva platform gateway (`FABRIC_GATEWAY_ADDRESS`, typically TCP **8443**) and control plane (`FABRIC_CONTROL_PLANE_URL`, typically HTTPS **443**)
- [ ] **`ca.crt`** from Step 2
- [ ] **Install env file** from Step 2 (`tenant-start.env` or `fabric-edge.env`) with `BOOTSTRAP_TOKEN` set

---

## Step 4: Clone the Setup Repository

```bash
git clone https://github.com/abluva/secure-agent-net.git
cd secure-agent-net
```

Layout used by this guide:

```
connect-agent/kubernetes/          tenant-start.sh
connect-agent/vm/k3s-appliance/    install.sh
agent/agent-deployment.yaml        launcher + agent-svc
```

---

## Step 5: Configure Agent Deployment

`agent/agent-deployment.yaml` uses placeholders. The installer replaces only these three:

- `<tenant-namespace>`
- `<tenantId>`
- `<envid>`

Everything else in that file (including SaaS control-server URL and SaaS IDs) is used as-is. You do not paste a SaaS API key into the launcher YAML.

Put `ca.crt` and the Install env file next to the script you will run (Step 6). Ensure `BOOTSTRAP_TOKEN` and `ENVIRONMENT_ID` are set in the env file.

---

## Step 6: Run the Setup Script

### Kubernetes

```bash
cd connect-agent/kubernetes
# ca.crt and tenant-start.env in this directory
chmod +x tenant-start.sh
./tenant-start.sh ./tenant-start.env
```

### VM / bare metal

```bash
cd connect-agent/vm/k3s-appliance
# ca.crt and fabric-edge.env in this directory
chmod +x install.sh
sudo ./install.sh --env-file=./fabric-edge.env
```

---

## What the Script Does

| Step | Action | Notes |
|------|--------|-------|
| 1 | Create tenant namespace | Label `abluva.io/tenant=true` (Kubernetes). VM appliance uses `fabric-edge`. |
| 2 | Create secrets | CA + bootstrap material for the Connect Agent |
| 3 | Deploy Connect Agent | DaemonSet — Agent dials **out** to the platform gateway and control plane (no Skupper site, MetalLB, or link-token redeem) |
| 4 | Deploy launcher | Applies `agent/agent-deployment.yaml` → `Deployment/agent` + `Service/agent-svc:5004` |
| 5 | Apply NetworkPolicy | Same-ns + Abluva SaaS ns; opt-in cross-tenant with `abluva.io/cross-tenant=true` |
| 6 | Wait for Agent | Waits until `daemonset/connect-agent` is ready |

---

## Step 7: Verify Setup

### Kubernetes

```bash
NAMESPACE=<your-tenant-namespace>

kubectl get pods -n $NAMESPACE
kubectl get daemonset connect-agent -n $NAMESPACE
kubectl get svc agent-svc -n $NAMESPACE
```

### VM / bare metal

```bash
k3s kubectl -n fabric-edge get pods
k3s kubectl -n fabric-edge get svc agent-svc
```

In the Abluva app, confirm the Agent shows **Connected** on the **Connect Agent** step before creating registrations.

---

## Step 8: Customer Registrations

Back on **Connect Agent** → **Customer registrations** → **Add registrations**.

| Row | Host | Port |
|---|---|---|
| launcher | `agent-svc` | `5004` |

**Create** stays disabled until an Agent is Connected. After a successful create, the page lists each name and status.

---

## Step 9: Register Resource in Platform

After the agent is deployed and verified:

1. Navigate to **Resources** → **Register Resource**
2. Give a **Resource Name** (e.g. `agent-launcher`)
3. Choose Resource Type: `agent#https`
4. Choose **Credentials** as Authentication Type
5. In the JSON box, add:

```json
{
  "serviceUrl": "http://agent-svc.<namespace>.svc.cluster.local:5004"
}
```

Replace `<namespace>` with your tenant namespace (`TENANT_NAMESPACE` from the Install file, or `fabric-edge` for the VM appliance).

6. Click **Create Resource**

---

## Service Endpoint Available

Once connected, these endpoints are available in your cluster:

| Service | URL from your cluster | Purpose |
|---------|----------------------|---------|
| Launcher | `http://agent-svc.<namespace>.svc.cluster.local:5004` | Customer launcher |
| Connect Agent | `connect-agent.<namespace>.svc.cluster.local:<port>` | Local listeners for Active registrations (ports managed by the Agent) |

---

## Troubleshooting

### Create registrations stays disabled

**Cause**: No Agent is Connected yet.

**Fix**: Wait until Step 7 shows Connected pods / Connected status in the UI, then retry **Create**.

### Agent pods CrashLoop or Pending

**Cause**: Missing bootstrap token, wrong CA, or nodes cannot reach the platform gateway / control plane.

**Fix**: Confirm `BOOTSTRAP_TOKEN` and `ca.crt`, and that `FABRIC_GATEWAY_ADDRESS` / `FABRIC_CONTROL_PLANE_URL` from the Install file are reachable from the cluster nodes.

### Launcher cannot reach control-server

**Cause**: Short service name used instead of the SaaS control-server FQDN, or wrong SaaS namespace.

**Fix**: Keep the filled `INFRA_BASE_URL` in `agent/agent-deployment.yaml` as shipped (FQDN). Do not replace it with a short name from the tenant namespace.

### Agent image pull error

**Cause**: Your cluster can't reach the container registry.

**Fix**: Contact Abluva support for alternative image delivery or configure registry trust.

### Request hangs (timeout)

**Cause**: Egress blocked to the platform NLB or control plane, or NetworkPolicy too tight for your workload path.

**Fix**: Verify outbound TCP to gateway **8443** and control-plane HTTPS. Contact Abluva support if platform-side ACLs are suspected.

---

## Support

If you encounter issues, contact Abluva support.

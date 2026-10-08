# Abluva Connect Agent and launcher

Install the Connect Agent and launcher on your Kubernetes cluster or Linux VM. Values come from the Abluva app. Do not commit `ca.crt`, bootstrap tokens, or filled env files.

## Layout

```
connect-agent/kubernetes/          tenant-start.sh
connect-agent/vm/k3s-appliance/    install.sh
agent/agent-deployment.yaml        launcher + agent-svc
```

The installers replace only `<tenant-namespace>`, `<tenantId>`, and `<envid>` in the agent YAML. Everything else in that file is used as-is.

---

## In the Abluva app (before clone)

Open **Subscriptions**, open this subscription, go to the **Connect Agent** step (after Assign SKUs, Environments, Membership).

1. **Flavor** — **Kubernetes** or **VM / bare metal**.
2. **Node count** (Kubernetes) or **Host count** (VM) — at least `1`.
3. **Max tunnels** — optional; must be ≥ the count; blank defaults to `50`. Click **Save max tunnels**.
4. **Bootstrap token** — **Generate token**, then **Copy**. The page says the token is shown only once and lasts about 7 days. Hover on **Generate token**: generating again replaces the previous token.
5. **CA** — **Fetch and copy** or **Download**. Save as `ca.crt`.
6. **Install** — **Copy** or **Download**. That file is `tenant-start.env` (Kubernetes) or `fabric-edge.env` (VM).

---

## Clone

```bash
git clone https://github.com/abluva/secure-agent-net.git
cd secure-agent-net
```

---

## Kubernetes

```bash
cd connect-agent/kubernetes
```

Put `ca.crt` and `tenant-start.env` in this directory.

```bash
chmod +x tenant-start.sh
./tenant-start.sh ./tenant-start.env
```

Needs `kubectl` and `python3`. The script creates the namespace (label `abluva.io/tenant=true`), secrets, Connect Agent DaemonSet, applies `../../agent/agent-deployment.yaml`, applies NetworkPolicy (same-ns + Abluva SaaS ns; opt-in cross-tenant with `abluva.io/cross-tenant=true`), then waits on `daemonset/connect-agent`.

```bash
kubectl -n <TENANT_NAMESPACE> get pods
kubectl -n <TENANT_NAMESPACE> get svc agent-svc
```

---

## VM / bare metal

```bash
cd connect-agent/vm/k3s-appliance
```

Put `ca.crt` and `fabric-edge.env` in this directory. `ENVIRONMENT_ID` must be set (the Install file from the app includes it).

```bash
chmod +x install.sh
sudo ./install.sh --env-file=./fabric-edge.env
```

This installs k3s if needed, deploys Connect Agent in `fabric-edge`, then applies `agent/agent-deployment.yaml` in the same namespace.

```bash
k3s kubectl -n fabric-edge get pods
k3s kubectl -n fabric-edge get svc agent-svc
```

---

## Customer registrations

Back on **Connect Agent** → **Customer registrations** → **Add registrations**.

Fill **Host** and **Port** (placeholders on the form):

| Row | Host | Port |
|---|---|---|
| launcher | `agent-svc` | `5004` |

**Create** stays disabled until an Agent is Connected (hover on **Create**). After a successful create, the page lists each name and status.

---

## Launcher resource

Open **Resources** → **Register Resource**.

**Basic Details**

- **Resource Name** — e.g. `agent-launcher`
- **Resource Type** — `agent#https`

**Authentication**

- **Type** — credentials
- **Configuration (JSON)**:

```json
{
  "serviceUrl": "http://agent-svc.<TENANT_NAMESPACE>.svc.cluster.local:5004"
}
```

Use `TENANT_NAMESPACE` from `tenant-start.env`, or `fabric-edge` for the VM appliance.

Click **Create Resource**.

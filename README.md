# SNO Deployer – Deployment Flow

This README describes how the **simplified Single Node OpenShift (SNO) deployer** works and how to run it. The script is `sno_deploy.py`; it uses a single config file and the Assisted Installer to deploy one SNO cluster in a VM on the same host.

Based on https://github.com/bn222/cluster-deployment-automation

---

## Setup
```bash
dnf install -y python3.11
python3.11 -m venv ocp-venv
source ocp-venv/bin/activate
./dependencies.sh
usermod -a -G root qemu
```

```bash
# From repo root, with Python venv activated (e.g. source ocp-venv/bin/activate)
python sno_deploy.py deploy --config sno_config.yaml
```

Use the same `sno_config.yaml` as in the repo (customize `name`, `version`, `master.ip`, `bridge` as needed). Put your pull secret at the path set in `pull_secret` (e.g. `./pull_secret.json`).

**Other commands:**

```bash
# Resume after a failure (skips completed steps)
python sno_deploy.py deploy --config sno_config.yaml --resume

# Remove the cluster and VM; keep the AI pod
python sno_deploy.py teardown --config sno_config.yaml

# Remove the cluster, VM, and stop the AI pod
python sno_deploy.py teardown --config sno_config.yaml --full

# Show saved state for this cluster
python sno_deploy.py state --config sno_config.yaml
```

---

## Deployment flow (high level)

The deploy runs in a fixed order. Steps are **saved in a state file** so you can re-run with `--resume` and skip what already completed.

```
1. Ensure SSH key exists (~/.ssh/id_ed25519)
2. Configure Libvirt (modular services, QEMU as root)
3. Configure virbr0 (default network: IP, DHCP range)
4. Start Assisted Installer pod (Podman); wait for DB and API
5. Deploy SNO master (one block; all or nothing on resume):
   a.  Delete any existing cluster in AI with same name
   b.  Create cluster in AI (SNO, version, domain, pull secret)
   c.  Create infraenv (cluster name + "-x86_64")
   d.  Download discovery ISO from AI image service
   e.  Add static DHCP entry for the VM (name, IP, MAC)
   f.  Create VM disk and start VM (virt-install, discovery ISO)
   g.  Wait until the host shows in AI as "known"
   h.  Start cluster installation in AI
   i.  Download kubeconfig and kubeadmin password
   j.  Wait for host to enter "Rebooting", then wait for VM down/up
   k.  Wait for cluster status "installed"
   l.  Update /etc/hosts and dnsmasq for API DNS
   m.  Set root password on the node via SSH
   n.  Mark "masters" done in state file
```

- **Steps 2–4** are idempotent and each has its own state key (`libvirt`, `bridge`, `ai-started`). If already done, they are skipped on the next run when using `--resume`.
- **Step 5** is a single state key `masters`. Once marked, the whole SNO deploy is skipped on resume. If you run without `--resume`, the state is cleared and step 5 runs from scratch (after 2–4 if they were not yet done).

**Network:** The script uses the default Libvirt network (virbr0). The bridge IP (e.g. `192.168.122.1`) is where the AI API and image service listen. The VM gets a static IP on that network via DHCP reservation so the script and AI can reach it.

---

## What gets created

| Item | Where / meaning |
|------|------------------|
| Cluster + infraenv | In the Assisted Installer API (deleted on teardown) | | Discovery ISO | `/tmp/sno_iso/<cluster_name>/<cluster_name>-x86_64.iso` | | VM disk | `/home/sno_guests_images/<cluster_name>/<master_name>.qcow2` | | Kubeconfig | Current directory `kubeconfig.<cluster_name>` or path in config |
| State | `/tmp/sno_state.json` (keyed by cluster name) |

---

## Config file

See `sno_config.yaml` in the repo. Main fields:

- **name** – Cluster name (used in AI, DNS, paths).
- **version** – OpenShift version (e.g. `4.19.0-nightly`, `4.14.0`).
- **master** – `name`, `ip`, `mac`, `cpu`, `ram`, `disk_size` (and optional `os_variant`).
- **bridge** – `ip`, `mask`, `dhcp_range` for virbr0.
- **pull_secret** – Path to `pull_secret.json`.
- **base_dns_domain**, **ntp_source** – Used for the cluster.
- Optional: **kubeconfig**, **proxy**, **noproxy**.

---

## After a successful deploy

```bash
export KUBECONFIG=./kubeconfig.<cluster_name>   # or path from config
oc get nodes
```

The node will show as control-plane and worker (SNO). Root password on the VM is set to `redhat` (see config/logs for user).

---

## More detail

- **Debugging commands by phase:** [README_SNO_DEBUG.md](README_SNO_DEBUG.md)

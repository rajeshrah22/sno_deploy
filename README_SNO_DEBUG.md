# SNO Deployer – Debugging Commands by Lifecycle Phase

Use this as a checklist while running `python sno_deploy.py deploy --config sno_config.yaml`. Set these from your `sno_config.yaml` and run the commands for the phase you're in.

**aicli** is used for all Assisted Installer (AI) API checks. Use the same Python env as `sno_deploy.py` (e.g. `source ocp-venv/bin/activate`). Set the AI URL once so you can omit `--url` on every command:

```bash
# Set from your sno_config.yaml
CLUSTER=vm-sno
BRIDGE_IP=192.168.122.1
MASTER_NAME=sno-master
MASTER_IP=192.168.122.41
INFRA_ENV="${CLUSTER}-x86_64"

# Optional: point aicli at your on-prem AI (then you can run "aicli list cluster" etc. without --url)
export AI_URL="http://${BRIDGE_IP}:8090"
# Or pass each time: aicli --url "http://${BRIDGE_IP}:8090" <command>
```

---

## Before deploy

| Check | Command |
|-------|--------|
| Config exists | `test -f sno_config.yaml && echo ok` |
| Pull secret exists | `test -f ./pull_secret.json && echo ok` |
| SSH key (script will create if missing) | `ls -la ~/.ssh/id_ed25519 2>/dev/null \|\| echo "no key"` |
| Libvirt default network | `virsh net-list --all` |
| virbr0 exists | `ip link show virbr0` |

---

## 1. After "Configuring libvirt"

| Check | Command |
|-------|--------|
| Modular libvirt services | `systemctl is-active virtqemud.service virtnetworkd.service` |
| QEMU runs as root | `grep -E '^\s*user|^\s*group' /etc/libvirt/qemu.conf` |

---

## 2. After "Configuring virbr0 bridge"

| Check | Command |
|-------|--------|
| Bridge is up | `ip addr show virbr0` |
| Bridge IP matches config | `ip addr show virbr0 \| grep "inet "` |
| Default network XML | `virsh net-dumpxml default` |
| DHCP range in XML | `virsh net-dumpxml default \| grep -A2 dhcp` |

---

## 3. After "Starting Assisted Installer" (AI pod)

| Check | Command |
|-------|--------|
| AI pod running | `podman pod ps \| grep assisted-installer` |
| AI containers | `podman ps -a --format "{{.Names}} {{.Status}}" \| grep assisted` |
| DB has release images | `podman exec assisted-installer-db psql -d installer -c "SELECT version FROM release_images;"` |
| API responds (aicli) | `aicli --url "http://${BRIDGE_IP}:8090" list cluster` |
| Image service (for ISO; no aicli) | `curl -s -o /dev/null -w "%{http_code}" "http://${BRIDGE_IP}:8888/health"` |
| AI logs (if issues) | `podman logs assisted-installer-service 2>&1 \| tail -100` |

---

## 4. After "Creating cluster"

| Check | Command |
|-------|--------|
| List clusters | `aicli --url "http://${BRIDGE_IP}:8090" list cluster` |
| Cluster info (status, id) | `aicli --url "http://${BRIDGE_IP}:8090" info cluster $CLUSTER` |

---

## 5. After "Creating infraenv"

| Check | Command |
|-------|--------|
| ISO info (implies infraenv ready) | `aicli --url "http://${BRIDGE_IP}:8090" info iso $CLUSTER` |

---

## 6. During / after "Download ISO"

| Check | Command |
|-------|--------|
| ISO directory | `ls -la /tmp/sno_iso/${CLUSTER}/` |
| ISO file present | `ls -la /tmp/sno_iso/${CLUSTER}/${INFRA_ENV}.iso` |
| ISO size (non-zero) | `stat -c "%s" /tmp/sno_iso/${CLUSTER}/${INFRA_ENV}.iso` |
| ISO URL / info (aicli) | `aicli --url "http://${BRIDGE_IP}:8090" info iso $CLUSTER` |
| Manual download (aicli, to cwd) | `aicli --url "http://${BRIDGE_IP}:8090" download iso $CLUSTER` |
| Manual download (curl to image service) | `INFRA_ID=$(curl -s "http://${BRIDGE_IP}:8090/api/assisted-install/v2/infra-envs" \| jq -r ".[] \| select(.name==\"$INFRA_ENV\") \| .id"); curl -v -o /tmp/test.iso "http://${BRIDGE_IP}:8888/api/assisted-images/images/${INFRA_ID}/discovery-image" 2>&1 \| tail -20` |

---

## 7. After "Setup DHCP entry" / "Starting VM"

| Check | Command |
|-------|--------|
| DHCP host entry | `virsh net-dumpxml default \| grep -A1 "ip-dhcp-host"` |
| VM disk exists | `ls -la /home/sno_guests_images/${CLUSTER}/${MASTER_NAME}.qcow2` |
| VM defined | `virsh list --all \| grep $MASTER_NAME` |
| VM state | `virsh dominfo $MASTER_NAME \| grep State` |
| VM is running | `virsh list \| grep $MASTER_NAME` |

---

## 8. "Waiting for host to reach known state"

| Check | Command |
|-------|--------|
| List hosts (status, status_info) | `aicli --url "http://${BRIDGE_IP}:8090" list hosts $CLUSTER` |
| Wait for 1 host (optional) | `aicli --url "http://${BRIDGE_IP}:8090" wait hosts $CLUSTER -n 1` |
| Ping master | `ping -c 1 $MASTER_IP` |
| SSH to discovery (core) | `ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 core@$MASTER_IP true && echo "SSH ok"` |

---

## 9. "Starting cluster installation" / cluster "installing"

| Check | Command |
|-------|--------|
| Cluster status | `aicli --url "http://${BRIDGE_IP}:8090" info cluster $CLUSTER` |
| Host status | `aicli --url "http://${BRIDGE_IP}:8090" list hosts $CLUSTER` |
| Cluster events | `aicli --url "http://${BRIDGE_IP}:8090" get events cluster $CLUSTER` |

---

## 10. After "Download kubeconfig" / "Waiting for master to reboot"

| Check | Command |
|-------|--------|
| Kubeconfig on disk | `ls -la ./kubeconfig.${CLUSTER} 2>/dev/null \|\| ls -la /root/kubeconfig.${CLUSTER} 2>/dev/null` |
| Host status (expect Rebooting) | `aicli --url "http://${BRIDGE_IP}:8090" list hosts $CLUSTER` |
| VM state (will go down then up) | `virsh dominfo $MASTER_NAME \| grep State` |
| VM list | `virsh list --all \| grep $MASTER_NAME` |

---

## 11. "Wait for cluster installed"

| Check | Command |
|-------|--------|
| Cluster status (expect "installed") | `aicli --url "http://${BRIDGE_IP}:8090" info cluster $CLUSTER` |
| Host status (expect "installed") | `aicli --url "http://${BRIDGE_IP}:8090" list hosts $CLUSTER` |
| Wait for install to complete (blocking) | `aicli --url "http://${BRIDGE_IP}:8090" wait $CLUSTER` |

---

## 12. After "Update /etc/hosts" and "Set root password"

| Check | Command |
|-------|--------|
| API in /etc/hosts | `grep "$CLUSTER" /etc/hosts` |
| dnsmasq servers file | `cat /etc/dnsmasq.d/servers/cda-servers.conf 2>/dev/null \| head -20` |
| SSH as core | `ssh -o StrictHostKeyChecking=no core@$MASTER_IP whoami` |
| SSH as root (after password set) | `ssh -o StrictHostKeyChecking=no root@$MASTER_IP whoami` |
| KUBECONFIG and oc | `export KUBECONFIG=./kubeconfig.${CLUSTER}; oc get nodes` |
| Download kubeconfig (aicli, to cwd) | `aicli --url "http://${BRIDGE_IP}:8090" download kubeconfig $CLUSTER` |

---

## 13. State file (resume / debugging)

| Check | Command |
|-------|--------|
| Current state | `python sno_deploy.py state --config sno_config.yaml` |
| State file path | `cat /tmp/sno_state.json 2>/dev/null \| jq .` |

---

## 14. Teardown

| Check | Command |
|-------|--------|
| List clusters (should not show $CLUSTER after delete) | `aicli --url "http://${BRIDGE_IP}:8090" list cluster` |
| Delete cluster via aicli | `aicli --url "http://${BRIDGE_IP}:8090" delete cluster $CLUSTER` |
| VM gone | `virsh list --all \| grep $MASTER_NAME` |
| DHCP entry removed | `virsh net-dumpxml default \| grep $MASTER_NAME` |
| AI pod (if --full) | `podman pod ps \| grep assisted` |

---

## One-shot: full host + cluster status (aicli)

```bash
CLUSTER=vm-sno
BRIDGE_IP=192.168.122.1
MASTER_NAME=sno-master

export AI_URL="http://${BRIDGE_IP}:8090"

echo "=== Clusters ==="
aicli list cluster

echo "=== Cluster info ==="
aicli info cluster $CLUSTER

echo "=== Hosts ==="
aicli list hosts $CLUSTER

echo "=== VM ==="
virsh dominfo $MASTER_NAME 2>/dev/null | grep -E "Name|State" || echo "VM not found"
```

---

## Enable verbose script logging

To see every command the script runs (e.g. `run()` at DEBUG):

- Edit `sno_deploy.py` and set `level=logging.DEBUG` in `logging.basicConfig(...)` (around line 52), or
- Add a `--debug` flag that sets the level to DEBUG.

Then run:

```bash
python sno_deploy.py deploy --config sno_config.yaml 2>&1 | tee deploy.log
```

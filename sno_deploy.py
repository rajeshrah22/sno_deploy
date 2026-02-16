#!/usr/bin/env python3
"""
Simplified Single Node OpenShift (SNO) Deployer.

Self-contained script that deploys an SNO cluster on localhost using the
Assisted Installer.  No multi-host, worker, BlueField, DPU, or multi-arch
support.  Replaces paramiko with subprocess ssh.

Usage:
    python sno_deploy.py deploy   --config sno_config.yaml
    python sno_deploy.py deploy   --config sno_config.yaml --resume
    python sno_deploy.py teardown --config sno_config.yaml
    python sno_deploy.py teardown --config sno_config.yaml --full
    python sno_deploy.py state    --config sno_config.yaml
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import fcntl
import glob
import hashlib
import itertools
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, IO, Iterator, Optional, Union

import requests
import yaml
from ailib import AssistedClient
from python_hosts import Hosts, HostsEntry
from requests import get as get_url


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("sno")


def error_and_exit(msg: str) -> None:
    logger.error(msg)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Shell helpers (replaces host.py -- no paramiko)
# ---------------------------------------------------------------------------

@dataclass
class Result:
    out: str
    err: str
    returncode: int

    def success(self) -> bool:
        return self.returncode == 0

    def __str__(self) -> str:
        return f"(rc={self.returncode}, err={self.err!r})"


def run(cmd: str, log_level: int = logging.DEBUG) -> Result:
    """Run a command locally via subprocess."""
    logger.log(log_level, f"$ {cmd}")
    args = shlex.split(cmd)
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
        out_b, err_b = proc.communicate()
        rc = proc.returncode
    out = out_b.decode("utf-8", errors="replace")
    err = err_b.decode("utf-8", errors="replace")
    logger.log(log_level, f"  -> rc={rc}")
    return Result(out, err, rc)


def run_or_die(cmd: str, log_level: int = logging.DEBUG) -> Result:
    r = run(cmd, log_level)
    if not r.success():
        error_and_exit(f"Command failed: {cmd}\n  stderr: {r.err}")
    return r


def ssh_run(ip: str, user: str, cmd: str) -> Result:
    """Run a command on a remote host via subprocess ssh (no paramiko)."""
    ssh_cmd = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        f"{user}@{ip}",
        cmd,
    ]
    logger.debug(f"ssh {user}@{ip}: {cmd}")
    proc = subprocess.run(ssh_cmd, capture_output=True, text=True)
    return Result(proc.stdout, proc.stderr, proc.returncode)


def ssh_run_or_die(ip: str, user: str, cmd: str) -> Result:
    r = ssh_run(ip, user, cmd)
    if not r.success():
        error_and_exit(f"SSH command failed on {ip}: {cmd}\n  stderr: {r.err}")
    return r


def wait_ssh(ip: str, user: str = "core", timeout_minutes: int = 60) -> None:
    """Wait until SSH is reachable."""
    deadline = time.time() + timeout_minutes * 60
    while time.time() < deadline:
        r = ssh_run(ip, user, "true")
        if r.success():
            return
        time.sleep(10)
    error_and_exit(f"Timeout waiting for SSH on {ip}")


# ---------------------------------------------------------------------------
# Timer / StopWatch  (inlined from timer.py)
# ---------------------------------------------------------------------------

def duration_to_str(duration: float) -> str:
    days = int(duration // 86400)
    hours = int((duration % 86400) // 3600)
    minutes = int((duration % 3600) // 60)
    seconds = round(duration % 60, 2)
    s = ""
    if days > 0:
        s += f"{days}d"
    if hours > 0:
        s += f"{hours}h"
    if minutes > 0:
        s += f"{minutes}m"
    s += f"{seconds:.2f}s"
    return s


def str_to_duration_float(duration: str) -> float:
    pattern = r"(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?"
    m = re.fullmatch(pattern, duration)
    if not m:
        raise ValueError(f"Invalid time format: {duration}")
    days, hours, minutes, seconds = (float(x or 0) for x in m.groups())
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


class Timer:
    def __init__(self, target_duration: str) -> None:
        self._start = time.time()
        self._d = str_to_duration_float(target_duration)

    def triggered(self) -> bool:
        return (time.time() - self._start) >= self._d

    def elapsed(self) -> str:
        return duration_to_str(min(time.time() - self._start, self._d))

    def target_duration(self) -> str:
        return duration_to_str(self._d)


class StopWatch:
    def __init__(self) -> None:
        self._start = 0.0
        self._end = 0.0
        self._stopped = False

    def start(self) -> None:
        self._start = time.time()
        self._end = self._start
        self._stopped = False

    def stop(self) -> None:
        self._end = time.time()
        self._stopped = True

    def __str__(self) -> str:
        current = self._end if self._stopped else time.time()
        return duration_to_str(current - self._start)


# ---------------------------------------------------------------------------
# State file  (inlined from state_file.py)
# ---------------------------------------------------------------------------

class StateFile:
    def __init__(self, cluster_name: str, path: str = "/tmp/sno_state.json") -> None:
        self.cluster_name = cluster_name
        self.path = path

    def _load(self) -> dict[str, dict[str, str]]:
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                data = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
                return data
        return {}

    def _save(self, state: dict[str, dict[str, str]]) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(state, f)
            f.flush()
            os.fsync(f.fileno())
            fcntl.flock(f, fcntl.LOCK_UN)

    def deployed(self, step: str) -> bool:
        state = self._load()
        cn = self.cluster_name
        return cn in state and step in state[cn] and state[cn][step] == "deployed"

    def mark(self, step: str, value: str = "deployed") -> None:
        state = self._load()
        state.setdefault(self.cluster_name, {})[step] = value
        self._save(state)

    def clear(self) -> None:
        state = self._load()
        state.pop(self.cluster_name, None)
        self._save(state)

    def __str__(self) -> str:
        return json.dumps(self._load(), indent=4)


# ---------------------------------------------------------------------------
# Common utilities  (inlined from common.py)
# ---------------------------------------------------------------------------

def wait_true(name: str, func: Callable[..., bool], timeout: str = "45m", interval: float = 30, **kwargs: Any) -> bool:
    logger.info(f"Waiting for {name}")
    t = Timer(timeout)
    for try_count in itertools.count(0):
        if func(**kwargs):
            logger.info(f"Took {try_count} tries for {name}")
            return True
        if t.triggered():
            logger.warning(f"Timeout after {t.elapsed()} for {name} (tried {try_count} times)")
            return False
        time.sleep(interval)
    return False


def iterate_ssh_keys() -> Iterator[tuple[str, str, str]]:
    for pub_file in glob.glob("/root/.ssh/*.pub"):
        with open(pub_file, "r") as f:
            pub_key = f.read().strip()
        priv_key = os.path.splitext(pub_file)[0]
        yield pub_file, pub_key, priv_key


def kubeconfig_get_paths(cluster_name: str, kubeconfig_path: Optional[str] = None) -> tuple[str, str, str, str]:
    if kubeconfig_path:
        kubeconfig_path = os.path.abspath(kubeconfig_path)
        path = os.path.dirname(kubeconfig_path)
    else:
        path = os.path.abspath(os.getcwd())
    downloaded_kubeconfig = f"{path}/kubeconfig.{cluster_name}"
    downloaded_kubeadmin = f"{path}/kubeadmin-password.{cluster_name}"
    if not kubeconfig_path:
        kubeconfig_path = downloaded_kubeconfig
    return path, kubeconfig_path, downloaded_kubeconfig, downloaded_kubeadmin


@contextlib.contextmanager
def atomic_write(filename: str, *, text: bool = True, mode: int = 0o644) -> Iterator[Any]:
    path = os.path.dirname(filename) or "."
    os.makedirs(path, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(filename) + ".", dir=path, text=text)
    try:
        with os.fdopen(fd, "w" if text else "wb") as f:
            yield f
        os.chmod(tmp, mode)
        os.rename(tmp, filename)
        tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


def vm_is_running(name: str) -> bool:
    r = run(f"virsh dominfo {name}", logging.DEBUG)
    return r.success() and re.search(r"State:.*running", r.out) is not None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class MasterConfig:
    name: str
    ip: str
    mac: str
    cpu: int = 8
    ram: int = 32768
    disk_size: int = 48
    os_variant: str = "rhel9.4"


@dataclass
class BridgeConfig:
    ip: str = "192.168.122.1"
    mask: str = "255.255.0.0"
    dhcp_range: str = "192.168.122.100,192.168.122.254"


@dataclass
class SNOConfig:
    name: str
    version: str
    base_dns_domain: str
    ntp_source: str
    pull_secret: str
    master: MasterConfig
    bridge: BridgeConfig
    kubeconfig: Optional[str] = None
    proxy: Optional[str] = None
    noproxy: Optional[str] = None

    @property
    def image_dir(self) -> str:
        return f"/home/sno_guests_images/{self.name}"

    @property
    def image_path(self) -> str:
        return os.path.join(self.image_dir, f"{self.master.name}.qcow2")

    @property
    def iso_dir(self) -> str:
        return f"/tmp/sno_iso/{self.name}"


def load_config(path: str) -> SNOConfig:
    with open(path) as f:
        raw = yaml.safe_load(f)

    master_raw = raw.get("master", {})
    bridge_raw = raw.get("bridge", {})

    master = MasterConfig(
        name=master_raw["name"],
        ip=master_raw["ip"],
        mac=master_raw["mac"],
        cpu=master_raw.get("cpu", 8),
        ram=master_raw.get("ram", 32768),
        disk_size=master_raw.get("disk_size", 48),
        os_variant=master_raw.get("os_variant", "rhel9.4"),
    )

    dhcp = bridge_raw.get("dhcp_range", "192.168.122.100,192.168.122.254")
    # Accept both "start,end" and "start-end"
    dhcp = dhcp.replace("-", ",") if "-" in dhcp else dhcp
    bridge = BridgeConfig(
        ip=bridge_raw.get("ip", "192.168.122.1"),
        mask=bridge_raw.get("mask", "255.255.0.0"),
        dhcp_range=dhcp,
    )

    return SNOConfig(
        name=raw["name"],
        version=raw["version"],
        base_dns_domain=raw.get("base_dns_domain", "redhat.com"),
        ntp_source=raw.get("ntp_source", "clock.redhat.com"),
        pull_secret=raw.get("pull_secret", "./pull_secret.json"),
        master=master,
        bridge=bridge,
        kubeconfig=raw.get("kubeconfig"),
        proxy=raw.get("proxy"),
        noproxy=raw.get("noproxy"),
    )


# ---------------------------------------------------------------------------
# Libvirt configuration  (simplified from libvirt.py)
# ---------------------------------------------------------------------------

MODULAR_SERVICES = ["qemu", "interface", "network", "nodedev", "nwfilter", "secret", "storage"]
MODULAR_SUFFIXES = [".socket", "-ro.socket", "-admin.socket"]


def _service_is_active(service: str) -> bool:
    return run(f"systemctl is-active {service}").out.strip() == "active"


def _service_is_enabled(service: str) -> bool:
    return run(f"systemctl is-enabled {service}").out.strip() == "enabled"


def configure_libvirt() -> None:
    logger.info("Configuring libvirt modular services")

    # Stop monolithic libvirtd if running
    if _service_is_active("libvirtd.service") or _service_is_enabled("libvirtd.service"):
        run("systemctl stop libvirtd.service")
        for suffix in [".socket", "-ro.socket", "-admin.socket", "-tcp.socket", "-tls.socket"]:
            run(f"systemctl stop libvirtd{suffix}")
            run(f"systemctl disable libvirtd{suffix}")
        run("systemctl disable libvirtd.service")

    if not _service_is_active("virtqemud.service"):
        run_or_die("systemctl start virtqemud.service")

    for svc in MODULAR_SERVICES:
        name = f"virt{svc}d"
        if not _service_is_enabled(f"{name}.service"):
            run_or_die(f"systemctl enable {name}.service")
        for suffix in MODULAR_SUFFIXES:
            if not _service_is_enabled(f"{name}{suffix}"):
                run_or_die(f"systemctl enable {name}{suffix}")
            if not _service_is_active(f"{name}{suffix}"):
                run_or_die(f"systemctl start {name}{suffix}")


def restart_libvirt(service: Optional[str] = None) -> None:
    if service is not None:
        run_or_die(f"systemctl restart virt{service}d.service")
        for suffix in MODULAR_SUFFIXES:
            run(f"systemctl start virt{service}d{suffix}")
        return
    for svc in MODULAR_SERVICES:
        run_or_die(f"systemctl restart virt{svc}d.service")
        for suffix in MODULAR_SUFFIXES:
            run(f"systemctl start virt{svc}d{suffix}")


def ensure_qemu_root() -> None:
    qemu_conf = "/etc/libvirt/qemu.conf"
    try:
        with open(qemu_conf) as f:
            content = f.read()
    except FileNotFoundError:
        content = ""
    if re.search(r'\nuser = "root"', content) and re.search(r'\ngroup = "root"', content):
        return
    run('sed -e \'s/#\\(user\\|group\\) = ".*"$/\\1 = "root"/\' -i /etc/libvirt/qemu.conf')
    restart_libvirt("qemu")


# ---------------------------------------------------------------------------
# Virtual bridge (simplified from virtualBridge.py -- localhost only)
# ---------------------------------------------------------------------------

def bridge_network_xml(cfg: BridgeConfig) -> str:
    start, end = cfg.dhcp_range.split(",")
    return f"""<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0' stp='off' delay='0'/>
  <ip address='{cfg.ip}' netmask='{cfg.mask}'>
    <dhcp>
      <range start='{start}' end='{end}'/>
    </dhcp>
  </ip>
</network>"""


def ensure_virbr0(cfg: BridgeConfig) -> None:
    """Ensure virbr0 exists with correct configuration."""
    r = run("virsh net-dumpxml default")
    needs_reconfigure = False

    if not r.success():
        needs_reconfigure = True
    elif "stp='off'" not in r.out:
        logger.info("Bridge needs reconfigure: stp enabled")
        needs_reconfigure = True
    elif f"address='{cfg.ip}'" not in r.out:
        logger.info("Bridge needs reconfigure: wrong IP")
        needs_reconfigure = True

    if needs_reconfigure:
        logger.info("Destroying and recreating bridge")
        run("virsh net-destroy default")
        r2 = run("virsh net-undefine default")
        if r2.returncode != 0 and "Network not found" not in r2.err:
            error_and_exit(f"net-undefine failed: {r2}")
        run("ip link delete virbr0")  # may fail if not present

        xml = bridge_network_xml(cfg)
        xml_path = "/tmp/sno_vir_bridge.xml"
        with open(xml_path, "w") as f:
            f.write(xml)

        run_or_die(f"virsh net-define {xml_path}")
        run_or_die("virsh net-start default")
        restart_libvirt()
        time.sleep(5)


def setup_dhcp_entry(name: str, ip: str, mac: str) -> None:
    """Add a static DHCP entry for the SNO master."""
    remove_dhcp_entry(name, ip, mac)
    host_xml = f"<host mac='{mac}' name='{name}' ip='{ip}'/>"
    logger.info(f"Creating DHCP entry: {name} ip={ip} mac={mac}")
    run_or_die(f'virsh net-update default add ip-dhcp-host "{host_xml}" --live --config')


def remove_dhcp_entry(name: str, ip: str, mac: str) -> None:
    """Remove DHCP entry if it exists."""
    xml_str = run("virsh net-dumpxml default").out
    if not xml_str:
        return
    try:
        tree = ET.fromstring(xml_str)
    except ET.ParseError:
        return

    ip_elem = next((it for it in tree.iter("ip")), None)
    if ip_elem is None:
        return
    dhcp = next((it for it in ip_elem.iter("dhcp")), None)
    if dhcp is None:
        return

    for e in dhcp:
        if e.get("name") == name or e.get("ip") == ip or e.get("mac") == mac:
            emac = e.attrib.get("mac", mac)
            ename = e.attrib.get("name", name)
            eip = e.attrib.get("ip", ip)
            cmd = f"virsh net-update default delete ip-dhcp-host \"<host mac='{emac}' name='{ename}' ip='{eip}'/>\" --live --config"
            r = run(cmd)
            logger.info(f"Delete DHCP for {ename}: {r}")

    # Clean virbr0.status leases
    status_file = Path("/var/lib/libvirt/dnsmasq/virbr0.status")
    if status_file.exists():
        content = status_file.read_text()
        if content.strip():
            try:
                leases = json.loads(content)
                filtered = [l for l in leases if l.get("mac-address") != mac and l.get("hostname") != name]
                if len(filtered) != len(leases):
                    run("virsh net-destroy default")
                    status_file.write_text(json.dumps(filtered, indent=4))
                    run("virsh net-start default")
                    restart_libvirt("qemu")
            except json.JSONDecodeError:
                pass


# ---------------------------------------------------------------------------
# Assisted Installer Service  (simplified from assistedInstallerService.py)
# ---------------------------------------------------------------------------

# Freeze SAAS versions
AI_SAAS_VERSION = "latest"
AI_INSTALLER_IMAGE = "registry.redhat.io/rhai/assisted-installer-rhel9:433f21415675d1077e87672e310fc515f8277751"
AI_CONTROLLER_IMAGE = "registry.redhat.io/rhai/assisted-installer-controller-rhel9:433f21415675d1077e87672e310fc515f8277751"
AI_AGENT_IMAGE = "registry.redhat.io/rhai/assisted-installer-agent-rhel9:d19761ec5c7d3e19d616953f628683fd19ce4896"

AI_CONFIGMAP_URL = "https://raw.githubusercontent.com/openshift/assisted-service/master/deploy/podman/configmap.yml"
AI_POD_URL = "https://raw.githubusercontent.com/openshift/assisted-service/master/deploy/podman/pod-persistent.yml"


def _hash_string(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


def _tmp_file() -> IO[str]:
    return tempfile.NamedTemporaryFile(delete=True, mode="w+")


def prep_version(version: str) -> dict[str, Any]:
    """Simplified version prep -- replaces the 200-line if/elif chain."""
    m = re.match(r"(\d+\.\d+)", version)
    if not m:
        error_and_exit(f"Cannot parse version: {version}")
    major_minor = m.group(1)

    if "nightly" in version:
        v_stripped = version.rstrip("-nightly")
        url_api = f"https://multi.ocp.releases.ci.openshift.org/api/v1/releasestream/{v_stripped}-0.nightly-multi/latest"
        resp = requests.get(url_api)
        j = resp.json()
        pullspec = j["pullSpec"]
    else:
        pullspec = f"quay.io/openshift-release-dev/ocp-release:{version}-multi"

    ret: dict[str, Any] = {
        "openshift_version": f"{major_minor}-multi",
        "cpu_architectures": ["x86_64", "arm64", "ppc64le", "s390x"],
        "cpu_architecture": "multi",
        "url": pullspec,
        "version": version,
    }
    if "ec" in version or "nightly" in version:
        ret["support_level"] = "beta"
    return ret


def _strip_unused_versions(os_images: str, version: str) -> str:
    m = re.match(r"(\d+\.\d+)", version)
    if not m:
        return os_images
    major_minor = m.group(1)
    j = json.loads(os_images)
    keep = [e for e in j if e.get("openshift_version") == major_minor]
    return json.dumps(keep)


def _customized_configmap(ip: str, version: str, proxy: Optional[str], noproxy: Optional[str]) -> dict[str, Any]:
    raw = get_url(AI_CONFIGMAP_URL).text
    y = yaml.safe_load(raw)
    y["data"]["IMAGE_SERVICE_BASE_URL"] = f"http://{ip}:8888"
    y["data"]["SERVICE_BASE_URL"] = f"http://{ip}:8090"
    y["data"]["INSTALLER_IMAGE"] = AI_INSTALLER_IMAGE
    y["data"]["CONTROLLER_IMAGE"] = AI_CONTROLLER_IMAGE
    y["data"]["AGENT_DOCKER_IMAGE"] = AI_AGENT_IMAGE
    y["data"]["OS_IMAGES"] = _strip_unused_versions(y["data"]["OS_IMAGES"], version)
    y["data"]["AIUI_CHAT_API_URL"] = f"http://{ip}:12121"

    hw = json.loads(y["data"]["HW_VALIDATOR_REQUIREMENTS"])
    hw[0]["master"]["disk_size_gb"] = 8
    hw[0]["worker"]["disk_size_gb"] = 8
    hw[0]["sno"]["disk_size_gb"] = 8
    y["data"]["HW_VALIDATOR_REQUIREMENTS"] = json.dumps(hw)

    version_contents = prep_version(version)
    y["data"]["RELEASE_IMAGES"] = json.dumps([version_contents])

    if proxy:
        y["data"]["http_proxy"] = proxy
        y["data"]["https_proxy"] = proxy
    if noproxy:
        y["data"]["no_proxy"] = noproxy
    return y


def _customized_pod() -> dict[str, Any]:
    raw = get_url(AI_POD_URL).text
    y = yaml.safe_load(raw)
    for container in y["spec"]["containers"]:
        image = container.get("image", "")
        if image.startswith("quay.io/edge-infrastructure/assisted"):
            container["image"] = image.replace(":latest", f":{AI_SAAS_VERSION}")
            container["securityContext"] = {"runAsUser": 0}
            container["imagePullPolicy"] = "Always"
    return y


def _add_hash_labels(pod: dict[str, Any], cm: dict[str, Any]) -> dict[str, Any]:
    ret = copy.deepcopy(pod)
    ret["metadata"]["labels"] = {
        "cda-pod/hash": _hash_string(yaml.dump(pod)),
        "cda-cm/hash": _hash_string(yaml.dump(cm)),
    }
    return ret


def _find_ai_pod() -> Optional[dict[str, str]]:
    r = run("podman pod ps --format json")
    if r.err:
        return None
    pods = json.loads(r.out)
    for p in pods:
        if p.get("Name") == "assisted-installer":
            return p
    return None


def ai_pod_running() -> bool:
    return _find_ai_pod() is not None


def _ai_stop_needed(pod: dict[str, Any], cm: dict[str, Any], force: bool, resume: bool) -> bool:
    ai_pod = _find_ai_pod()
    if not ai_pod:
        return False
    if force:
        return True
    if ai_pod["Status"] != "Running":
        return True
    if resume:
        return False

    j = json.loads(run("podman inspect assisted-installer").out)
    labels = j[0].get("Labels", {}) if j else {}
    pod_hash = _hash_string(yaml.dump(pod))
    cm_hash = _hash_string(yaml.dump(cm))
    if labels.get("cda-pod/hash") != pod_hash:
        logger.info("AI pod hash mismatch")
        return True
    if labels.get("cda-cm/hash") != cm_hash:
        logger.info("AI configmap hash mismatch")
        return True
    logger.info("AI already running with matching config")
    return False


def ai_stop() -> None:
    if not ai_pod_running():
        return
    logger.info("Tearing down assisted-installer pod")
    pod = _customized_pod()
    with _tmp_file() as pf:
        yaml.dump(pod, pf)
        pf.flush()
        r = run(f"podman kube down --force {pf.name}")
        if r.returncode and ("unrecognized" in r.err or "unknown" in r.err):
            run("podman pod rm -f assisted-installer")
    run("podman volume rm ai-db-data")
    run("podman volume rm ai-service-data")


def _wait_for_db() -> None:
    """Wait for AI database to be populated.

    BUG FIX: The original CDA code had incorrect condition ordering --
    timeout was only checked when "multi" was already in the output,
    making it dead code. Fixed here to check timeout every iteration.
    """
    check_cmd = 'podman exec assisted-installer-db psql -d installer -c "SELECT * FROM release_images;"'
    t = Timer("20m")
    while True:
        if t.triggered():
            error_and_exit(f"Failed to wait for DB after {t.target_duration()}")
        result = run(check_cmd)
        if "multi" in result.out:
            logger.info(f"DB populated after {t.elapsed()}")
            break
        time.sleep(0.5)


def _play_kube(pod: dict[str, Any], cm: dict[str, Any]) -> Result:
    with _tmp_file() as pf, _tmp_file() as cf:
        pf.write(json.dumps(pod))
        pf.flush()
        cf.write(json.dumps(cm))
        cf.flush()
        return run_or_die(f"podman play kube --configmap {cf.name} {pf.name}")


def _ensure_virbr0_exists() -> None:
    """Make sure virbr0 is up before starting AI."""
    if not run("ip link show virbr0").success():
        logger.info("virbr0 missing, restarting libvirt network")
        configure_libvirt()
        run("virsh net-start default")
        time.sleep(5)
    if not run("ip link show virbr0").success():
        error_and_exit("Cannot find virbr0 -- ensure libvirt is running")


def ai_wait_api(ip: str) -> None:
    _ensure_virbr0_exists()
    url = f"http://{ip}:8090/api/assisted-install/v2/clusters"
    logger.info(f"Waiting for AI API at {url}")
    for i in range(30):
        try:
            if get_url(url).status_code == 200:
                logger.info("AI API is ready")
                return
        except Exception:
            pass
        if i == 20:
            error_and_exit("AI API is not coming up")
        time.sleep(2)


def ai_start(cfg: SNOConfig, resume: bool = False) -> None:
    ip = cfg.bridge.ip
    cm = _customized_configmap(ip, cfg.version, cfg.proxy, cfg.noproxy)
    pod = _customized_pod()
    pod_labeled = _add_hash_labels(pod, cm)

    if _ai_stop_needed(pod, cm, force=False, resume=resume):
        ai_stop()

    if not ai_pod_running():
        logger.info("Starting assisted-installer pod")
        _play_kube(pod_labeled, cm)
    _wait_for_db()
    ai_wait_api(ip)


# ---------------------------------------------------------------------------
# AI Client wrapper  (simplified from assistedInstaller.py)
# ---------------------------------------------------------------------------

class SNOAssistedClient(AssistedClient):  # type: ignore
    def __init__(self, url: str) -> None:
        super().__init__(url, quiet=True, debug=False)

    def ensure_cluster_deleted(self, name: str) -> None:
        logger.info(f"Ensuring cluster {name} is deleted")
        while self._cluster_exists(name):
            try:
                self.delete_cluster(name)
            except Exception:
                logger.debug("Retrying cluster delete...")
            time.sleep(1)

    def _cluster_exists(self, name: str) -> bool:
        return any(name == c.get("name") for c in self.list_clusters())

    def ensure_infraenv_created(self, name: str, cfg: dict[str, str]) -> None:
        if name not in (x["name"] for x in self.list_infra_envs()):
            logger.info(f"Creating infraenv {name}")
            self.create_infra_env(name, cfg)

    def ensure_infraenv_deleted(self, name: str) -> None:
        if name in (x["name"] for x in self.list_infra_envs()):
            self.delete_infra_env(name)

    def download_kubeconfig_and_secrets(self, name: str, kubeconfig_path: Optional[str]) -> tuple[str, str]:
        path, kp, downloaded_kp, downloaded_pw = kubeconfig_get_paths(name, kubeconfig_path)
        self.download_kubeconfig(name, path)
        self.download_kubeadminpassword(name, path)
        if downloaded_kp != kp:
            os.rename(downloaded_kp, kp)
        logger.info(f"KUBECONFIG={kp}")
        logger.info(f"KUBEADMIN_PASSWD={downloaded_pw}")
        return kp, downloaded_pw

    @staticmethod
    def delete_kubeconfig_and_secrets(name: str, kubeconfig_path: Optional[str]) -> None:
        _, kp, _, pw = kubeconfig_get_paths(name, kubeconfig_path)
        for f in (kp, pw):
            try:
                os.remove(f)
            except OSError:
                pass

    def download_iso_with_retry(self, infra_env: str, path: str) -> None:
        """Download ISO with retry -- fixed to log actual exception."""
        logger.info(self.info_iso(infra_env, {}))
        t = Timer("15m")
        os.makedirs(path, exist_ok=True)
        while not t.triggered():
            try:
                self.download_iso(infra_env, path)
                logger.info(f"Downloaded ISO after {t.elapsed()}")
                return
            except Exception as e:
                logger.warning(f"ISO download failed: {e}, retrying...")
            time.sleep(1)
            if not ai_pod_running():
                error_and_exit("AI pods became unhealthy during ISO download")
        error_and_exit(f"Failed to download ISO after {t.elapsed()}")

    def cluster_state(self, cluster_name: str) -> str:
        for c in self.list_clusters():
            if c.get("name") == cluster_name:
                return c["status"]
        error_and_exit(f"Cluster {cluster_name} not found")
        return ""  # unreachable

    def wait_cluster_status(self, cluster_name: str, status: str) -> None:
        logger.info(f"Waiting for cluster to reach '{status}' state")
        cur = None
        while True:
            new = self.cluster_state(cluster_name)
            if new != cur:
                logger.info(f"Cluster state: {new}")
                cur = new
            if cur == "error":
                error_and_exit("Cluster reached error state")
            if cur == status:
                return
            time.sleep(1)

    def ensure_cluster_installing(self, cluster_name: str) -> None:
        self.wait_cluster_status(cluster_name, "ready")
        self._start_until_success(cluster_name)

    def _start_until_success(self, cluster_name: str) -> None:
        logger.info(f"Starting cluster installation (will retry)")
        prev = ""
        for tries in itertools.count(0):
            cs = self.cluster_state(cluster_name)
            if cs != prev:
                logger.info(f"Cluster state: {cs}")
                prev = cs
            if cs in ("ready", "error"):
                try:
                    self.start_cluster(cluster_name)
                except Exception:
                    pass
            elif cs == "installing":
                logger.info(f"Took {tries} tries to start cluster")
                break
            time.sleep(5)

    def get_host_by_name(self, name: str) -> Optional[dict[str, Any]]:
        for h in self.list_hosts():
            if h.get("requested_hostname") == name and "inventory" in h:
                return h
        return None

    def get_cluster_api_vip(self, cluster_name: str) -> str:
        info = self.info_cluster(cluster_name)
        if not hasattr(info, "api_vips") or len(info.api_vips) == 0:
            error_and_exit(f"No API VIP found for cluster {cluster_name}")
        return info.api_vips[0].ip


# ---------------------------------------------------------------------------
# VM lifecycle  (simplified from clusterNode.py VmClusterNode)
# ---------------------------------------------------------------------------

def create_vm_disk(image_path: str, disk_size_gb: int) -> None:
    os.makedirs(os.path.dirname(image_path), exist_ok=True)
    logger.info(f"Creating {disk_size_gb}GB disk at {image_path}")
    run_or_die(f"qemu-img create -f qcow2 -o preallocation=off {image_path} {disk_size_gb}G")


def start_vm(cfg: SNOConfig, iso_path: str) -> bool:
    m = cfg.master
    cmd = f"""virt-install
        --connect qemu:///system
        -n {m.name}
        -r {m.ram}
        --cpu host
        --vcpus {m.cpu}
        --os-variant={m.os_variant}
        --import
        --network network=default,mac={m.mac}
        --events on_reboot=restart
        --cdrom {iso_path}
        --disk path={cfg.image_path}
        --noreboot
        --noautoconsole"""

    logger.info(f"Starting VM {m.name}")
    r = run(cmd)
    if not r.success():
        logger.error(f"virt-install failed: {r.err}")
    return r.success()


def teardown_vm(cfg: SNOConfig) -> None:
    name = cfg.master.name
    image = cfg.image_path

    if os.path.exists(image):
        os.remove(image)
    alt = image.replace(".qcow2", ".img")
    if os.path.exists(alt):
        os.remove(alt)

    if run(f"virsh desc {name}").success():
        r = run(f"virsh destroy {name}")
        logger.info(r.err if r.err else r.out.strip())
        r = run(f"virsh undefine {name}")
        logger.info(r.err if r.err else r.out.strip())


def ensure_vm_reboot(name: str) -> bool:
    """Wait for VM to reboot after installation."""

    def vm_state_is(running: bool) -> bool:
        return vm_is_running(name) == running

    # Wait for VM to go down
    wait_true(f"reboot of {name} to start", lambda: vm_state_is(False), timeout="30m", interval=10)

    if not vm_is_running(name):
        logger.info(f"VM {name} not running after reboot, starting manually")
        r = run(f"virsh start {name}")
        if not r.success() and "already active" not in r.err:
            logger.error(f"Failed to start VM {name}: {r.err}")
            return False

    # Wait for VM to come back up
    wait_true(f"reboot of {name} to finish", lambda: vm_state_is(True), timeout="10m", interval=5)
    return True


# ---------------------------------------------------------------------------
# DNS / dnsmasq / /etc/hosts  (simplified from dnsutil.py)
# ---------------------------------------------------------------------------

RESOLVCONF = "/etc/resolv.conf"
RESOLVCONF_ORIG = "/etc/resolv.conf.cda-orig"
RESOLVCONF_LOCAL = "/etc/resolv.conf.cda-local"
DNSMASQ_SERVERS_FILE = "/etc/dnsmasq.d/servers/cda-servers.conf"


def _resolvconf_dont_touch() -> bool:
    return os.path.exists("/etc/.resolv.conf.cda-dont-touch")


def _resolvconf_ensure_orig() -> None:
    if os.path.exists(RESOLVCONF_ORIG):
        return
    try:
        with open(RESOLVCONF, "rb") as f:
            content = f.read()
    except IOError:
        content = b""
    if not content:
        return
    if b"Written by cluster-deployment-automation" in content:
        return
    if b"Generated by NetworkManager" in content and os.path.exists("/run/NetworkManager/resolv.conf"):
        run(f"ln -snf /run/NetworkManager/resolv.conf {RESOLVCONF_ORIG}")
    else:
        with atomic_write(RESOLVCONF_ORIG, text=False) as f:
            f.write(content)


def _resolvconf_update(setup: bool = True) -> None:
    if _resolvconf_dont_touch():
        return
    if not setup:
        if not os.path.exists(RESOLVCONF_ORIG):
            return
        try:
            lnk = os.readlink(RESOLVCONF)
        except Exception:
            return
        if not os.path.basename(lnk).startswith("resolv.conf.cda."):
            return
        run(f"ln -snf {os.path.basename(RESOLVCONF_ORIG)} {RESOLVCONF}")
        return

    with atomic_write(RESOLVCONF_LOCAL) as f:
        f.write(f"""# Written by cluster-deployment-automation (sno_deploy.py).
# Original file: {RESOLVCONF_ORIG}
nameserver 127.0.0.1
""")
    if not _resolvconf_dont_touch():
        run(f"ln -snf {os.path.basename(RESOLVCONF_LOCAL)} {RESOLVCONF}")


def dnsmasq_update(cluster_name: str, api_vip: Optional[str] = None) -> None:
    _resolvconf_ensure_orig()

    # Update server entries
    os.makedirs(os.path.dirname(DNSMASQ_SERVERS_FILE), exist_ok=True)
    try:
        with open(DNSMASQ_SERVERS_FILE, "rb") as f:
            old_content = f.read()
    except Exception:
        old_content = b""

    old_entries = [l.strip() for l in old_content.split(b"\n") if l.strip().startswith(b"server=/")]

    new_entries = list(old_entries)
    prefix1 = f"server=/*.api.{cluster_name}.redhat.com/*.api-int.{cluster_name}.redhat.com/#".encode()
    prefix2 = f"server=/apps.{cluster_name}.redhat.com/api.{cluster_name}.redhat.com/api-int.{cluster_name}.redhat.com/".encode()

    new_entries = [e for e in new_entries if e != prefix1 and not e.startswith(prefix2)]
    if api_vip:
        new_entries.append(prefix1)
        new_entries.append(prefix2 + api_vip.encode())

    new_entries.sort()
    new_content = b"# Written by cluster-deployment-automation (sno_deploy.py).\n" + b"\n".join(new_entries) + b"\n"

    changed = new_content != old_content
    if changed:
        with atomic_write(DNSMASQ_SERVERS_FILE, text=False) as f:
            f.write(new_content)

    # Write main dnsmasq config
    dmasqconf = "/etc/dnsmasq.d/cda.conf"
    with atomic_write(dmasqconf) as f:
        f.write(f"# Written by cluster-deployment-automation (sno_deploy.py).\n")
        f.write("listen-address=127.0.0.1\n")
        f.write("bind-interfaces\n")
        f.write(f"resolv-file={RESOLVCONF_ORIG}\n")
        f.write(f"servers-file={DNSMASQ_SERVERS_FILE}\n")

    if api_vip:
        _resolvconf_update(setup=True)

    run("systemctl unmask dnsmasq.service")
    run("systemctl enable dnsmasq.service")
    if changed or not _service_is_active("dnsmasq.service"):
        run("systemctl restart dnsmasq.service")


def update_etc_hosts(cluster_name: str, api_vip: str) -> None:
    api_name = f"api.{cluster_name}.redhat.com"
    hosts = Hosts()
    hosts.remove_all_matching(name=api_name)
    hosts.remove_all_matching(address=api_vip)
    hosts.add([HostsEntry(entry_type="ipv4", address=api_vip, names=[api_name])])
    hosts.write()
    restart_libvirt("network")


# ---------------------------------------------------------------------------
# Deploy flow
# ---------------------------------------------------------------------------

def deploy(cfg: SNOConfig, resume: bool, secrets_path: str) -> None:
    state = StateFile(cfg.name)
    if not resume:
        logger.info("Resetting state")
        state.clear()

    sw = StopWatch()
    sw.start()

    # Step 1: Ensure SSH key exists
    if not os.path.exists(os.path.expanduser("~/.ssh/id_ed25519")):
        logger.info("No SSH key found, generating one")
        run_or_die("ssh-keygen -t ed25519 -N '' -f ~/.ssh/id_ed25519")

    # Step 2: Configure libvirt
    if not state.deployed("libvirt"):
        logger.info("=== Configuring libvirt ===")
        configure_libvirt()
        ensure_qemu_root()
        state.mark("libvirt")
    else:
        logger.info("Skipping libvirt (already configured)")

    # Step 3: Configure bridge
    if not state.deployed("bridge"):
        logger.info("=== Configuring virbr0 bridge ===")
        ensure_virbr0(cfg.bridge)
        state.mark("bridge")
    else:
        logger.info("Skipping bridge (already configured)")

    # Step 4: Start AI
    if not state.deployed("ai-started"):
        logger.info("=== Starting Assisted Installer ===")
        ai_start(cfg, resume=resume)
        state.mark("ai-started")
    else:
        logger.info("Skipping AI start (already done)")
        # Even if skipped, make sure API is reachable
        ai_wait_api(cfg.bridge.ip)

    ai_url = f"{cfg.bridge.ip}:8090"
    ai = SNOAssistedClient(ai_url)

    # Step 5: Create cluster + infraenv + download ISO + start VM
    if not state.deployed("masters"):
        logger.info("=== Deploying SNO master ===")

        # Teardown any existing state
        ai.ensure_cluster_deleted(cfg.name)

        # Create cluster
        cluster_cfg: dict[str, Any] = {
            "openshift_version": cfg.version,
            "cpu_architecture": "multi",
            "pull_secret": secrets_path,
            "infraenv": "false",
            "vip_dhcp_allocation": False,
            "additional_ntp_source": cfg.ntp_source,
            "base_dns_domain": cfg.base_dns_domain,
            "sno": True,
        }
        if cfg.proxy:
            cluster_cfg["proxy"] = cfg.proxy
        if cfg.noproxy:
            cluster_cfg["noproxy"] = cfg.noproxy
        logger.info(f"Creating cluster: {cluster_cfg}")
        ai.create_cluster(cfg.name, cluster_cfg)

        # Create infraenv
        infra_env = f"{cfg.name}-x86_64"
        ie_cfg: dict[str, str] = {
            "cluster": cfg.name,
            "pull_secret": secrets_path,
            "cpu_architecture": "x86_64",
            "openshift_version": cfg.version,
        }
        if cfg.proxy:
            ie_cfg["proxy"] = cfg.proxy
        if cfg.noproxy:
            ie_cfg["noproxy"] = cfg.noproxy
        ai.ensure_infraenv_created(infra_env, ie_cfg)

        # Download ISO
        ai.download_iso_with_retry(infra_env, cfg.iso_dir)
        iso_file = os.path.join(cfg.iso_dir, f"{infra_env}.iso")

        # Setup DHCP entry
        setup_dhcp_entry(cfg.master.name, cfg.master.ip, cfg.master.mac)

        # Create disk + start VM
        create_vm_disk(cfg.image_path, cfg.master.disk_size)
        if not start_vm(cfg, iso_file):
            error_and_exit("Failed to start SNO VM")

        # Wait for host to appear in AI and reach known state
        def host_known() -> bool:
            h = ai.get_host_by_name(cfg.master.name)
            if h is None:
                return False
            status = h.get("status", "")
            if status == "error":
                error_and_exit(f"Host {cfg.master.name} in error state")
            return status == "known"

        logger.info("Waiting for host to reach 'known' state in AI")
        if not wait_true("host known", host_known, timeout="30m", interval=10):
            error_and_exit("Host never reached known state")

        # Start installation
        ai.ensure_cluster_installing(cfg.name)

        # Download kubeconfig
        ai.download_kubeconfig_and_secrets(cfg.name, cfg.kubeconfig)

        # Wait for reboot
        def master_rebooting() -> bool:
            h = ai.get_host_by_name(cfg.master.name)
            if h is None:
                return False
            status = h.get("status", "")
            info = h.get("status_info", "")
            if status == "error" or status == "installing-pending-user-action":
                return True
            return status == "installing-in-progress" and info == "Rebooting"

        logger.info("Waiting for master to reboot")
        wait_true("master reboot", master_rebooting, timeout="45m", interval=10)
        ensure_vm_reboot(cfg.master.name)

        # Wait for cluster installed
        ai.wait_cluster_status(cfg.name, "installed")

        # Update /etc/hosts and dnsmasq
        api_vip = ai.get_cluster_api_vip(cfg.name)
        update_etc_hosts(cfg.name, api_vip)
        dnsmasq_update(cfg.name, api_vip)

        # Set root password
        logger.info("Setting root password on SNO node")
        wait_ssh(cfg.master.ip, "core", timeout_minutes=10)
        ssh_run(cfg.master.ip, "core", "echo root:redhat | sudo chpasswd")

        state.mark("masters")
    else:
        logger.info("Skipping master deployment (already deployed)")

    sw.stop()
    logger.info(f"Deployment completed in {sw}")


# ---------------------------------------------------------------------------
# Teardown flow
# ---------------------------------------------------------------------------

def teardown(cfg: SNOConfig, full: bool = False) -> None:
    state = StateFile(cfg.name)
    ai_url = f"{cfg.bridge.ip}:8090"

    # Try to clean up AI state if API is reachable
    try:
        ai = SNOAssistedClient(ai_url)
        ai.ensure_cluster_deleted(cfg.name)
        infra_env = f"{cfg.name}-x86_64"
        ai.ensure_infraenv_deleted(infra_env)
    except Exception as e:
        logger.warning(f"Could not clean AI state (pod may be down): {e}")

    # Clean DNS
    dnsmasq_update(cfg.name, api_vip=None)

    # Teardown VM
    teardown_vm(cfg)

    # Remove DHCP entry
    remove_dhcp_entry(cfg.master.name, cfg.master.ip, cfg.master.mac)

    # Remove kubeconfig
    SNOAssistedClient.delete_kubeconfig_and_secrets(cfg.name, cfg.kubeconfig)

    # Remove ISO dir
    iso_dir = cfg.iso_dir
    if os.path.exists(iso_dir):
        import shutil
        shutil.rmtree(iso_dir, ignore_errors=True)

    # Remove image dir
    image_dir = cfg.image_dir
    if os.path.exists(image_dir):
        import shutil
        shutil.rmtree(image_dir, ignore_errors=True)

    state.clear()

    if full:
        logger.info("Full teardown: stopping AI pod")
        ai_stop()

    logger.info("Teardown complete")


# ---------------------------------------------------------------------------
# Argument parsing and main
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Simplified SNO Deployer")
    parser.add_argument("--config", "-c", required=True, help="Path to sno_config.yaml")

    sub = parser.add_subparsers(dest="command")

    deploy_p = sub.add_parser("deploy", help="Deploy SNO cluster")
    deploy_p.add_argument("--resume", action="store_true", help="Resume from last successful step")
    deploy_p.add_argument("--secrets-path", default="./pull_secret.json", help="Path to pull secret")

    teardown_p = sub.add_parser("teardown", help="Teardown SNO cluster")
    teardown_p.add_argument("--full", action="store_true", help="Also stop AI pod")

    sub.add_parser("state", help="Print state file")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not args.command:
        error_and_exit("No command specified. Use: deploy, teardown, or state")

    cfg = load_config(args.config)

    if args.command == "state":
        print(StateFile(cfg.name))
        return

    if args.command == "deploy":
        secrets = getattr(args, "secrets_path", cfg.pull_secret)
        deploy(cfg, resume=args.resume, secrets_path=secrets)
    elif args.command == "teardown":
        teardown(cfg, full=args.full)


if __name__ == "__main__":
    main()

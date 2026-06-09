"""
Sandbox execution engine: runs the target repo in an isolated Docker container
and observes runtime behavior (network, filesystem, process activity).
"""

import time
import json
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
import docker  # pip install docker


SANDBOX_IMAGE = "python:3.12-slim"  # overridden per-project type
MAX_RUN_SECONDS = 60
NETWORK_NAME = "secreview_isolated"


@dataclass
class RuntimeObservation:
    outbound_connections: list[dict] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    processes_spawned: list[str] = field(default_factory=list)
    env_vars_accessed: list[str] = field(default_factory=list)
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    suspicious_behaviors: list[str] = field(default_factory=list)


def _detect_project_type(repo_path: str) -> tuple[str, str]:
    """Return (docker_image, start_command) based on detected project type."""
    p = Path(repo_path)
    if (p / "package.json").exists():
        return "node:20-slim", "npm install && npm start"
    if (p / "requirements.txt").exists() or (p / "pyproject.toml").exists():
        return SANDBOX_IMAGE, "pip install -r requirements.txt 2>/dev/null; python main.py 2>/dev/null || python app.py 2>/dev/null || python -m flask run 2>/dev/null || echo 'No entry point found'"
    if (p / "pom.xml").exists():
        return "maven:3.9-eclipse-temurin-21", "mvn package -q && java -jar target/*.jar"
    if (p / "go.mod").exists():
        return "golang:1.22-alpine", "go run ."
    return SANDBOX_IMAGE, "echo 'No recognisable entry point'"


def _create_isolated_network(client: "docker.DockerClient") -> str:
    """Create a Docker network with outbound internet blocked."""
    try:
        net = client.networks.get(NETWORK_NAME)
        return net.id
    except docker.errors.NotFound:
        net = client.networks.create(
            NETWORK_NAME,
            driver="bridge",
            internal=True,  # no external routing
            options={"com.docker.network.bridge.enable_icc": "false"},
        )
        return net.id


def _flag_suspicious(obs: RuntimeObservation) -> None:
    """Heuristic checks on runtime observations."""
    suspicious = []

    for conn in obs.outbound_connections:
        host = conn.get("host", "")
        if any(ip in host for ip in ["169.254", "metadata.google", "metadata.aws"]):
            suspicious.append(f"Cloud metadata endpoint accessed: {host}")
        if conn.get("port") in [4444, 1337, 9001]:
            suspicious.append(f"Common C2 port contacted: {host}:{conn.get('port')}")

    for f in obs.files_written:
        if any(sensitive in f for sensitive in ["/etc/passwd", "/etc/shadow", "~/.ssh", ".env"]):
            suspicious.append(f"Sensitive file write attempt: {f}")

    for proc in obs.processes_spawned:
        if any(shell in proc for shell in ["bash", "sh", "cmd", "powershell", "nc ", "ncat"]):
            suspicious.append(f"Shell spawned at runtime: {proc}")

    obs.suspicious_behaviors = suspicious


def run_in_sandbox(repo_path: str, timeout: int = MAX_RUN_SECONDS) -> RuntimeObservation:
    """
    Mount repo into a Docker container, run it, and return runtime observations.
    Uses strace inside container for syscall-level file/process tracking.
    """
    obs = RuntimeObservation()

    try:
        client = docker.from_env()
    except Exception as e:
        obs.stderr = f"Docker unavailable: {e}"
        return obs

    image, start_cmd = _detect_project_type(repo_path)
    print(f"[*] Sandbox: image={image}, cmd={start_cmd}")

    # Wrap with strace to capture file writes and process spawns
    traced_cmd = (
        f"apt-get install -qq -y strace 2>/dev/null; "
        f"strace -e trace=openat,execve,connect -o /tmp/strace.log -ff sh -c '{start_cmd}'"
    )

    try:
        _create_isolated_network(client)

        container = client.containers.run(
            image,
            command=["sh", "-c", traced_cmd],
            volumes={repo_path: {"bind": "/app", "mode": "ro"}},
            working_dir="/app",
            network=NETWORK_NAME,
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=50000,          # 50% CPU cap
            pids_limit=128,
            read_only=False,          # strace writes to /tmp
            remove=False,
            detach=True,
            security_opt=["no-new-privileges"],
        )

        try:
            exit_result = container.wait(timeout=timeout)
            obs.exit_code = exit_result.get("StatusCode")
        except Exception:
            container.stop(timeout=5)
            obs.exit_code = -1

        logs = container.logs(stdout=True, stderr=True).decode(errors="replace")
        obs.stdout = logs

        # Parse strace log if available
        try:
            strace_raw, _ = container.exec_run("cat /tmp/strace.log").output.decode(errors="replace"), None
            strace_raw = container.exec_run("cat /tmp/strace.log").output.decode(errors="replace")
            _parse_strace(strace_raw, obs)
        except Exception:
            pass

        container.remove(force=True)

    except docker.errors.ImageNotFound:
        obs.stderr = f"Docker image '{image}' not found locally — pull it first."
    except Exception as e:
        obs.stderr = str(e)

    _flag_suspicious(obs)
    return obs


def _parse_strace(strace_log: str, obs: RuntimeObservation) -> None:
    """Extract file writes, process spawns, and network connects from strace output."""
    for line in strace_log.splitlines():
        # File writes
        if "openat(" in line and ("O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line):
            parts = line.split('"')
            if len(parts) >= 2:
                obs.files_written.append(parts[1])

        # Process spawns
        elif "execve(" in line and "= 0" in line:
            parts = line.split('"')
            if len(parts) >= 2:
                obs.processes_spawned.append(parts[1])

        # Network connections (connect syscall with AF_INET)
        elif "connect(" in line and "AF_INET" in line:
            try:
                addr_part = line.split("sin_addr=inet_addr(")[1].split(")")[0].strip('"')
                port_part = line.split("sin_port=htons(")[1].split(")")[0]
                obs.outbound_connections.append({"host": addr_part, "port": int(port_part)})
            except (IndexError, ValueError):
                pass

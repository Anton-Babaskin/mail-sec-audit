"""Read-only Docker queries used by the Mailcow adapter."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..runner import Runner

INSPECT_PROJECT = '{{index .Config.Labels "com.docker.compose.project"}}'
INSPECT_WORKDIR = '{{index .Config.Labels "com.docker.compose.project.working_dir"}}'
INSPECT_VMAIL = '{{range .Mounts}}{{if eq .Destination "/var/vmail"}}{{.Source}}{{end}}{{end}}'
INSPECT_IMAGE = "{{.Config.Image}}"


@dataclass(frozen=True)
class Container:
    id: str
    state: str


def service_container(runner: Runner, service: str) -> Optional[Container]:
    result = runner.run(
        [
            "docker",
            "ps",
            "-a",
            "--no-trunc",
            "--filter",
            f"label=com.docker.compose.service={service}",
            "--format",
            "{{.ID}}\t{{.State}}",
        ]
    )
    if not result.ok:
        return None
    for line in result.stdout.splitlines():
        container_id, _, state = line.partition("\t")
        if container_id.strip():
            return Container(container_id.strip(), state.strip() or "unknown")
    return None


def inspect(runner: Runner, container_id: str, template: str) -> str:
    result = runner.run(["docker", "inspect", "--format", template, container_id])
    return result.stdout.strip() if result.ok else ""


def project_containers(runner: Runner, project: str) -> Optional[list[tuple[str, str, str]]]:
    result = runner.run(
        [
            "docker",
            "ps",
            "-a",
            "--filter",
            f"label=com.docker.compose.project={project}",
            "--format",
            "{{.Names}}\t{{.State}}\t{{.Status}}",
        ]
    )
    if not result.ok:
        return None
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            rows.append((parts[0], parts[1], parts[2]))
    return rows

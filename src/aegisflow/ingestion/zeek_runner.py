from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
import re


class ZeekUnavailableError(RuntimeError):
    """Raised when the configured Zeek executable cannot be found."""


class ZeekExecutionError(RuntimeError):
    """Raised when Zeek fails to process a capture."""


@dataclass(frozen=True, slots=True)
class ZeekRunResult:
    conn_log: Path
    output_directory: Path
    stdout: str
    stderr: str


class ZeekRunner:
    def __init__(self, executable: str = "zeek") -> None:
        self.executable = executable

    def resolved_executable(self) -> str | None:
        explicit = Path(self.executable)
        if explicit.parent != Path(".") or explicit.is_absolute():
            return str(explicit) if explicit.is_file() else None
        return shutil.which(self.executable)

    def check_available(self) -> str:
        resolved = self.resolved_executable()
        if not resolved:
            raise ZeekUnavailableError(
                f"Zeek executable {self.executable!r} was not found. Install Zeek in Linux/WSL "
                "or pass --zeek-binary with an executable path."
            )
        return resolved

    def process_pcap(self, pcap: str | Path, output_directory: str | Path) -> ZeekRunResult:
        executable = self.check_available()
        capture = Path(pcap).resolve()
        if not capture.is_file():
            raise FileNotFoundError(f"PCAP file not found: {capture}")
        output = Path(output_directory).resolve()
        output.mkdir(parents=True, exist_ok=True)
        command = [executable, "-C", "-r", str(capture), "LogAscii::use_json=T"]
        result = subprocess.run(
            command,
            cwd=output,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ZeekExecutionError(
                f"Zeek exited with code {result.returncode}: {result.stderr.strip()}"
            )
        conn_log = output / "conn.log"
        if not conn_log.is_file():
            raise ZeekExecutionError("Zeek completed but did not produce conn.log")
        return ZeekRunResult(conn_log, output, result.stdout, result.stderr)


class WSLZeekRunner:
    """Run a Linux Zeek installation from the Windows Drastha process."""

    def __init__(
        self,
        executable: str = "/opt/zeek/bin/zeek",
        distribution: str | None = None,
        wsl_executable: str = "wsl.exe",
    ) -> None:
        self.executable = executable
        self.distribution = distribution
        self.wsl_executable = wsl_executable

    def _base_command(self) -> list[str]:
        command = [self.wsl_executable]
        if self.distribution:
            command.extend(["--distribution", self.distribution])
        return command

    def _run(self, arguments: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(self._base_command() + arguments, **kwargs)
        except FileNotFoundError as exc:
            raise ZeekUnavailableError(
                "WSL was not found. Install WSL and Ubuntu before using WSL Zeek mode."
            ) from exc

    def check_available(self) -> str:
        result = self._run(
            ["--", self.executable, "--version"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise ZeekUnavailableError(
                f"Zeek executable {self.executable!r} was not available inside WSL"
                + (f": {detail}" if detail else ".")
            )
        return f"WSL:{self.distribution or 'default'}:{self.executable}"

    def _wsl_path(self, path: Path) -> str:
        raw = str(path)
        drive_match = re.match(r"^([A-Za-z]):[\\/](.*)$", raw)
        if drive_match:
            drive, remainder = drive_match.groups()
            return f"/mnt/{drive.lower()}/{remainder.replace(chr(92), '/')}"

        unc_match = re.match(
            r"^\\\\(?:wsl\.localhost|wsl\$)\\[^\\]+\\(.*)$",
            raw,
            flags=re.IGNORECASE,
        )
        if unc_match:
            return "/" + unc_match.group(1).replace("\\", "/")

        result = self._run(
            ["--", "wslpath", "-a", str(path)],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 or not result.stdout.strip():
            detail = result.stderr.strip() or "no path returned"
            raise ZeekExecutionError(f"Could not translate Windows path for WSL: {detail}")
        return result.stdout.strip()

    def process_pcap(self, pcap: str | Path, output_directory: str | Path) -> ZeekRunResult:
        self.check_available()
        capture = Path(pcap).resolve()
        if not capture.is_file():
            raise FileNotFoundError(f"PCAP file not found: {capture}")
        output = Path(output_directory).resolve()
        output.mkdir(parents=True, exist_ok=True)

        capture_linux = self._wsl_path(capture)
        output_linux = self._wsl_path(output)
        command = self._base_command() + [
            "--cd",
            output_linux,
            "--",
            self.executable,
            "-C",
            "-r",
            capture_linux,
            "LogAscii::use_json=T",
        ]
        result = self._run(
            command[len(self._base_command()):],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ZeekExecutionError(
                f"Zeek exited with code {result.returncode}: {result.stderr.strip()}"
            )
        conn_log = output / "conn.log"
        if not conn_log.is_file():
            raise ZeekExecutionError("Zeek completed but did not produce conn.log")
        return ZeekRunResult(conn_log, output, result.stdout, result.stderr)

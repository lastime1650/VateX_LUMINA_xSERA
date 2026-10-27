"""Versioned action-free 64-dimensional CPU features; old 24-vector is untouched."""

import hashlib
import ipaddress
import re

from .research_behavior_graph import ACTIONS, event_features, inputs, normalize_path
from .research_fusion import _action

ROLES = ("editor", "browser", "shell", "service", "python", "system", "archive", "other")
TARGETS = ("document", "executable", "configuration", "registry", "private_network", "public_network", "archive", "other")
FEATURES = tuple(["legacy_"+name for name in event_features({"raw":{}})["features"]] +
    ["role_"+name for name in ROLES] + ["target_kind_"+name for name in TARGETS] +
    ["semantic_trigram_"+str(i) for i in range(16)] +
    ["network_tool", "administrative_command", "credential_target", "script_target", "encoded_command_v2", "parent_incarnation", "device_incarnation", "privileged_port"])


def role(row):
    image=normalize_path(inputs(row)["image"]).rsplit("/",1)[-1]
    groups=(("editor",("editor","notepad","wordpad","nano","vim","emacs","gedit","soffice","libreoffice","code")),
        ("browser",("browser","chrome","firefox","msedge","iexplore","safari","opera")),
        ("python",("python","pypy")),("shell",("powershell","pwsh","cmd.","bash","zsh","/sh")),
        ("service",("service","svchost","daemon","systemd","cron")),
        ("archive",("7z","unzip","gzip","tar.","archive")),("system",("lsass","wininit","init.","kernel")))
    if image in {"sh","cmd","cmd.exe"}:return "shell"
    return next((name for name,tokens in groups if any(token in image for token in tokens)),"other")


def target_kind(row):
    value=inputs(row)
    if value["registry"]:return "registry"
    if value["dest_ip"] and not value["file"]:
        try:return "public_network" if ipaddress.ip_address(value["dest_ip"]).is_global else "private_network"
        except ValueError:return "other"
    path=normalize_path(value["file"])
    if path.endswith((".exe",".dll",".elf",".so",".ps1",".sh",".py")):return "executable"
    if path.endswith((".txt",".doc",".docx",".pdf",".odt",".csv",".xlsx")):return "document"
    if path.endswith((".conf",".config",".ini",".yaml",".json",".xml")):return "configuration"
    if path.endswith((".zip",".gz",".tar",".7z",".rar")):return "archive"
    return "other"


def pattern(row):
    """Role/action/target semantic pattern, independent of host and family labels."""
    return (role(row),_action(inputs(row)["action"]),target_kind(row))


def features(row):
    value=inputs(row);original=event_features(row);which_role=role(row);target=target_kind(row)
    text=normalize_path(value["image"]+" "+value["command"])
    grams=[text[i:i+3] for i in range(max(0,min(len(text)-2,512)))]
    hashed=[0.0]*16
    for token in grams:hashed[hashlib.sha256(token.encode()).digest()[0]%16]+=1/max(1,len(grams))
    command=value["command"].lower();path=(value["file"]+value["registry"]).lower()
    try:port=float(value["dest_port"] or 0)
    except (ValueError,TypeError):port=0
    extra=[float(any(x in command for x in ("curl ","wget ","http://","https://","ssh ","scp "))),
        float(any(x in command for x in ("sudo ","runas ","-verb runas","administrator"))),
        float(any(x in path+command for x in ("lsass","credential","shadow","samdump"))),
        float(path.endswith((".ps1",".sh",".py",".bat",".js"))),
        float(bool(re.search(r"(?:^|\s)-(?:enc|encodedcommand)(?:\s|$)",command))),
        float(bool(value["parent_guid"] and value["parent_start"])),
        float(bool(value["device"] and value["boot"])),float(0<port<1024)]
    values=original["values"]+[float(which_role==x) for x in ROLES]+[float(target==x) for x in TARGETS]+hashed+extra
    action=_action(value["action"])
    return {"values":values,"features":dict(zip(FEATURES,values)),"target":ACTIONS.index(action),"target_name":action,"missing":original["missing"]}

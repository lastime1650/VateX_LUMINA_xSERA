"""Pinned, conservative OCSF 1.4.0 derived mapping profile.

This is a documented subset, not an OCSF conformance certification. Unknown
values remain null, vendor semantics remain in unmapped, receipts are untouched.
"""

from .release_manifest import digest, hash_file

VERSION = "1.4.0"
PROFILE_VERSION = 1
MAPPING_DIGEST = digest({"ocsf": VERSION, "profile": PROFILE_VERSION, "implementation": hash_file(__file__)})


def project(projection):
    semantics = projection.get("event_semantics", {})
    action = semantics.get("reported_action") or projection.get("action")
    mapping = {
        "process_create": (1007, 1, "Launch"), "process_created": (1007, 1, "Launch"),
        "process_terminate": (1007, 2, "Terminate"), "process_terminated": (1007, 2, "Terminate"),
        "process_observed": (1007, 99, "Other"), "process_inventory": (1007, 99, "Other"),
        "file_create": (1001, 1, "Create"), "file_delete": (1001, 4, "Delete"),
        "authentication": (3002, 1, "Logon"), "logout": (3002, 2, "Logoff"),
        "network_connection": (4001, 1, "Open"), "allow": (4001, 99, "Other"), "block": (4001, 99, "Other"),
    }
    class_uid, activity_id, activity_name = mapping.get(action, (0, 0, "Unknown"))
    process = projection.get("process", {})
    flow = projection.get("flow") or {}
    file = projection.get("file", {})
    return {"metadata": {"version": VERSION, "uid": projection["event_id"],
                         "product": {"name": projection.get("product"), "vendor_name": "source-reported"}},
            "class_uid": class_uid, "category_uid": class_uid // 1000,
            "activity_id": activity_id, "activity_name": activity_name,
            "type_uid": class_uid * 100 + activity_id,
            "time": int(projection["event_time"] * 1000),
            "status_id": {"success": 1, "failure": 2}.get(projection.get("outcome"), 0),
            "device": {"uid": projection.get("device", {}).get("uid"), "hostname": projection.get("host")},
            "actor": {"user": {"uid": projection.get("actor", {}).get("uid"), "name": projection.get("actor", {}).get("name")}},
            "process": {"uid": process.get("guid"), "pid": process.get("pid"), "name": process.get("name"), "cmd_line": process.get("command_line")},
            "file": {"uid": file.get("object_id"), "path": file.get("path")},
            "src_endpoint": {"ip": flow.get("src_ip"), "port": flow.get("src_port")},
            "dst_endpoint": {"ip": flow.get("dest_ip"), "port": flow.get("dest_port")},
            "unmapped": {"xsera": {"profile": "derived-subset-v1", "mapping_digest": MAPPING_DIGEST,
                                     "projection_version": projection["version"], "original_action": action,
                                     "semantics": semantics, "device_boot_id": projection.get("device", {}).get("boot_id"),
                                     "source_id": projection.get("source_id"), "source_version": projection.get("source_version"),
                                     "conformance_certified": False}}}

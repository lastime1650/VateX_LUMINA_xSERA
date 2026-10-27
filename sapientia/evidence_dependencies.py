"""Conservative risk terms over connected overlapping original evidence sets."""
import hashlib
import json


def adjusted(rows):
    parent, weights, seen, sets = [], [], {}, set()
    def root(n):
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n
    for row in rows:
        evidence = json.loads(row["evidence"])
        originals = evidence.get("event_ids", [])
        originals = sorted(set(originals)) if isinstance(originals,list) and originals and all(isinstance(v,str) for v in originals) else ["unknown-contribution:"+row["id"]]
        sets.add(hashlib.sha256(json.dumps(originals,separators=(",",":")).encode()).hexdigest())
        keys = list(originals)
        group = evidence.get("analysis",{}).get("dependency_group")
        if group:
            keys.append("dependency-group:"+str(group))
        n = len(parent)
        parent.append(n)
        weights.append(row["term"])
        for key in keys:
            if key in seen:
                a,b = root(n),root(seen[key])
                if a != b:
                    parent[b]=a
                    weights[a]=max(weights[a],weights[b])
            seen[key]=n
    groups = {root(n) for n in range(len(parent))}
    return {"score":sum(weights[n] for n in groups),"groups":len(groups),"distinct_sets":len(sets)}

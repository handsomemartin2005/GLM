"""Check frozen inputs, planned session identities and model-to-action provenance."""
import hashlib
import json
import sys
from pathlib import Path
from api import parse
from lab import fixture,save

def main(run):
    run = Path(run)
    plan = json.loads((run / "PLAN.json").read_text(encoding="utf-8"))
    for name, expected in plan["source_hashes"].items():
        assert hashlib.sha256((run / "sources" / name).read_bytes()).hexdigest() == expected, name
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in (run / "trials").glob("*.json")]
    for row in rows:
        assert row["initial_files"] == fixture(), "Initial source differs from frozen task fixture"
    pending=[]
    if plan["kind"] == "natural_model_sessions":
        expected = {"__".join((m,t,s,g)) for m,_v,t,s,g in plan["jobs"]}
        actual = {r["trial_id"] for r in rows}
        assert actual <= expected and len(actual) == len(rows)
        pending = sorted(expected - actual)
        for row in rows:
            actions=[]
            for call in row["model_calls"]:
                if "call_id" not in call:
                    continue
                response_path = run / "calls" / (call["call_id"] + ".json")
                response = json.loads(response_path.read_text(encoding="utf-8"))
                parsed,error,_message = parse(response)
                if not error:
                    actions.extend((a["action"],a.get("arguments",{})) for a in parsed)
            # Run this on the final, multi-call-compatible batch only.
            assert actions == [(e["action"],e["arguments"]) for e in row["events"]], "Model action provenance mismatch: " + row["trial_id"]
    markers = list((run / "calls").glob("*.started.json")) if (run / "calls").exists() else []
    interrupted = [p.name for p in markers if not p.with_name(p.name.replace(".started.json", ".json")).exists()]
    result={"status":"PASS", "rows":len(rows),"planned":plan["planned_sessions"],"pending_sessions":pending,"request_start_markers":len(markers),"interrupted_call_markers":interrupted,"frozen_source_hashes_verified":len(plan["source_hashes"]),"initial_fixtures_verified":len(rows),"model_action_provenance_verified":plan["kind"]=="natural_model_sessions"}
    save(run / "INTEGRITY.json",result)
    print(json.dumps(result,ensure_ascii=False))

if __name__ == "__main__":
    main(sys.argv[1])

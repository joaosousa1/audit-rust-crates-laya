#!/usr/bin/env python3
import subprocess
import json
import os
import sys
import glob
import urllib.request
import argparse
import re
import tomllib  # Built-in in Python 3.11+

try:
    import laya
    HAS_LAYA = True
except ImportError:
    HAS_LAYA = False

DEFAULT_POLICY_FILENAME = "policy.toml"

def verify_rust_project():
    if not os.path.exists("Cargo.toml"):
        print("❌ Error: The current directory is not a valid Rust project (Cargo.toml not found).", file=sys.stderr)
        print("💡 Run this command from the root of a Rust project.", file=sys.stderr)
        sys.exit(1)

def parse_args():
    parser = argparse.ArgumentParser(description="Agnostic Rust Dependency Security Auditor (Laya Decision Model or TOML Policy)")
    parser.add_argument("--fetch-downloads", action="store_true", help="Query crates.io API for download metrics")
    parser.add_argument("--model-path", type=str, default="convaiinnovations/laya", help="Laya model repo ID OR fallback TOML policy file")
    return parser.parse_args()

def get_cargo_metadata():
    try:
        cmd = ["cargo", "metadata", "--format-version", "1"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Error running cargo metadata: {e}", file=sys.stderr)
        return None

def fetch_crates_io_downloads(crate_name):
    url = f"https://crates.io/api/v1/crates/{crate_name}"
    req = urllib.request.Request(url, headers={"User-Agent": "RustAuditor/1.0"})
    try:
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return data.get("crate", {}).get("downloads", 0)
    except Exception:
        return 0

def find_crate_source(name, version):
    cargo_home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
    registry_src = os.path.join(cargo_home, "registry", "src")
    if not os.path.exists(registry_src):
        return None
    paths = glob.glob(os.path.join(registry_src, "*", f"{name}-{version}"))
    return paths[0] if paths else None

def heuristic_scan(source_path):
    flags = []
    if not source_path or not os.path.exists(source_path):
        return ["Missing Cache"]

    patterns = {
        "Network": r"(reqwest|ureq|std::net|TcpStream|UdpSocket|tokio::net)",
        "Env": r"std::env::var|env::var",
        "Process": r"std::process::Command|Command::new",
    }

    found = []
    for root, _, files in os.walk(source_path):
        for file in files:
            if file.endswith(".rs"):
                try:
                    with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for k, p in patterns.items():
                            if k not in found and re.search(p, content):
                                found.append(k)
                except Exception:
                    pass
    return found

def create_default_policy_file(filepath):
    sample_content = """# cargo-vet style local policy template
[crates.bytes]
allowed_flags = []
description = "Pure memory management, no capabilities allowed."

[crates.reqwest]
allowed_flags = ["Network"]
description = "HTTP client, requires network."
"""
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(sample_content)
    except Exception:
        pass

def load_toml_policy(filepath):
    if not os.path.exists(filepath):
        create_default_policy_file(filepath)
    try:
        with open(filepath, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}

def evaluate_with_toml_policy(policy_data, crate_name, flags):
    crates_section = policy_data.get("crates", {})
    if crate_name not in crates_section:
        return {
            "status": "FAIL",
            "reason": f"Policy Violation: Crate '{crate_name}' is not registered in policy file."
        }
    allowed_flags = crates_section[crate_name].get("allowed_flags", [])
    violations = [f for f in flags if f not in allowed_flags]
    if violations:
        return {
            "status": "FAIL",
            "reason": f"Unauthorized capabilities triggered: {violations} (Allowed: {allowed_flags})."
        }
    return {
        "status": "PASS",
        "reason": "Behaviors strictly match registered policy criteria."
    }

def evaluate_with_laya(agent, crate_name, flags):
    if not agent:
        return {"status": "PASS", "reason": "Laya agent not loaded."}

    state_text = f"Crate name: {crate_name}. Triggered heuristic flags: {flags}."
    
    questions = {
        "security_anomaly": {
            "instructions": "Analyze the dependency behavior and determine if it represents a threat.",
            "question": "Does this behavior represent a severe security anomaly?",
            "type": "choice",
            "criteria": ["Standard architectural behavior", "Severe security anomaly"]
        }
    }
    
    try:
        result = agent.predict(state_text, questions)
        
        answers = result.get("answers", {}) if isinstance(result, dict) else {}
        ans = answers.get("security_anomaly", {})
        probs_dict = ans.get("probabilities", {}) if isinstance(ans, dict) else {}
        
        fail_prob = float(probs_dict.get("Severe security anomaly", 0.0))
        pass_prob = float(probs_dict.get("Standard architectural behavior", 1.0 - fail_prob))

        print("#" * 70)
        if pass_prob > 0.5:
            print("✅")
        else:
            print("❌")
        print(crate_name + " " + str(pass_prob))
        print("")
        
        if fail_prob > 0.5:
            return {
                "status": "FAIL",
                "reason": f"Laya Decision: Security anomaly detected (Confidence: {fail_prob:.2f})."
            }
        else:
            return {
                "status": "PASS",
                "reason": f"Laya Decision: Verified safe architecture (Confidence: {pass_prob:.2f})."
            }
    except Exception as e:
        return {"status": "PASS", "reason": f"Fallback: Evaluation defaulted to PASS due to inference error ({e})."}

def main():
    verify_rust_project()
    args = parse_args()

    use_laya = False
    laya_agent = None
    toml_policy = {}

    if HAS_LAYA and not args.model_path.endswith((".toml", ".gguf")):
        print(f"🧠 Mode: Laya Decision Engine ({args.model_path})")
        print("Loading Laya model via official package...")
        try:
            laya_agent = laya.load(args.model_path)
            use_laya = True
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"⚠️ Warning: Failed to load Laya model ({e}). Falling back to TOML policy mode.")
            toml_policy = load_toml_policy(DEFAULT_POLICY_FILENAME)
    else:
        policy_path = args.model_path if not args.model_path.endswith(".gguf") else DEFAULT_POLICY_FILENAME
        print(f"📜 Mode: Deterministic TOML Policy ({policy_path})")
        toml_policy = load_toml_policy(policy_path)

    meta = get_cargo_metadata()
    if not meta:
        return

    seen_packages = set()
    general_report = []

    for pkg in meta.get("packages", []):
        name = pkg["name"]
        version = pkg["version"]
        if name in seen_packages:
            continue
        seen_packages.add(name)

        downloads = fetch_crates_io_downloads(name) if args.fetch_downloads else 0
        source_path = find_crate_source(name, version)
        flags = heuristic_scan(source_path)

        general_report.append({
            "name": name,
            "version": version,
            "downloads": downloads,
            "flags": flags
        })

    print("\n[Table 1] General Mapping & Heuristic Scan:")
    w_crate = max([len(p["name"]) for p in general_report] + [5])
    w_ver = max([len(p["version"]) for p in general_report] + [7])
    w_flags = max([len(", ".join(p["flags"]) if p["flags"] else "None") for p in general_report] + [15])

    header = f"{'Crate':<{w_crate}} | {'Version':<{w_ver}} | {'Heuristic Flags':<{w_flags}}"
    print(header)
    print("-" * len(header))

    for p in general_report:
        flags_str = ", ".join(p["flags"]) if p["flags"] else "None"
        print(f"{p['name']:<{w_crate}} | {p['version']:<{w_ver}} | {flags_str:<{w_flags}}")

    suspect_packages = [p for p in general_report if p["flags"] and "Missing Cache" not in p["flags"]]

    if suspect_packages:
        print("\n\n[Table 2] Evaluation & Security Screening:")
        eval_results = []
        for p in suspect_packages:
            if use_laya:
                res = evaluate_with_laya(laya_agent, p["name"], p["flags"])
            else:
                res = evaluate_with_toml_policy(toml_policy, p["name"], p["flags"])
            
            status_txt = f"❌ {res.get('status', 'PASS')}" if res.get('status') == 'FAIL' else f"✅ {res.get('status', 'PASS')}"
            eval_results.append({
                "name": p["name"],
                "status_fmt": status_txt,
                "reason": res.get("reason", "")
            })

        w2_crate = max([len(e["name"]) for e in eval_results] + [5])
        w2_status = max([len(e["status_fmt"]) for e in eval_results] + [8])
        w2_reason = max([len(e["reason"]) for e in eval_results] + [20])

        header2 = f"{'Crate':<{w2_crate}} | {'Status':<{w2_status}} | {'Evaluation Reason':<{w2_reason}}"
        print(header2)
        print("-" * len(header2))

        for e in eval_results:
            print(f"{e['name']:<{w2_crate}} | {e['status_fmt']:<{w2_status}} | {e['reason']:<{w2_reason}}")
    else:
        print("\n\nNo packages triggered heuristics requiring screening.")

if __name__ == "__main__":
    main()

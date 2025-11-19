#!/usr/bin/env python3
"""
IOC Reputation Checker (Local + Technical Checks + Reporting)
-------------------------------------------------------------
Beginner-friendly tool for SOC-like website checks that is:
 - Self-contained (no API keys)
 - Performs basic live checks (DNS resolution, HTTPS, simple heuristics)
 - Uses a local reputation database (trusted / suspicious / malicious)
 - Lets users add trusted sites and persists them to disk
 - Generates a plain-text report saved to the ./reports/ folder

How to run:
    python3 ioc_reputation_checker_local_plus.py

Notes for learners:
 - This is an educational/demo tool. A real SOC workflow uses many more signals
   and professional threat intelligence sources.
 - The purpose here is to show how signals are combined into an actionable
   (and explainable) verdict for both technical and non-technical audiences.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import ssl
import urllib.request
import urllib.error
import json
import os
import datetime
import re

# ---------------------------
# Local simulated database
# ---------------------------
# This local database is for demo purposes. You can edit it inside the code
# or add sites using the GUI. Trusted sites added via the GUI are saved to disk.
SIMULATED_DB = {
    "trusted": [
        "google.com",
        "facebook.com",
        "wikipedia.org"
    ],
    "suspicious": [
        "suspicious-site.com",
        "weirdexample.net"
    ],
    "malicious": [
        "phishing-login.net",
        "badsite.example"
    ]
}

# File used to persist user-trusted sites across runs
TRUSTED_STORE_FILE = "trusted_sites.json"
REPORTS_DIR = "reports"

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)


# ---------------------------
# Utility / helper functions
# ---------------------------
def now_timestamp():
    """Return current timestamp string for reports and UI status."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_domain(domain: str) -> str:
    """
    Normalize input to a domain-only string.
    Removes http/https scheme and any path.
    """
    if not domain:
        return ""
    d = domain.strip().lower()
    d = re.sub(r"^https?://", "", d)  # strip http or https
    d = d.split("/")[0]               # remove any path
    d = d.split(":")[0]               # remove port if given
    return d


def load_trusted_store():
    """
    Load user-managed trusted sites from disk (if present).
    Returns a list of domains.
    """
    if os.path.exists(TRUSTED_STORE_FILE):
        try:
            with open(TRUSTED_STORE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


def save_trusted_store(trusted_list):
    """Persist the user-managed trusted list to disk."""
    try:
        with open(TRUSTED_STORE_FILE, "w", encoding="utf-8") as f:
            json.dump(trusted_list, f, indent=2)
        return True
    except Exception:
        return False


# ---------------------------
# Basic live technical checks
# ---------------------------
def dns_resolves(domain: str) -> (bool, list):
    """
    Test whether the domain resolves to at least one IP address.
    Returns (resolves_bool, list_of_ip_strings)
    """
    try:
        # getaddrinfo returns multiple address records
        info = socket.getaddrinfo(domain, None)
        ips = sorted({item[4][0] for item in info})
        return True, ips
    except socket.gaierror:
        return False, []
    except Exception:
        return False, []


def check_https_certificate(domain: str, timeout: int = 5) -> (bool, str):
    """
    Attempt to connect to the domain over HTTPS and validate the TLS certificate.
    Returns (https_ok_bool, message).
    Uses Python's ssl and urllib to avoid third-party dependencies.
    """
    # Build URL
    url = f"https://{domain}/"
    ctx = ssl.create_default_context()

    try:
        # urllib.request will verify SSL certificates by default using the context
        with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
            # If we successfully open the page over HTTPS with a valid cert,
            # consider HTTPS present and OK.
            return True, f"HTTPS reachable (HTTP status {resp.getcode()})."
    except urllib.error.HTTPError as he:
        # HTTP errors can still indicate HTTPS exists (e.g., 403, 404)
        return True, f"HTTPS reachable (HTTP error {he.code})."
    except ssl.SSLError as se:
        return False, f"HTTPS certificate error: {se}."
    except urllib.error.URLError as ue:
        # URLError can mean connection refused / no route / cert validation failed
        return False, f"HTTPS connection failed: {ue.reason}."
    except Exception as e:
        return False, f"HTTPS check error: {e}."


def heuristic_checks(domain: str) -> list:
    """
    Perform simple, explainable heuristics that can indicate suspiciousness.
    Returns a list of human-readable "notes" (which can be empty).
    Example heuristics:
     - Domain contains an IP address instead of a name
     - Very long domain name
     - Many numeric or hyphen segments
     - Use of punycode (xn--), common in homograph attacks
    """
    notes = []
    # IP-looking domain (e.g., 203.0.113.5)
    if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", domain):
        notes.append("Domain is an IP address rather than a named domain; this is uncommon for legitimate websites.")
    # Punycode homograph indicator
    if domain.startswith("xn--") or "xn--" in domain:
        notes.append("Domain contains punycode (xn--), which may be used in homograph attacks.")
    # Length check
    if len(domain) > 60:
        notes.append("Domain name is unusually long, which can be a risk indicator.")
    # Count hyphens / extra segments
    segments = domain.split(".")
    if any(len(seg) > 30 for seg in segments):
        notes.append("One or more domain components are very long; this can be suspicious.")
    # Many hyphens or numeric-only segments
    hyphen_count = domain.count("-")
    numeric_segments = sum(1 for s in segments if s.isnumeric())
    if hyphen_count >= 3:
        notes.append("Domain contains many hyphens; attackers sometimes use hyphens to create lookalikes.")
    if numeric_segments >= 2:
        notes.append("Domain has multiple numeric components; could be auto-generated.")
    return notes


# ---------------------------
# Analysis and aggregation
# ---------------------------
def analyze_domain(domain: str, trusted_store: list):
    """
    Perform combined checks and return a structured analysis dictionary that includes:
     - domain
     - resolution info
     - https check
     - local db reputation
     - heuristics notes
     - final verdict (Safe / Suspicious / Dangerous / Unknown)
     - human-readable explanation lines
    """
    domain = normalize_domain(domain)
    analysis = {
        "domain": domain,
        "timestamp": now_timestamp(),
        "resolved": False,
        "ips": [],
        "https_ok": False,
        "https_msg": "",
        "local_reputation": "unknown",  # from simulated DB or trusted_store
        "heuristics": [],
        "verdict": "Unknown",
        "explanation_lines": []
    }

    # Check in user-managed trusted store first (highest priority for this demo)
    if domain in trusted_store:
        analysis["local_reputation"] = "trusted"
        analysis["explanation_lines"].append("This site is in the user-maintained trusted list.")
    # Check simulated DB
    elif domain in SIMULATED_DB.get("trusted", []):
        analysis["local_reputation"] = "trusted"
        analysis["explanation_lines"].append("This site is in the built-in trusted list.")
    elif domain in SIMULATED_DB.get("malicious", []):
        analysis["local_reputation"] = "malicious"
        analysis["explanation_lines"].append("This site is in the built-in malicious list.")
    elif domain in SIMULATED_DB.get("suspicious", []):
        analysis["local_reputation"] = "suspicious"
        analysis["explanation_lines"].append("This site is in the built-in suspicious list.")
    else:
        analysis["local_reputation"] = "unknown"
        analysis["explanation_lines"].append("No matching records in local reputation lists.")

    # DNS resolution
    resolves, ips = dns_resolves(domain)
    analysis["resolved"] = resolves
    analysis["ips"] = ips
    if resolves:
        analysis["explanation_lines"].append(f"Domain resolves to IP(s): {', '.join(ips)}.")
    else:
        analysis["explanation_lines"].append("Domain could not be resolved via DNS.")

    # HTTPS / certificate check
    https_ok, https_msg = check_https_certificate(domain)
    analysis["https_ok"] = https_ok
    analysis["https_msg"] = https_msg
    analysis["explanation_lines"].append(https_msg)

    # Heuristic checks
    heur = heuristic_checks(domain)
    analysis["heuristics"] = heur
    analysis["explanation_lines"].extend(heur)

    # Compute final verdict with simple rule-based logic
    # Priority: local malicious -> Dangerous
    # If local trusted and HTTPS ok -> Safe
    # If unresolved OR cert error -> Suspicious/Dangerous
    # Heuristics present increases suspicion
    if analysis["local_reputation"] == "malicious":
        analysis["verdict"] = "Dangerous"
        analysis["explanation_lines"].append("High confidence: local intelligence marks this as malicious.")
    elif analysis["local_reputation"] == "trusted" and analysis["https_ok"] and analysis["resolved"]:
        analysis["verdict"] = "Safe"
        analysis["explanation_lines"].append("Trusted and uses HTTPS; low risk indicated.")
    else:
        # mixed or unknown signals
        suspicion_score = 0
        if not analysis["resolved"]:
            suspicion_score += 3
        if not analysis["https_ok"]:
            suspicion_score += 2
        # each heuristic note adds 1
        suspicion_score += len(analysis["heuristics"])
        # local suspicious adds 2
        if analysis["local_reputation"] == "suspicious":
            suspicion_score += 2

        # Map score to verdict
        if suspicion_score >= 4:
            analysis["verdict"] = "Dangerous"
            analysis["explanation_lines"].append("Multiple risk signals detected; treat as dangerous.")
        elif suspicion_score >= 2:
            analysis["verdict"] = "Suspicious"
            analysis["explanation_lines"].append("Some risk signals detected; exercise caution.")
        else:
            analysis["verdict"] = "Unknown"
            analysis["explanation_lines"].append("Signals are inconclusive; proceed with caution.")

    return analysis


# ---------------------------
# Report generation
# ---------------------------
def generate_report_text(analysis: dict, scanned_by: str = "IOC Reputation Checker Demo"):
    """
    Build a plain-text report from the analysis dictionary.
    The report is human-friendly and suitable for sharing.
    """
    lines = []
    lines.append("IOC Reputation Checker - Scan Report")
    lines.append(f"Generated: {analysis.get('timestamp', now_timestamp())}")
    lines.append(f"Scanned by: {scanned_by}")
    lines.append("")
    lines.append(f"Target: {analysis.get('domain')}")
    lines.append(f"Verdict: {analysis.get('verdict')}")
    lines.append("")
    lines.append("Technical findings:")
    lines.append(f" - DNS resolution: {'Yes' if analysis.get('resolved') else 'No'}")
    if analysis.get("ips"):
        lines.append(f" - Resolved IPs: {', '.join(analysis.get('ips'))}")
    lines.append(f" - HTTPS: {'Valid/Reachable' if analysis.get('https_ok') else 'Not available / certificate issue'}")
    if analysis.get("https_msg"):
        lines.append(f"   > {analysis.get('https_msg')}")
    # local reputation
    lines.append(f" - Local reputation: {analysis.get('local_reputation')}")
    lines.append("")
    lines.append("Why we reached this verdict (plain English):")
    for idx, reason in enumerate(analysis.get("explanation_lines", []), start=1):
        lines.append(f" {idx}. {reason}")
    lines.append("")
    # Guidance
    lines.append("Suggested next steps:")
    if analysis.get("verdict") == "Safe":
        lines.append(" - Site appears safe. No immediate action required.")
    elif analysis.get("verdict") == "Suspicious":
        lines.append(" - Use caution. Do not enter credentials or sensitive data.")
        lines.append(" - Consider deeper analysis or blocking if you see other evidence.")
    elif analysis.get("verdict") == "Dangerous":
        lines.append(" - Block the domain and do not visit or share credentials.")
        lines.append(" - If seen in email attachments, treat as malicious and isolate affected systems.")
    else:
        lines.append(" - Signals inconclusive. Consider additional analysis (WHOIS, passive DNS, VirusTotal).")

    return "\n".join(lines)


def save_report(analysis: dict, folder: str = REPORTS_DIR):
    """
    Save the textual report to disk and return the filename path.
    File naming: reports/report_YYYYmmdd_HHMMSS_<domain>.txt
    """
    safe_domain = analysis.get("domain", "unknown").replace("/", "_")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{ts}_{safe_domain}.txt"
    path = os.path.join(folder, filename)
    text = generate_report_text(analysis)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# ---------------------------
# GUI application
# ---------------------------
class IOCApp(tk.Tk):
    """
    Tkinter application presenting a clean interface for scanning and
    managing trusted sites, and for saving reports.
    """

    def __init__(self):
        super().__init__()
        self.title("IOC Reputation Checker - Local (SOC Demo)")
        self.geometry("820x620")
        self.configure(bg="#f7f7f7")
        # Load user trusted store and combine with built-in list dynamically
        self.user_trusted = load_trusted_store()
        # Build UI
        self._create_widgets()

    def _create_widgets(self):
        pad = 8
        header = ttk.Label(self, text="IOC Reputation Checker — Local SOC Demo", font=("Arial", 18, "bold"))
        header.pack(pady=(12, 6))

        # Description
        desc = ttk.Label(self, text="Enter a website or domain to analyze its safety. The tool combines local intelligence with "
                                    "basic live checks (DNS, HTTPS, heuristics) and produces an explanation and a report.",
                         wraplength=760)
        desc.pack(pady=(0, 12))

        # Input frame
        frame = ttk.Frame(self)
        frame.pack(fill=tk.X, padx=pad)

        ttk.Label(frame, text="Website / Domain:").grid(row=0, column=0, sticky="w")
        self.entry = ttk.Entry(frame, width=60)
        self.entry.grid(row=0, column=1, padx=(8, 8))
        self.entry.insert(0, "example.com")

        ttk.Button(frame, text="Run Scan", command=self.run_scan).grid(row=0, column=2, padx=(4, 0))
        ttk.Button(frame, text="Add to Trusted", command=self.add_to_trusted).grid(row=0, column=3, padx=(4, 0))
        ttk.Button(frame, text="Export Last Report", command=self.export_last_report).grid(row=0, column=4, padx=(4, 0))

        # Results area
        results_label = ttk.Label(self, text="Scan Results (plain English):", font=("Arial", 12, "bold"))
        results_label.pack(pady=(12, 6))

        self.results_box = tk.Text(self, height=18, width=98, wrap=tk.WORD)
        self.results_box.pack(padx=pad)
        self.results_box.config(state=tk.DISABLED)

        # Bottom controls and status
        controls = ttk.Frame(self)
        controls.pack(fill=tk.X, padx=pad, pady=(12, 6))
        ttk.Button(controls, text="Show Trusted Sites", command=self.show_trusted_sites).pack(side=tk.LEFT)
        ttk.Button(controls, text="Show Built-in Lists", command=self.show_builtin_lists).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(controls, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(controls, text="Future Features", command=self.show_future_features).pack(side=tk.RIGHT)

        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status.pack(fill=tk.X, padx=pad)

        # Keep last analysis for export
        self.last_analysis = None
        self.last_report_path = None

    # ----------------------
    # UI helper methods
    # ----------------------
    def append_result_text(self, text: str):
        """Append text to the results box (read-only for user)."""
        self.results_box.config(state=tk.NORMAL)
        self.results_box.insert(tk.END, text + "\n")
        self.results_box.see(tk.END)
        self.results_box.config(state=tk.DISABLED)

    def set_results_text(self, text: str):
        """Replace contents of results box."""
        self.results_box.config(state=tk.NORMAL)
        self.results_box.delete("1.0", tk.END)
        self.results_box.insert(tk.END, text + "\n")
        self.results_box.config(state=tk.DISABLED)

    def clear_results(self):
        """Clear the results text box."""
        self.results_box.config(state=tk.NORMAL)
        self.results_box.delete("1.0", tk.END)
        self.results_box.config(state=tk.DISABLED)
        self.status_var.set("Cleared results")

    # ----------------------
    # Core features
    # ----------------------
    def run_scan(self):
        """
        Run a full analysis and present results.
        Saves the last analysis + report for export.
        """
        user_input = self.entry.get().strip()
        if not user_input:
            messagebox.showwarning("Input required", "Please enter a website or domain to analyze.")
            return

        domain = normalize_domain(user_input)
        self.status_var.set(f"Scanning {domain} ...")
        self.update_idletasks()

        # Combine built-in trusted with user-managed trusted for this run
        combined_trusted = list(set(SIMULATED_DB.get("trusted", []) + self.user_trusted))

        analysis = analyze_domain(domain, combined_trusted)
        # Create a human-friendly report text
        report_text = generate_report_text(analysis)
        # Display succinct result for demo viewers (plain English)
        display_text = []
        display_text.append(f"Checked: {analysis['domain']}")
        display_text.append(f"Time: {analysis['timestamp']}")
        display_text.append("")
        display_text.append(f"Verdict: {analysis['verdict']}")
        display_text.append("")
        display_text.append("Why we reached this verdict:")
        for i, line in enumerate(analysis["explanation_lines"], 1):
            display_text.append(f" {i}. {line}")
        display_text.append("")
        display_text.append("Suggested action:")
        if analysis["verdict"] == "Safe":
            display_text.append(" - Site appears safe. No immediate defensive action required.")
        elif analysis["verdict"] == "Suspicious":
            display_text.append(" - Use caution. Consider manual review or temporary monitoring/blocking.")
        elif analysis["verdict"] == "Dangerous":
            display_text.append(" - Block, quarantine related artifacts, and investigate any associated alerts.")
        else:
            display_text.append(" - Inconclusive: consider additional sources for confirmation.")

        self.set_results_text("\n".join(display_text))

        # Save last analysis and report
        self.last_analysis = analysis
        try:
            path = save_report(analysis)
            self.last_report_path = path
            self.status_var.set(f"Scan complete. Report saved to {path}")
        except Exception as e:
            self.last_report_path = None
            self.status_var.set(f"Scan complete. Failed to save report: {e}")

    def add_to_trusted(self):
        """
        Add the current entry to the user-trusted list and persist to disk.
        This allows the demo user or SOC analyst to mark verified-good sites.
        """
        user_input = self.entry.get().strip()
        if not user_input:
            messagebox.showwarning("Input required", "Please enter a website or domain to add.")
            return
        domain = normalize_domain(user_input)
        if domain in self.user_trusted:
            messagebox.showinfo("Already trusted", f"{domain} is already in your trusted list.")
            return
        self.user_trusted.append(domain)
        saved = save_trusted_store(self.user_trusted)
        if saved:
            messagebox.showinfo("Trusted added", f"{domain} has been added to your trusted list.")
            self.status_var.set(f"Added trusted site: {domain}")
        else:
            messagebox.showwarning("Save failed", "Could not save trusted list to disk.")

    def show_trusted_sites(self):
        """Show the user-managed trusted list in a small window."""
        popup = tk.Toplevel(self)
        popup.title("User Trusted Sites")
        txt = tk.Text(popup, width=60, height=20)
        txt.pack(padx=8, pady=8)
        for d in sorted(self.user_trusted):
            txt.insert(tk.END, d + "\n")
        txt.config(state=tk.DISABLED)

    def show_builtin_lists(self):
        """Show the built-in simulated lists in a small window."""
        popup = tk.Toplevel(self)
        popup.title("Built-in Reputation Lists")
        txt = tk.Text(popup, width=80, height=25)
        txt.pack(padx=8, pady=8)
        txt.insert(tk.END, "Trusted (built-in):\n")
        for d in SIMULATED_DB.get("trusted", []):
            txt.insert(tk.END, "  " + d + "\n")
        txt.insert(tk.END, "\nSuspicious (built-in):\n")
        for d in SIMULATED_DB.get("suspicious", []):
            txt.insert(tk.END, "  " + d + "\n")
        txt.insert(tk.END, "\nMalicious (built-in):\n")
        for d in SIMULATED_DB.get("malicious", []):
            txt.insert(tk.END, "  " + d + "\n")
        txt.config(state=tk.DISABLED)

    def export_last_report(self):
        """
        If a report was generated by the last scan, allow the user to save a copy
        to another location. Otherwise prompt to run a scan first.
        """
        if not self.last_report_path or not os.path.exists(self.last_report_path):
            messagebox.showinfo("No report", "No report available. Please run a scan first.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("Text files", "*.txt")],
                                            initialfile=os.path.basename(self.last_report_path))
        if not dest:
            return
        try:
            with open(self.last_report_path, "r", encoding="utf-8") as fsrc:
                data = fsrc.read()
            with open(dest, "w", encoding="utf-8") as fdst:
                fdst.write(data)
            messagebox.showinfo("Exported", f"Report exported to {dest}")
        except Exception as e:
            messagebox.showerror("Export failed", f"Could not export report: {e}")

    def show_future_features(self):
        """List of professional extensions for the project roadmap."""
        features = (
            "• Integrate multiple live threat intelligence APIs (VirusTotal, AbuseIPDB)\n"
            "• Passive DNS / WHOIS enrichment and domain-age checks\n"
            "• Automated batch scanning and scheduling\n"
            "• Export to PDF and shareable incident tickets (JIRA, ServiceNow)\n"
            "• More advanced heuristics: certificate chain, DKIM/SPF header analysis for emails\n"
        )
        messagebox.showinfo("Future Features", features)


# ---------------------------
# Run the application
# ---------------------------
def main():
    # On startup, ensure we load any user trusted sites
    app = IOCApp()
    app.user_trusted = load_trusted_store()
    app.mainloop()


if __name__ == "__main__":
    main()

from modules.base import BaseScanner
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


class CMDiScanner(BaseScanner):

    def __init__(self, target_url, session, config):
        super().__init__(target_url, session, config)

        # Track duplicates: (page + input) or (page + param)
        self.seen_form_vulns = set()
        self.seen_url_vulns = set()

    # ======================================================
    # MAIN ENTRY
    # ======================================================
    def scan(self, forms=None, urls=None):
        self.logger.info(f"Scanning for Command Injection on {self.target_url}")

        payloads = self.load_payloads("wordlists/cmdi_payloads.txt")

        # -------- FORM TESTING --------
        if forms:
            for form in forms:
                result = self.scan_form_for_cmdi(form, payloads)
                if not result:
                    continue

                field, payload, action = result
                vuln_id = f"{action}|{field}"

                if vuln_id in self.seen_form_vulns:
                    continue

                self.seen_form_vulns.add(vuln_id)

                desc = (
                    f"Command Injection found! Form Field: {field} | "
                    f"Payload: {payload} | Action: {action}"
                )
                self.add_vulnerability("Command Injection", desc, "High")

        # -------- URL TESTING --------
        if urls:
            for url in urls:
                result = self.scan_url_for_cmdi(url, payloads)
                if not result:
                    continue

                param, payload, test_url = result

                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                vuln_id = f"{base_url}|{param}"
                if vuln_id in self.seen_url_vulns:
                    continue

                self.seen_url_vulns.add(vuln_id)

                desc = (
                    f"Command Injection found in URL! Param: {param} | "
                    f"Payload: {payload} | URL: {test_url}"
                )
                self.add_vulnerability("Command Injection", desc, "High")

    # ======================================================
    # PAYLOADS
    # ======================================================
    def load_payloads(self, path):
        if os.path.exists(path):
            with open(path, "r") as f:
                return [p.strip() for p in f if p.strip()]

        # DEFAULT WORKING PAYLOADS (DVWA compatible)
        return [
            ";id",
            "&& id",
            "| id",
            ";whoami",
            "&& whoami",
            "| whoami",
            ";uname -a",
            "&& uname -a",
            "| uname -a",
            ";cat /etc/passwd",
        ]

    # ======================================================
    # DETECTION LOGIC
    # ======================================================
    def detect_cmdi(self, response, payload):

        body = response.text.lower()

        reflections = [
            "uid=", "gid=", "www-data", "root",
            "command not found",
            "not recognized as an internal",
            "cannot find",
            "not found",
            "sh:", "bash:",
        ]

        for r in reflections:
            if r in body:
                return True

        # Check if command echo appears anywhere
        cmd_word = payload.replace(";", "").replace("|", "").replace("&&", "").strip()
        if cmd_word and cmd_word in body:
            return True

        return False

    # ======================================================
    # FORM TESTER
    # ======================================================
    def scan_form_for_cmdi(self, form, payloads):

        action = form.get("action")
        inputs = form.get("inputs", [])

        # Base values for all fields
        base_data = {i["name"]: "test" for i in inputs if i.get("name")}

        for inp in inputs:
            field = inp.get("name")
            if not field:
                continue

            for payload in payloads:
                test_data = base_data.copy()
                test_data[field] = payload

                response = self.session.post(action, data=test_data)

                if self.detect_cmdi(response, payload):
                    return (field, payload, action)

        return None

    # ======================================================
    # URL TESTER
    # ======================================================
    def scan_url_for_cmdi(self, url, payloads):

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return None

        for param in params:
            for payload in payloads:

                test_params = {k: v[:] for k, v in params.items()}
                test_params[param] = [payload]  # FIX: must be list for urlencode

                test_query = urlencode(test_params, doseq=True)

                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, test_query, parsed.fragment
                ))

                response = self.session.get(test_url)

                if self.detect_cmdi(response, payload):
                    return (param, payload, test_url)

        return None

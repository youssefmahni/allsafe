import json

def save_report(vulnerabilities, output_file):
    if not output_file:
        return

    try:
        with open(output_file, 'w') as f:
            if output_file.endswith('.json'):
                json.dump(vulnerabilities, f, indent=4)
            else:
                for vuln in vulnerabilities:
                    f.write(f"[{vuln['severity']}] {vuln['type']}: {vuln['details']} ({vuln['url']})\n")
        print(f"Report saved to {output_file}")
    except Exception as e:
        print(f"Error saving report: {e}")

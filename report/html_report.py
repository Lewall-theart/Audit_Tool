
from html import escape


class HtmlReport:
    def generate(self, data, path):
        if "hosts" not in data:
            self._generate_single_host_report(data, path)
            return

        summary = data["summary"]
        html = [
            "<html><head><meta charset='utf-8'>",
            "<style>",
            "body{font-family:Segoe UI,Arial,sans-serif;padding:20px;}",
            "table{border-collapse:collapse;width:100%;margin:10px 0 20px 0;}",
            "th,td{border:1px solid #ddd;padding:8px;text-align:left;}",
            "th{background:#f4f4f4;}",
            ".pass{color:#0a7f3f;font-weight:600;}",
            ".fail{color:#b42318;font-weight:600;}",
            ".unknown{color:#6b7280;font-weight:600;}",
            "</style></head><body>",
            "<h1>Windows Security Audit</h1>",
            f"<p><strong>Total hosts:</strong> {summary.get('total_hosts', 0)}</p>",
            f"<p><strong>Overall score:</strong> {summary.get('score', 0):.2f}%</p>",
            f"<p><strong>Passed / Failed / Unknown:</strong> {summary.get('passed', 0)} / {summary.get('failed', 0)} / {summary.get('unknown', 0)}</p>",
            "<h2>Host Summary</h2>",
            "<table><tr><th>Host</th><th>Score</th><th>Passed</th><th>Failed</th><th>Unknown</th></tr>",
        ]

        for host_result in data["hosts"]:
            host = escape(str(host_result.get("host", "unknown")))
            host_summary = host_result.get("summary", {})
            html.append(
                "<tr>"
                f"<td>{host}</td>"
                f"<td>{host_summary.get('score', 0):.2f}%</td>"
                f"<td>{host_summary.get('passed', 0)}</td>"
                f"<td>{host_summary.get('failed', 0)}</td>"
                f"<td>{host_summary.get('unknown', 0)}</td>"
                "</tr>"
            )
        html.append("</table>")

        for host_result in data["hosts"]:
            host = escape(str(host_result.get("host", "unknown")))
            source = escape(str(host_result.get("source", "")))
            html.append(f"<h3>{host}</h3>")
            if source:
                html.append(f"<p><strong>Source:</strong> {source}</p>")
            html.append("<table><tr><th>Control</th><th>Expected</th><th>Observed</th><th>Status</th><th>Evidence</th></tr>")
            for detail in host_result.get("details", []):
                status = str(detail.get("status", "UNKNOWN")).upper()
                status_class = {
                    "PASS": "pass",
                    "FAIL": "fail",
                    "UNKNOWN": "unknown",
                }.get(status, "unknown")
                html.append(
                    "<tr>"
                    f"<td>{escape(str(detail.get('control', '')))}</td>"
                    f"<td>{escape(str(detail.get('expected', '')))}</td>"
                    f"<td>{escape(str(detail.get('observed', '')))}</td>"
                    f"<td class='{status_class}'>{status}</td>"
                    f"<td>{escape(str(detail.get('evidence', '')))}</td>"
                    "</tr>"
                )
            html.append("</table>")

        html.append("</body></html>")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))

    def _generate_single_host_report(self, data, path):
        html = "<h1>Windows Security Audit</h1>"
        html += f"<p>Score: {data['summary']['score']:.2f}%</p>"
        html += "<table border='1'><tr><th>Control</th><th>Status</th></tr>"

        for r in data["details"]:
            html += f"<tr><td>{escape(str(r['control']))}</td><td>{escape(str(r['status']))}</td></tr>"

        html += "</table>"

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

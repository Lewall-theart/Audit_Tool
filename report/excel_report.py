
import csv

class ExcelReport:
    def generate(self, data, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            if "hosts" not in data:
                writer.writerow(["Control", "Expected", "Observed", "Status"])
                for r in data["details"]:
                    writer.writerow([r["control"], r["expected"], r["observed"], r["status"]])
                return

            summary = data.get("summary", {})
            writer.writerow(["Metric", "Value"])
            writer.writerow(["Total hosts", summary.get("total_hosts", 0)])
            writer.writerow(["Overall score", f"{summary.get('score', 0):.2f}%"])
            writer.writerow(["Passed", summary.get("passed", 0)])
            writer.writerow(["Failed", summary.get("failed", 0)])
            writer.writerow(["Unknown", summary.get("unknown", 0)])
            writer.writerow([])

            writer.writerow(["Host", "Control", "Expected", "Observed", "Status", "Evidence", "Source"])
            for host_result in data["hosts"]:
                host = host_result.get("host", "")
                source = host_result.get("source", "")
                for r in host_result.get("details", []):
                    writer.writerow(
                        [
                            host,
                            r.get("control"),
                            r.get("expected"),
                            r.get("observed"),
                            r.get("status"),
                            r.get("evidence"),
                            source,
                        ]
                    )

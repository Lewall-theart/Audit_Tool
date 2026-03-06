
from datetime import datetime
from pathlib import Path

from inputs.log_file_loader import LogFileLoader
from analyzers.log_parser import LogParser
from analyzers.attribute_extractor import AttributeExtractor
from analyzers.evidence_builder import EvidenceBuilder
from engine.mapping_engine import MappingEngine
from engine.evaluation_engine import EvaluationEngine
from engine.compliance_engine import ComplianceEngine
from report.json_report import JsonReport
from report.html_report import HtmlReport
from report.excel_report import ExcelReport


def analyze_host(log_item, parser, extractor, evidence_builder, mapping, evaluator, compliance):
    parsed = parser.parse(log_item["lines"])
    attributes = extractor.extract(parsed)
    evidence = evidence_builder.build(attributes)
    mapped = mapping.map(evidence)
    results = evaluator.evaluate(mapped)
    compliance_result = compliance.calculate(results)

    for detail in compliance_result["details"]:
        detail["host"] = log_item["host"]
        detail["source"] = log_item["path"]

    compliance_result["host"] = log_item["host"]
    compliance_result["source"] = log_item["path"]
    return compliance_result


def summarize(host_results):
    total_hosts = len(host_results)
    total_controls = sum(item["summary"]["total_controls"] for item in host_results)
    passed = sum(item["summary"]["passed"] for item in host_results)
    failed = sum(item["summary"]["failed"] for item in host_results)
    unknown = sum(item["summary"]["unknown"] for item in host_results)
    evaluated = sum(item["summary"]["evaluated_controls"] for item in host_results)
    score = (passed / evaluated * 100) if evaluated else 0

    return {
        "summary": {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "total_hosts": total_hosts,
            "total_controls": total_controls,
            "passed": passed,
            "failed": failed,
            "unknown": unknown,
            "evaluated_controls": evaluated,
            "score": score,
        },
        "hosts": host_results,
    }


def generate_report_with_fallback(generator, data, output_path):
    try:
        generator.generate(data, output_path)
        return output_path
    except PermissionError:
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fallback_path = output_path.with_name(f"{output_path.stem}_{timestamp}{output_path.suffix}")
        generator.generate(data, fallback_path)
        return fallback_path


def main():
    logs_dir = Path("logs/windows")
    output_dir = Path("output")
    output_dir.mkdir(parents=True, exist_ok=True)

    loader = LogFileLoader()
    log_items = loader.load_directory(logs_dir)
    if not log_items:
        print(f"No log files found in: {logs_dir}")
        return

    parser = LogParser()
    extractor = AttributeExtractor()
    evidence_builder = EvidenceBuilder()
    mapping = MappingEngine()
    evaluator = EvaluationEngine()
    compliance = ComplianceEngine()

    host_results = [
        analyze_host(log_item, parser, extractor, evidence_builder, mapping, evaluator, compliance)
        for log_item in log_items
    ]
    audit_result = summarize(host_results)

    json_path = generate_report_with_fallback(JsonReport(), audit_result, output_dir / "report.json")
    html_path = generate_report_with_fallback(HtmlReport(), audit_result, output_dir / "report.html")
    csv_path = generate_report_with_fallback(ExcelReport(), audit_result, output_dir / "report.csv")

    print(
        f"Audit completed. Processed {len(host_results)} log files from {logs_dir}. "
        f"Reports generated: {json_path}, {html_path}, {csv_path}"
    )


if __name__ == "__main__":
    main()


class ComplianceEngine:
    def calculate(self, results):
        total = len(results)
        passed = sum(1 for r in results if r["status"]=="PASS")
        failed = sum(1 for r in results if r["status"]=="FAIL")
        unknown = sum(1 for r in results if r["status"]=="UNKNOWN")
        evaluated = passed + failed
        score = (passed/evaluated*100) if evaluated else 0

        return {
            "summary":{
                "total_controls": total,
                "passed": passed,
                "failed": failed,
                "unknown": unknown,
                "evaluated_controls": evaluated,
                "score": score
            },
            "details":results
        }

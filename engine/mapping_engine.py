
import json

class MappingEngine:
    def __init__(self):
        with open("knowledge_base/windows_security_baseline.json") as f:
            self.baseline = json.load(f)

    def map(self, evidence):
        mapped = []
        for e in evidence:
            key = e["control"]
            expected = self.baseline.get(key)
            mapped.append({
                "control": key,
                "expected": expected,
                "observed": e["observed_value"],
                "evidence": e["evidence"]
            })
        return mapped

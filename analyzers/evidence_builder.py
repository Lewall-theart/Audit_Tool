
class EvidenceBuilder:
    def build(self, attributes):
        evidence = []
        for attr in attributes:
            evidence.append({
                "control": attr["attribute"],
                "observed_value": attr["value"],
                "evidence": attr.get("evidence", "Collected from log analysis")
            })
        return evidence

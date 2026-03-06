
class EvaluationEngine:
    def evaluate(self, mapped_controls):
        results = []
        for control in mapped_controls:
            status = self._evaluate_control(control["expected"], control["observed"])
            control["status"] = status
            results.append(control)
        return results

    def _evaluate_control(self, expected, observed):
        if expected is None or observed is None:
            return "UNKNOWN"

        if isinstance(expected, dict):
            return self._evaluate_with_operator(expected, observed)

        if isinstance(expected, bool):
            return "PASS" if bool(observed) is expected else "FAIL"

        return "PASS" if str(expected).strip().lower() == str(observed).strip().lower() else "FAIL"

    def _evaluate_with_operator(self, expected, observed):
        operator = expected.get("operator", "eq")

        if operator == "eq":
            target = expected.get("value")
            if target is None:
                return "UNKNOWN"
            if isinstance(target, str):
                return "PASS" if str(observed).strip().lower() == target.strip().lower() else "FAIL"
            return "PASS" if observed == target else "FAIL"

        observed_number = self._to_number(observed)
        if observed_number is None:
            return "FAIL"

        if operator == "gte":
            target = self._to_number(expected.get("value"))
            if target is None:
                return "UNKNOWN"
            return "PASS" if observed_number >= target else "FAIL"

        if operator == "lte":
            target = self._to_number(expected.get("value"))
            if target is None:
                return "UNKNOWN"
            return "PASS" if observed_number <= target else "FAIL"

        if operator == "between":
            min_value = self._to_number(expected.get("min"))
            max_value = self._to_number(expected.get("max"))
            if min_value is None or max_value is None:
                return "UNKNOWN"
            return "PASS" if min_value <= observed_number <= max_value else "FAIL"

        return "UNKNOWN"

    @staticmethod
    def _to_number(value):
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

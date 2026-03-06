
class LogParser:
    def parse(self, logs):
        parsed = []
        for line_number, line in enumerate(logs, start=1):
            cleaned = line.strip()
            if not cleaned:
                continue
            parsed.append({"line_number": line_number, "raw": cleaned})
        return parsed

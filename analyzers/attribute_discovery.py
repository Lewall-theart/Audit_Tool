
class AttributeDiscovery:
    def discover(self, logs):
        discovered = set()
        for line in logs:
            parts = line.split()
            for p in parts:
                if "=" in p:
                    discovered.add(p.split("=")[0])
        return list(discovered)

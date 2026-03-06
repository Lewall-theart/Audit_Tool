
from collectors.firewall import FirewallCollector
from collectors.defender import DefenderCollector
from collectors.registry import RegistryCollector
from collectors.eventlog import EventLogCollector
from collectors.systeminfo import SystemInfoCollector

class LiveCollector:
    def collect_all(self):
        data = {}
        data.update(FirewallCollector().collect())
        data.update(DefenderCollector().collect())
        data.update(RegistryCollector().collect())
        data["events"] = EventLogCollector().collect()
        data.update(SystemInfoCollector().collect())
        return data

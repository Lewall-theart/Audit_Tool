
class MicrosoftDocs:
    DOCS = {
        "firewall_enabled": "https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/"
    }

    def get_doc(self, key):
        return self.DOCS.get(key,"")

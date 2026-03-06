
import json

class JsonReport:
    def generate(self, data, path):
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data,f,indent=2)

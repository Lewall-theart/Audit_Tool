
from pathlib import Path


class LogFileLoader:
    def load(self, filepath):
        path = Path(filepath)
        if not path.is_file():
            return []

        data = path.read_bytes()
        text = data.decode("utf-8", errors="replace").replace("\x00", "")
        return text.splitlines()

    def load_directory(self, directory, pattern="*.txt"):
        directory_path = Path(directory)
        if not directory_path.is_dir():
            return []

        logs = []
        for file_path in sorted(directory_path.glob(pattern)):
            if not file_path.is_file():
                continue

            logs.append(
                {
                    "host": file_path.stem,
                    "path": str(file_path),
                    "lines": self.load(file_path),
                }
            )
        return logs

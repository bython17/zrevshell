from pathlib import Path
import json


def log(focus_message: str, description):
    print(f"[{focus_message.upper()}] {description}")


def write_json(file_path: Path, data: dict):
    file_path.write_text(json.dumps(data))


def read_json(file_path: Path):
    if not file_path.is_file():
        file_path.write_text("{}")
    return json.loads(file_path.read_text())

import json
from pathlib import Path

import pytest


@pytest.fixture
def synthetic_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "synthetic"


@pytest.fixture
def raw_event(synthetic_dir: Path) -> dict:
    path = synthetic_dir / "normal_activity.json"
    return json.loads(path.read_text(encoding="utf-8"))["Records"][0]

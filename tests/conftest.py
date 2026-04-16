import pytest
from pathlib import Path


@pytest.fixture
def tmp(tmp_path: Path) -> Path:
    """Alias pytest's built-in tmp_path fixture as 'tmp' for all tests."""
    return tmp_path

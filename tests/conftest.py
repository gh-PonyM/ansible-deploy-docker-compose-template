import shutil
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def fixture_path():
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="function")
def temporary_directory():
    """Provides a temporary directory that is removed after the test."""
    directory = tempfile.mkdtemp()
    yield Path(directory)
    shutil.rmtree(directory)


@pytest.fixture(scope="session")
def output_dir():
    out = Path(__file__).parent.parent / "generated"
    if not out.is_dir():
        out.mkdir()
    return out

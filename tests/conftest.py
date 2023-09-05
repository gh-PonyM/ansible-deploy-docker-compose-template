import contextlib
import os
import shutil
import tempfile
from pathlib import Path

import pytest
from click.testing import CliRunner
import typing as t


@pytest.fixture(scope="session")
def fixture_path():
    return Path(__file__).parent / "fixtures"


@contextlib.contextmanager
def cd_to_directory(path: Path, env: t.Optional[dict] = None):
    """Changes working directory and returns to previous on exit."""
    prev_cwd = Path.cwd()
    os.chdir(path)
    if env:
        for k, v in env.items():
            os.environ[k] = v
    try:
        yield
    finally:
        os.chdir(prev_cwd)
        if env:
            for k in env:
                os.environ[k] = ""


@pytest.fixture(scope="function")
def temporary_directory():
    """Provides a temporary directory that is removed after the test."""
    directory = tempfile.mkdtemp()
    yield Path(directory)
    shutil.rmtree(directory)


@pytest.fixture()
def runner(temporary_directory):
    with cd_to_directory(
        temporary_directory, env={}
    ):
        yield CliRunner()

"""Smoke tests: prove the package installs and the CLI entry point runs."""

import iampath
from iampath.cli import main


def test_package_imports_from_src():
    package_file_path = iampath.__file__
    assert "src/iampath" in package_file_path


def test_cli_main_prints_banner(capsys):
    main()
    printed_output = capsys.readouterr().out
    assert "iampath 0.1.0" in printed_output

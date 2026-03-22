# Copyright 2026 cvemula1. Licensed under the Apache License, Version 2.0
# Tests for CLI

from __future__ import annotations

import pytest

from tif.cli import main


class TestCLI:
    def test_version(self):
        assert main(["version"]) == 0

    def test_version_flag(self):
        assert main(["--version"]) == 0

    def test_no_args_shows_help(self, capsys):
        assert main([]) == 0

    def test_demo_table(self, capsys):
        assert main(["demo"]) == 0
        captured = capsys.readouterr()
        assert "Trust" in captured.out

    def test_demo_json(self, capsys):
        assert main(["demo", "-f", "json"]) == 0
        captured = capsys.readouterr()
        import json
        card = json.loads(captured.out)
        assert card["verdict"] == "WARN"
        assert card["trust_score"] > 0

    def test_demo_ascii(self):
        assert main(["demo", "--ascii"]) == 0

    def test_policy_list(self, capsys):
        assert main(["policy", "list"]) == 0
        captured = capsys.readouterr()
        assert "default" in captured.out
        assert "cis-l1" in captured.out

    def test_policy_check_from_file(self, tmp_path, capsys):
        # Write a sample Trust Card
        from tif.core.verifier import build_demo_card
        card = build_demo_card()
        card_file = tmp_path / "card.json"
        card_file.write_text(card.to_json())

        result = main(["policy", "check", str(card_file), "--policy-pack", "default"])
        assert result == 0

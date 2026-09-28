"""Tests for flowhound.__main__ (CLI entry-point)."""

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from flowhound.__main__ import main


class TestMain:
    def test_help_exits_cleanly(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0

    def test_has_attack_and_sniff_commands(self):
        assert "attack" in main.commands
        assert "sniff" in main.commands

    def test_invokes_attack_subcommand(self):
        runner = CliRunner()
        with patch(
            "flowhound.cli.command.detect_target",
            return_value=("langflow", "1.0.0"),
        ):
            db_mock = MagicMock()
            db_mock.retrieve_vulnerabilities.return_value = []
            with patch("flowhound.__main__.Database", return_value=db_mock):
                result = runner.invoke(
                    main, ["attack", "--url", "http://localhost:7860"]
                )
        assert result.exit_code == 0

    def test_invokes_sniff_subcommand(self):
        runner = CliRunner()
        with patch(
            "flowhound.cli.command.detect_target",
            return_value=("langflow", "1.0.0"),
        ):
            db_mock = MagicMock()
            db_mock.retrieve_vulnerabilities.return_value = []
            with patch("flowhound.__main__.Database", return_value=db_mock):
                result = runner.invoke(
                    main, ["sniff", "--url", "http://localhost:7860"]
                )
        assert result.exit_code == 0

    def test_sets_database_instance_on_context(self):
        runner = CliRunner()
        with patch("flowhound.__main__.Database") as mock_db_cls:
            mock_db_cls.return_value.retrieve_vulnerabilities.return_value = []
            with patch(
                "flowhound.cli.command.detect_target",
                return_value=("langflow", "1.0.0"),
            ):
                result = runner.invoke(
                    main, ["attack", "--url", "http://localhost:7860"]
                )
        assert mock_db_cls.called
        assert result.exit_code == 0

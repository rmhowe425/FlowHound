import sys
import logging
import pytest
from unittest.mock import patch, MagicMock
from flowhound.cli.message_format import ClickLogHandler, output_banner


# ---------------------------------------------------------------------------
# ClickLogHandler.emit
# ---------------------------------------------------------------------------

emit_levels = [
    (logging.DEBUG,    'debug message',    '[-] '),
    (logging.INFO,     'info message',     '[+] '),
    (logging.WARNING,  'warning message',  '[!] '),
    (logging.ERROR,    'error message',    '[!] '),
    (logging.CRITICAL, 'critical message', '[CRITICAL] '),
]


@pytest.mark.parametrize("level, message, expected_prefix", emit_levels)
def test_emit_writes_to_correct_stream(level, message, expected_prefix):
    handler = ClickLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))

    record = logging.LogRecord(
        name='flowhound.test',
        level=level,
        pathname='',
        lineno=0,
        msg=message,
        args=(),
        exc_info=None,
    )

    captured = []

    with patch('flowhound.cli.message_format.echo', side_effect=lambda s, file=None: captured.append(s)):
        handler.emit(record)

    assert len(captured) == 1
    assert expected_prefix in captured[0]
    assert message in captured[0]


def test_emit_exploit_logger_uses_green():
    handler = ClickLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))

    record = logging.LogRecord(
        name='flowhound.vulnerabilities.exploits.cve_2026_9198',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='exploit info',
        args=(),
        exc_info=None,
    )

    styled_calls = []
    with patch('flowhound.cli.message_format.style', side_effect=lambda s, **kw: styled_calls.append(kw) or s):
        with patch('flowhound.cli.message_format.echo'):
            handler.emit(record)

    assert any(call.get('fg') == 'green' for call in styled_calls)


def test_emit_error_writes_to_stderr():
    handler = ClickLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))

    record = logging.LogRecord(
        name='flowhound.test',
        level=logging.ERROR,
        pathname='',
        lineno=0,
        msg='an error',
        args=(),
        exc_info=None,
    )

    streams = []
    with patch('flowhound.cli.message_format.echo', side_effect=lambda s, file=None: streams.append(file)):
        handler.emit(record)

    assert streams[0] is sys.stderr


def test_emit_info_writes_to_stdout():
    handler = ClickLogHandler()
    handler.setFormatter(logging.Formatter('%(message)s'))

    record = logging.LogRecord(
        name='flowhound.test',
        level=logging.INFO,
        pathname='',
        lineno=0,
        msg='some info',
        args=(),
        exc_info=None,
    )

    streams = []
    with patch('flowhound.cli.message_format.echo', side_effect=lambda s, file=None: streams.append(file)):
        handler.emit(record)

    assert streams[0] is sys.stdout


# ---------------------------------------------------------------------------
# output_banner
# ---------------------------------------------------------------------------

def test_output_banner_writes_to_stdout():
    streams = []
    with patch('flowhound.cli.message_format.echo', side_effect=lambda s, file=None: streams.append(file)):
        output_banner('test banner')

    assert streams[0] is sys.stdout


def test_output_banner_includes_message():
    captured = []
    with patch('flowhound.cli.message_format.echo', side_effect=lambda s, file=None: captured.append(s)):
        output_banner('hello world')

    assert any('hello world' in c for c in captured)

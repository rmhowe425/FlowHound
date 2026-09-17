import sys
from click import echo, style

def output_banner(msg: str):
    echo(style(msg, fg='blue'), file=sys.stdout)
    sys.stdout.flush()

def output_status(msg: str, space: bool = False):
    if space:
        echo(style(f'\n[+] {msg}', fg='blue'), file=sys.stdout)
    else:
        echo(style(f'[+] {msg}', fg='blue'), file=sys.stdout)
    sys.stdout.flush()

def output_warning(msg: str):
    echo(style(f'[!] {msg}', fg='yellow'), file=sys.stdout)
    sys.stdout.flush()


def output_error(msg: str):
    echo(style(f'[!] {msg}', fg='red'), file=sys.stdout)
    sys.stderr.flush()


def exploit_status(msg: str):
    echo(style(f'[*] {msg}', fg='green'), file=sys.stdout)
    sys.stdout.flush()


def exploit_warning(msg: str):
    echo(style(f'[!] {msg}', fg='green'), file=sys.stdout)
    sys.stdout.flush()

import click
from flowhound.cli.command import attack, search

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(context_settings=CONTEXT_SETTINGS)
def main():
    pass


main.add_command(attack)
main.add_command(search)

if __name__ == '__main__':
    main()

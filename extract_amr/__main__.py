"""Run the extract-amr command."""

from .cli import cli


if __name__ == "__main__":
    import sys
    sys.argv.extend(["inspect", "pcaps/1.pcapng", "--progress"])
    cli()

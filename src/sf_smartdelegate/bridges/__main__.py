"""`python -m sf_smartdelegate.bridges <subcommand>`: the same as `smartdelegate bridge <subcommand>`."""
import sys

from .cli import main

sys.exit(main())

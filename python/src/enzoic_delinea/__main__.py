"""Allow `python -m enzoic_delinea`."""

import sys

from .delinea import main

if __name__ == "__main__":
    sys.exit(main())

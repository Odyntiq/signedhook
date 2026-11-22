"""Enable ``python -m signedhook`` execution of the CLI."""

from .cli import main

raise SystemExit(main())

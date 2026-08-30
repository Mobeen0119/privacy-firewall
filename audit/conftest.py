"""Makes `import hash_chain` / `import sign` work when pytest is run from
the repo root (`pytest audit` or `npm run test:py`)."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

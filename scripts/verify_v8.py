#!/usr/bin/env python3
"""
Backward-compatible entry point delegating to ANTI V9 Bounded Async Orchestrator (`scripts/verify_v9.py`).
"""

import sys
from verify_v9 import main

if __name__ == "__main__":
    sys.exit(main())

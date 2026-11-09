#!/usr/bin/env python3
"""Run the public-API regression for replacing an active disk's pathname."""
import os
from pathlib import Path
import runpy

os.environ["KRUN_TEST_REPLACED_DISK"] = "1"
runpy.run_path(str(Path(__file__).with_name("run.py")), run_name="__main__")

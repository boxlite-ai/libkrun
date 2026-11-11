#!/usr/bin/env python3
"""Native HVF process-exit/save/restore regression.
Usage: python3 tests/checkpoint/run-hvf.py /directory/containing/libkrunfw.5.dylib
Requires the local Linux sysroot and cargo build -p libkrun --features blk,net.
"""
from pathlib import Path
import platform
import runpy
assert platform.system() == "Darwin" and platform.machine() == "arm64"
runpy.run_path(str(Path(__file__).with_name("run.py")), run_name="__main__")

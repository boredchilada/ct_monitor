#!/usr/bin/env python3
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ct_monitor.main import main

if __name__ == "__main__":
    main()
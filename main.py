#!/usr/bin/env python3
import sys
from core import menu

def main():
    try:
        menu.main_menu()
    except KeyboardInterrupt:
        print("\n[!] Exiting RedPhantom...")
        sys.exit(0)

if __name__ == "__main__":
    main()

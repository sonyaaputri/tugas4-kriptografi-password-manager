import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli import PasswordManagerCLI

if __name__ == "__main__":
    PasswordManagerCLI().run()

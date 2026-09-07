import pathlib
import sys

# cli/ isn't a package (seed.py is meant to be run as a script, not imported
# via a package path) -- add it to sys.path directly so tests can `import seed`.
CLI_DIR = pathlib.Path(__file__).resolve().parent.parent / "cli"
sys.path.insert(0, str(CLI_DIR))

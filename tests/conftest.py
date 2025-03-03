import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent.parent / "src"
core_path = src_path / "core"
sys.path.append(str(core_path))
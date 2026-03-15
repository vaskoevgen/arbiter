# Bridge: makes `from src.config import ...` resolve to arbiter.config
import sys
import importlib

# Ensure arbiter.config is importable
from arbiter import config as _config_mod

# Register src.config in sys.modules so `from src.config import ...` works
sys.modules[f"{__name__}.config"] = _config_mod

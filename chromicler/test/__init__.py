# Test configuration and fixtures
import sys
from pathlib import Path

# Add the chromicler package to the path for testing
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

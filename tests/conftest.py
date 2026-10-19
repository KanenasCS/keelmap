import os
import sys
from pathlib import Path

# Every test runs with evidence verification on, see keelmap.model.VERIFY_EVIDENCE.
os.environ["KEELMAP_VERIFY_EVIDENCE"] = "1"
sys.path.insert(0, str(Path(__file__).parent))

"""Long fuzzing campaign. CI runs a short deterministic one in tests/test_fuzz_smoke.py.

Usage: python tools/fuzz.py [iterations] [seed]

Failures are kept as capture files in fuzz-findings/ (git-ignored). Seeds are
built from tests/pcapgen.py and the public fixtures only.
"""

import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(root / "src"), str(root / "tests")]

from fuzzing import run  # noqa: E402
from seeds import build  # noqa: E402


def main() -> int:
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    seed = int(sys.argv[2]) if len(sys.argv) > 2 else int(time.time())
    out = root / "fuzz-findings"
    (out / "seeds").mkdir(parents=True, exist_ok=True)
    seeds = build(out / "seeds")
    start = time.time()
    failures = run(seeds, iterations, seed, out)
    print(f"{iterations} inputs, seed {seed}, {time.time() - start:.0f} s")
    for problem, path in failures.items():
        print(f"FAILURE {problem}\n        input kept at {path}")
    print("no failures" if not failures else f"{len(failures)} distinct failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

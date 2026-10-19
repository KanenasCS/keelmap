"""Short deterministic fuzzing run on every test run. tools/fuzz.py runs long campaigns."""

from fuzzing import run
from seeds import build


def test_fuzz_smoke(tmp_path):
    seeds = build(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    failures = run(seeds, iterations=800, seed=20261018, workdir=work)
    assert not failures, "\n".join(f"{k}  ({v})" for k, v in failures.items())

"""Run with uv run --locked --offline python harness.py --repo-root <checkout>."""

from patch_harness.cli import main

if __name__ == "__main__":
    raise SystemExit(main())

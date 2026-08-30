#!/usr/bin/env python3
"""
zt.py -- one command-line entry point for the whole toolkit (v1.4.0).

Instead of remembering which script does what, everything is a sub-command:

    python zt.py evaluate      # reproducible accuracy + latency (2,400 requests)
    python zt.py analyze       # ROC/PR-AUC, threshold sweep, evasion test
    python zt.py benchmark     # Isolation Forest vs LOF vs One-Class SVM
    python zt.py train         # (re)train the synthetic model and save it
    python zt.py test          # run the unit tests
    python zt.py serve         # start the Flask service (PEP + API + dashboard)

Sub-modules are imported lazily inside each handler on purpose: analyze.py and
benchmark_models.py each point config.DB_PATH at their own throwaway database when
imported, so importing them only when needed keeps the sub-commands isolated.
"""
import argparse
import sys


def _run_isolated(module_name, extra_argv=None):
    """Import a sub-module and call its main(). Several sub-modules parse sys.argv
    themselves, so we swap in a clean argv (just the program name plus any options
    the sub-command chose to forward) and restore it afterwards."""
    import importlib
    saved = sys.argv
    sys.argv = [module_name] + (extra_argv or [])
    try:
        importlib.import_module(module_name).main()
    finally:
        sys.argv = saved


def cmd_evaluate(args):
    extra = []
    if args.normal is not None:
        extra += ["--normal", str(args.normal)]
    if args.per_attack is not None:
        extra += ["--per-attack", str(args.per_attack)]
    _run_isolated("evaluate", extra)


def cmd_analyze(args):
    _run_isolated("analyze")


def cmd_benchmark(args):
    _run_isolated("benchmark_models")


def cmd_train(args):
    import engine
    print("Training synthetic model (%d normal + %d attack)..."
          % (args.normal, args.attack))
    engine.train_on_synthetic(n_normal=args.normal, n_attack=args.attack)
    print("Done. Model written to the configured MODEL_PATH.")


def cmd_test(args):
    # Prefer pytest; fall back to running test_core.py directly.
    try:
        import pytest
        raise SystemExit(pytest.main(["-q"]))
    except ImportError:
        import runpy
        runpy.run_module("test_core", run_name="__main__")


def cmd_serve(args):
    import os
    import config
    import app as flask_app
    flask_app.start_up()
    host = os.getenv("HOST", "127.0.0.1")
    print("Starting the service on http://%s:%d  (dashboard at /dashboard)"
          % (host, config.PORT))
    flask_app.app.run(host=host, port=config.PORT)


def build_parser():
    p = argparse.ArgumentParser(
        prog="zt",
        description="Adaptive Zero-Trust Access Control - unified CLI")
    sub = p.add_subparsers(dest="command", required=True)

    e = sub.add_parser("evaluate", help="reproducible accuracy + latency evaluation")
    e.add_argument("--normal", type=int, default=None, help="number of normal test requests")
    e.add_argument("--per-attack", type=int, default=None, help="requests per attack type (x5)")
    e.set_defaults(func=cmd_evaluate)
    sub.add_parser("analyze", help="ROC/PR-AUC, threshold sweep, evasion test").set_defaults(func=cmd_analyze)
    sub.add_parser("benchmark", help="compare IF vs LOF vs One-Class SVM").set_defaults(func=cmd_benchmark)

    t = sub.add_parser("train", help="(re)train the synthetic model")
    t.add_argument("--normal", type=int, default=2000, help="normal samples (default 2000)")
    t.add_argument("--attack", type=int, default=100, help="attack samples (default 100)")
    t.set_defaults(func=cmd_train)

    sub.add_parser("test", help="run the unit tests").set_defaults(func=cmd_test)
    sub.add_parser("serve", help="start the Flask service").set_defaults(func=cmd_serve)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

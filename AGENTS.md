# ebp.el implementation guide

The neighboring `ebp` repository is normative.  This repository implements
that contract for Emacs; it never expands the protocol by implementation
accident.

- Keep every `ebp-*.el` feature loadable on Emacs 30.1 with only built-ins and
  other files in this repository.
- The one exception is the optional `ebp-websocket.el`, the Emacs side of
  SPEC 5.5 `loopback-websocket`, which MAY require the `websocket` package
  (amendment #190 decision).  Nothing else may depend on it or on that
  package, and it must degrade to a clear load-time error, never a silent
  fallback, when the package is absent.
- Do not require, define, or dynamically reach into `jetpacs-*`, Glasspane, or
  another application namespace.
- Preserve byte-exact framing, authentication, revision, and receipt behavior.
- Add conformance coverage before changing observable protocol behavior.
- Compile into a temporary directory; never overwrite neighboring `.elc`
  files or editor backups.

Run `test/run-tests.sh` before handing off changes.  It needs the spec
checkout (`EBP_SPEC_DIR`, default `../ebp`) and, for the SPEC 5.5 module, a
checkout of ahyatt/emacs-websocket (`EBP_WEBSOCKET_DIR`, default
`../emacs/emacs-websocket`); it exits 2 rather than skipping when either is
missing.

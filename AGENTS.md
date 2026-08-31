# ebp.el implementation guide

The neighboring `ebp` repository is normative.  This repository implements
that contract for Emacs; it never expands the protocol by implementation
accident.

- Keep every `ebp-*.el` feature loadable on Emacs 30.1 with only built-ins and
  other files in this repository.
- Do not require, define, or dynamically reach into `jetpacs-*`, Glasspane, or
  another application namespace.
- Preserve byte-exact framing, authentication, revision, and receipt behavior.
- Add conformance coverage before changing observable protocol behavior.
- Compile into a temporary directory; never overwrite neighboring `.elc`
  files or editor backups.

Run `test/run-tests.sh` before handing off changes.

# ebp.el

Canonical Emacs 30.1+ implementation of the Emacs Bridge Protocol (EBP).
The normative protocol, machine-readable contract, and conformance goldens
live in the neighboring [`ebp`](../ebp) repository.

`lisp/ebp.el` owns transport framing, authentication, sessions, protocol
dispatch, revisions, receipts, and module plumbing.  The other `ebp-*.el`
files are reusable endpoint modules for synchronization, completion, sandboxed
paths, and durable receipt/work storage.  None may depend on Jetpacs or another
application.

Run the standalone gate with:

```sh
test/run-tests.sh
```

Set `EBP_SPEC_DIR` when the specification checkout is not at `../ebp`.

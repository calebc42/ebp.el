# ebp.el

Canonical Emacs 30.1+ implementation of the Emacs Bridge Protocol (EBP).
The normative protocol, machine-readable contract, and conformance goldens
live in the neighboring [`ebp`](../ebp) repository.

`lisp/ebp-wire.el` is the pure wire layer: JSON receiver rules, Content-Length
framing, the JSON-RPC envelope, pairing proofs, and the session state step.
`lisp/ebp.el` is the client engine on top of it: authentication, sessions,
protocol dispatch, revisions, receipts, transports, and module plumbing.  The
other `ebp-*.el` files are reusable endpoint modules for synchronization,
completion, sandboxed paths, durable receipt/work storage, and the optional
transport profiles (`ebp-tls.el`, `ebp-websocket.el`, `ebp-unix.el`).  None
may depend on Jetpacs or another application.

Run the standalone gate with:

```sh
test/run-tests.sh
```

Set `EBP_SPEC_DIR` when the specification checkout is not at `../ebp`.

#!/bin/sh
set -eu

cd "$(dirname "$0")/.."
spec_dir=${EBP_SPEC_DIR:-"$(pwd)/../ebp"}
test -r "$spec_dir/contract.json" || {
  echo "EBP specification not found at $spec_dir" >&2
  exit 2
}
export EBP_SPEC_DIR=$spec_dir

# SPEC 5.5 (lisp/ebp-websocket.el) rents the third-party websocket package;
# the gate takes it from a sibling checkout, like the spec, never silently.
websocket_dir=${EBP_WEBSOCKET_DIR:-"$(pwd)/../emacs/emacs-websocket"}
test -r "$websocket_dir/websocket.el" || {
  echo "websocket.el not found at $websocket_dir (set EBP_WEBSOCKET_DIR)" >&2
  exit 2
}
export EBP_WEBSOCKET_DIR=$websocket_dir

guard_count=0
for source in lisp/ebp*.el; do
  feature=$(basename "$source" .el)
  EBP_GUARD_FEATURE=$feature emacs -Q --batch -L lisp -L "$websocket_dir" \
    --eval '(setq load-prefer-newer t)' \
    --eval '
(progn
  (require (intern (getenv "EBP_GUARD_FEATURE")))
  (let (offenders)
    (mapatoms
     (lambda (symbol)
       (when (and (string-prefix-p "jetpacs" (symbol-name symbol))
                  (or (fboundp symbol) (boundp symbol) (facep symbol)
                      (get symbol (quote error-conditions))
                      (get symbol (quote group-documentation))
                      (get symbol (quote custom-group))
                      (memq symbol features)))
         (push symbol offenders))))
    (when offenders
      (message "application symbols after loading %s: %S"
               (getenv "EBP_GUARD_FEATURE") offenders)
      (kill-emacs 1))))'
  guard_count=$((guard_count + 1))
done
test "$guard_count" -ge 7

compile_dir=$(mktemp -d)
trap 'rm -rf "$compile_dir"' EXIT
for source in lisp/*.el; do
  emacs -Q --batch -L lisp -L "$websocket_dir" \
    --eval "(progn
      (setq load-prefer-newer t byte-compile-error-on-warn t)
      (setq byte-compile-dest-file-function
            (lambda (file)
              (expand-file-name
               (concat (file-name-nondirectory file) \"c\")
               \"$compile_dir\"))))" \
    -f batch-byte-compile "$source"
done

for suite in ebp-wire-test ebp-store-test ebp-revision-test ebp-sync-test \
             ebp-complete-test ebp-websocket-test; do
  emacs -Q --batch -L lisp -L test -L "$websocket_dir" \
    --eval '(setq load-prefer-newer t)' \
    -l "test/$suite.el" -f ert-run-tests-batch-and-exit
done

;;; ebp-unix.el --- SPEC 5.6 emacs-unix listener -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; The Emacs side of the SPEC 5.6 `emacs-unix' transport profile: Emacs
;; BINDS a Unix-domain stream socket in a directory private to its user
;; and a shorter-lived Companion — a desktop frontend beside a daemon
;; Emacs — DIALS it, the `emacsclient' shape.  Protocol roles do not
;; change: Emacs still sends `session.hello' first on every accepted
;; connection, and Content-Length framing (SPEC 6) carries every message.
;;
;; Built-ins only.  The socket is `make-network-process' with `:server t
;; :family local', exactly as `server.el' serves emacsclient, and the
;; directory rules SPEC 5.6 states (created 0700, owned by us, no group or
;; other access, no symlink) are `server-ensure-safe-dir's.  What SPEC 5.7
;; requires of the binding endpoint — the pre-authentication pool with its
;; 10 s deadline and newest-wins eviction, supersession by the newest
;; AUTHENTICATED connection — and what SPEC 5.6 requires of a binding
;; Emacs's receiver — the strict SPEC 6.2/4.1 decoder, REQUIRED here where
;; a dialing Emacs may rent jsonrpc.el's tolerances — live in ebp.el as
;; the `ebp--binder-*' pool and `ebp--strict-process-connection', shared
;; with the SPEC 5.5 WebSocket binder.  This file adds the socket: path
;; policy, stale-socket handling, accept, and close.
;;
;; Everything above the socket is ebp.el's: each accepted connection runs
;; the ordinary handshake driver on a CANDIDATE client, and at
;; welcome-verified `ebp-client--adopt' promotes it into the logical
;; client the application holds.

;;; Code:

(require 'cl-lib)
(require 'jsonrpc)
(require 'ebp-wire)                     ; framing, limits, `ebp-frame-close'
(require 'ebp)
(require 'server)                       ; `server-ensure-safe-dir'

;;;; User options

(defgroup ebp-unix nil
  "The SPEC 5.6 `emacs-unix' listener."
  :group 'ebp
  :prefix "ebp-unix-")

(defcustom ebp-unix-socket-directory
  (let ((runtime (getenv "XDG_RUNTIME_DIR")))
    (if (and runtime (file-name-absolute-p runtime))
        (expand-file-name "ebp" runtime)
      (format "%sebp%d" (file-name-as-directory temporary-file-directory)
              (user-uid))))
  "Directory holding the SPEC 5.6 socket, private to this user.
SPEC 5.6 RECOMMENDS `$XDG_RUNTIME_DIR/ebp/'; without that variable the
`server.el' convention `TMPDIR/ebpUID' is used.  The directory is created
mode 0700 and refused when it is a symlink, owned by another user, or
accessible by group or others (`server-ensure-safe-dir')."
  :type 'directory)

(defcustom ebp-unix-socket-name "ebp.sock"
  "File name of the SPEC 5.6 socket inside `ebp-unix-socket-directory'."
  :type 'string)

(defun ebp-unix-default-path ()
  "The default SPEC 5.6 socket path."
  (expand-file-name ebp-unix-socket-name ebp-unix-socket-directory))

;;;; Path policy (SPEC 5.6 "Socket")

(defun ebp-unix--connectable-p (path)
  "Non-nil when a listener currently accepts connections at PATH.
A stale socket file refuses the connect outright.  A live listener is an
Emacs that will answer the accept with `session.hello'; the probe waits
briefly for those bytes before closing so the peer's write lands on an
open socket rather than a closed one (an EPIPE, which a batch Emacs does
not survive), and nothing is ever sent."
  (condition-case nil
      (let* ((got nil)
             (probe (make-network-process :name "ebp-unix probe"
                                          :family 'local :service path
                                          :noquery t :coding 'binary
                                          :filter (lambda (_p _s) (setq got t))))
             (deadline (+ (float-time) 1.0)))
        (while (and (not got) (process-live-p probe)
                    (< (float-time) deadline))
          (accept-process-output probe 0.1))
        (when (process-live-p probe)
          (delete-process probe))
        t)
    (file-error nil)))

(defun ebp-unix--prepare-path (path)
  "Make PATH safe to bind (SPEC 5.6): secure its directory, clear a stale file.
The directory is checked and created by `server-ensure-safe-dir'.  An
existing file at PATH that is not a socket, or a socket owned by another
user, is refused; a socket of ours that still accepts connections is
another Emacs authority on this path and is refused, never unlinked; a
socket of ours that refuses connections is stale and is unlinked."
  (server-ensure-safe-dir (file-name-directory path))
  (when-let* ((attrs (file-attributes path 'integer)))
    (let ((modes (file-attribute-modes attrs))
          (uid (file-attribute-user-id attrs)))
      (unless (eq (aref modes 0) ?s)
        (signal 'ebp-transport-refused (list 'not-a-socket path)))
      (unless (eql uid (user-uid))
        (signal 'ebp-transport-refused
                (list 'socket-owner-mismatch path uid (user-uid))))
      (when (ebp-unix--connectable-p path)
        (signal 'ebp-transport-refused (list 'socket-in-use path)))
      (delete-file path))))

;;;; Listener lifecycle (the registry hooks)

(defun ebp-unix--check (host port config)
  "Registry `:check': HOST is an absolute socket path, no PORT."
  (ignore config)
  (unless (and (stringp host) (not (string-empty-p host))
               (file-name-absolute-p host))
    (error "ebp: emacs-unix takes the absolute socket path as HOST (SPEC 5.6), got %S"
           host))
  (when port
    (error "ebp: emacs-unix takes no PORT (SPEC 5.6), got %S" port)))

(defun ebp-unix--on-accept (server socket _message)
  "A Companion dialed: pool SOCKET and run the handshake on a candidate.
The listener's `:log' function.  SOCKET was created with the listener's
filter and sentinel; the connection class takes it over before any byte
can be read, because this runs synchronously at accept."
  (let* ((client (process-get server :ebp-client))
         (binder (and client (ebp--binder client))))
    (if (or (null binder) (ebp-client-terminal-p client))
        (ignore-errors (delete-process socket))
      (set-process-query-on-exit-flag socket nil)
      (ebp--binder-admit binder socket)
      (let ((conn (apply #'make-instance 'ebp--strict-process-connection
                         :name "ebp-unix" :process socket
                         ;; SPEC 23.3: no bodies in the clear by default.
                         :events-buffer-config
                         (if ebp-log-events '(:size nil :format full) '(:size 0))
                         (ebp--connection-initargs))))
        (ebp--binder-start-candidate binder socket conn)))))

(defun ebp-unix--listen (client)
  "Registry `:listen': ensure CLIENT's listener is bound; idempotent."
  (let ((existing (ebp--binder client)))
    (if (and existing (process-live-p (ebp--binder-process existing)))
        existing
      (let* ((path (ebp-client-host client))
             (binder (ebp--make-binder :client client :address path)))
        (ebp-unix--prepare-path path)
        (let ((proc (with-file-modes #o600
                      (make-network-process
                       :name (format "ebp-unix listener on %s" path)
                       :server t :family 'local :service path
                       :noquery t :coding 'binary
                       :filter #'ebp--strict-filter
                       :sentinel #'ebp--strict-sentinel
                       :log #'ebp-unix--on-accept
                       :plist (list :ebp-client client)))))
          ;; Belt and braces: the umask may have widened the socket file.
          (ignore-errors (set-file-modes path #o600 'nofollow))
          (setf (ebp--binder-process binder) proc
                (ebp-client-transport-state client) binder)
          binder)))))

(defun ebp-unix--close (client)
  "Registry `:close': drop every pending candidate, the listener, the file."
  (when-let* ((binder (ebp--binder client)))
    (let ((path (ebp--binder-address binder)))
      (ebp--binder-close client)
      (when (and path (file-exists-p path)
                 (eql (file-attribute-user-id (file-attributes path 'integer))
                      (user-uid)))
        (ignore-errors (delete-file path))))))

(ebp-register-transport 'emacs-unix
                        :role 'binder
                        :check #'ebp-unix--check
                        :listen #'ebp-unix--listen
                        :close #'ebp-unix--close
                        :adopt #'ebp--binder-adopted)

;;;; Entry point

;;;###autoload
(defun ebp-unix-listen (&rest config)
  "Bind the SPEC 5.6 listener and return one logical EBP client.
CONFIG is `ebp-connect' config plus `:path' (default
`ebp-unix-default-path').  The returned client is `closed' for
`(listening)' until a Companion dials the socket and authenticates; it
then runs READY on that connection, survives its loss (idle again, no
redial — the Companion redials, SPEC 5.7), and is superseded only by the
next connection that authenticates.  Register actions and hooks on this
client only; the candidates that run each handshake are internal.
`ebp-client-close' closes the listener with every connection and
unlinks the socket."
  (let ((path (or (plist-get config :path) (ebp-unix-default-path))))
    (apply #'ebp-connect path nil :transport 'emacs-unix
           (cl-loop for (k v) on config by #'cddr
                    unless (eq k :path) append (list k v)))))

(provide 'ebp-unix)
;;; ebp-unix.el ends here

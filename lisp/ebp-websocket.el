;;; ebp-websocket.el --- SPEC 5.5 loopback-websocket listener -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Package-Requires: ((emacs "30.1") (websocket "1.15"))

;;; Commentary:

;; The Emacs side of the SPEC 5.5 `loopback-websocket' transport profile:
;; Emacs BINDS a WebSocket server on 127.0.0.1 and a browser-hosted
;; Companion DIALS it, because a browser can hold no transport other than
;; WebSocket.  Protocol roles do not change: Emacs still sends
;; `session.hello' first on every accepted connection.  One JSON-RPC
;; message rides in one WebSocket text message; Section 6 framing does
;; not apply.
;;
;; This is the one file in the repository allowed to require the
;; third-party `websocket' package (AGENTS.md, amendment #190).  It rents
;; the library for RFC 6455 and adds, on top of it, everything SPEC 5.5
;; requires of the binding endpoint: the Origin allowlist enforced before
;; the upgrade completes, the message bound with the 6.2 skip semantics
;; and the 1400 diagnostic, refusal of binary messages, the strict 4.1
;; receiver rules (REQUIRED of Emacs here, only RECOMMENDED for a dialing
;; Emacs), the 5.6 pre-authentication pool with its 10 s deadline and
;; newest-wins eviction, and supersession by the newest AUTHENTICATED
;; connection.
;;
;; Everything above the socket is ebp.el's: each accepted connection runs
;; the ordinary handshake driver on a CANDIDATE client
;; (`ebp-client--make-candidate'), and at welcome-verified
;; `ebp-client--adopt' promotes it into the logical client the
;; application holds.  Dispatch, overload accounting, receipts, editor
;; sync, and the reference codec are reused unchanged; this file adds a
;; `jsonrpc-connection' subclass and the listener lifecycle, nothing else.

;;; Code:

(require 'cl-lib)
(require 'jsonrpc)
(require 'ebp)

;; SPEC 5.5 needs RFC 6455, which Emacs does not ship.  Fail loudly at
;; load — never silently — when the package is absent (AGENTS.md).
(eval-and-compile
  (unless (require 'websocket nil t)
    (error "ebp-websocket: the `websocket' package (GNU ELPA / MELPA) is \
required for SPEC 5.5 loopback-websocket"))
  (dolist (fn '(websocket-server-accept websocket-server-filter
                websocket-verify-client-headers websocket-send
                websocket-close websocket-server-close))
    (unless (fboundp fn)
      (error "ebp-websocket: this `websocket' lacks `%s'; 1.15 or later is needed"
             fn))))

;;;; User options

(defgroup ebp-websocket nil
  "The SPEC 5.5 `loopback-websocket' listener."
  :group 'ebp
  :prefix "ebp-websocket-")

(defcustom ebp-websocket-port 8767
  "Default listener port (SPEC 5.5: ws://127.0.0.1:8767).
A `:port' passed to `ebp-websocket-listen' overrides it."
  :type 'integer)

(defcustom ebp-websocket-allowed-origins nil
  "Origins a browser Companion may dial from, as \"scheme://host[:port]\".
SPEC 5.5: the WebSocket `Origin' header is validated against this list
during the HTTP upgrade and a mismatch — or an absent Origin — is
refused with 403 before any EBP frame is exchanged.  Empty means every
upgrade is refused: fail closed.  A connection's `:allowed-origins'
config overrides it.  Comparison is exact and ASCII case-insensitive;
the opaque origin `null' can never be listed."
  :type '(repeat string))

(defcustom ebp-websocket-max-pending 8
  "Bound on concurrent pre-authentication connections (SPEC 5.6).
When reached, a new dial evicts the OLDEST pending connection — newest
wins, mirroring supersession — rather than being refused."
  :type 'integer)

(defvar ebp-websocket--preauth-deadline 10
  "Seconds an accepted connection has to finish the Section 9 handshake.
SPEC 5.6 fixes it at 10; not a user option.  Tests bind it shorter.")

(defvar ebp-websocket--diagnostic-interval 10
  "Minimum seconds between `1400 frame-too-large' reports per connection.
SPEC 22.3 requires `log.error' to be rate-limited; unlike 1401, a 1400
keeps the connection open, so the once-per-connection latch cannot serve.")

;;;; Listener and pending state

(cl-defstruct (ebp-websocket--listener (:constructor ebp-websocket--make-listener))
  client process port origins (pending nil))

(cl-defstruct (ebp-websocket--pending (:constructor ebp-websocket--make-pending))
  socket accepted-at timer candidate)

(defun ebp-websocket--listener (client)
  "CLIENT's listener struct, or nil."
  (ebp-client-transport-state client))

(defun ebp-websocket--client-origins (client)
  "The Origin allowlist for CLIENT."
  (or (plist-get (ebp-client-config client) :allowed-origins)
      ebp-websocket-allowed-origins))

(defun ebp-websocket--origin-syntax-p (s)
  "Non-nil when S is a serialized origin \"scheme://host[:port]\"."
  (and (stringp s)
       (string-match-p "\\`[A-Za-z][A-Za-z0-9+.-]*://[^/[:space:]]+\\'" s)))

;;;; The connection class (jsonrpc.el's transport seam)

(defclass ebp-websocket--connection (ebp--endpoint-mixin jsonrpc-connection)
  ((ws :initarg :ws :initform nil :accessor ebp-websocket--connection-ws)
   (on-shutdown :initarg :on-shutdown :initform #'ignore
                :accessor ebp-websocket--connection-on-shutdown)
   (shutdown-started :initform nil
                     :accessor ebp-websocket--connection-shutdown-started)
   ;; Message reassembly (SPEC 5.5 message bound): fragments so far, their
   ;; octet count, and whether the rest of an oversize message is being
   ;; discarded until its final frame.
   (chunks :initform nil :accessor ebp-websocket--connection-chunks)
   (buffered-octets :initform 0 :accessor ebp-websocket--connection-buffered-octets)
   (discarding :initform nil :accessor ebp-websocket--connection-discarding)
   (last-diagnostic :initform nil :accessor ebp-websocket--connection-last-diagnostic))
  "One accepted WebSocket connection as a `jsonrpc-connection'.")

(defun ebp-websocket--live-p (conn)
  "Non-nil while CONN's socket is open and no shutdown has begun."
  (let ((ws (ebp-websocket--connection-ws conn)))
    (and ws (not (ebp-websocket--connection-shutdown-started conn))
         (process-live-p (websocket-conn ws)))))

(cl-defmethod jsonrpc-connection-send ((conn ebp-websocket--connection)
                                       &rest args
                                       &key id method _params
                                       (_result nil result-supplied-p) error
                                       &allow-other-keys)
  "SPEC 5.5 sender: one message, serialized under 4.1, as one text frame.
The octets are UTF-8 of `json-serialize' under jsonrpc.el's conventions,
never `websocket-send-text', whose `raw-text' encoding would leak a
raw-byte character onto the wire.  SPEC 4.5's sender bound applies: a
body over `ebp-max-body-octets' signals `ebp-frame-close' exactly as
`ebp-encode-frame' does, and `ebp-client--request' rolls its claim back."
  (let* ((method (cond ((null method) nil)
                       ((keywordp method) (substring (symbol-name method) 1))
                       ((symbolp method) (symbol-name method))
                       ((stringp method) method)
                       (t (error "ebp-websocket: bad method %S" method))))
         (message (cl-loop for (k v) on (copy-sequence args) by #'cddr
                           unless (eq k :partial)
                           append (list k (if (eq k :method) method v))))
         (kind (cond ((or result-supplied-p error) 'reply)
                     (id 'request)
                     (method 'notification)))
         (converted (jsonrpc-convert-to-endpoint conn message kind))
         (json (json-serialize converted :null-object nil :false-object :json-false))
         (bytes (encode-coding-string json 'utf-8))
         (ws (ebp-websocket--connection-ws conn)))
    (when (> (length bytes) ebp-max-body-octets)
      (signal 'ebp-frame-close (list "body exceeds max_frame_bytes")))
    (unless (ebp-websocket--live-p conn)
      (error "ebp-websocket: connection is closed"))
    (websocket-send ws (make-websocket-frame :opcode 'text :payload bytes
                                             :completep t))
    (jsonrpc--event conn 'client :json json :kind kind
                    :message message :foreign-message converted)))

(cl-defmethod jsonrpc-running-p ((conn ebp-websocket--connection))
  (ebp-websocket--live-p conn))

(cl-defmethod jsonrpc-shutdown ((conn ebp-websocket--connection) &optional _cleanup)
  (ebp-websocket--conclude conn t))

(defun ebp-websocket--conclude (conn close-socket)
  "Conclude CONN once: fail its continuations locally, then run on-shutdown.
This is the sentinel jsonrpc.el's process transport gets for free: every
outstanding continuation's timer is cancelled and its error-fn called
with code -1 (`ebp--transport-error-p'), after the continuation list has
been cleared so a throwing error-fn cannot abandon the rest.  CLOSE-SOCKET
non-nil also closes the WebSocket; `websocket-close' fires `on-close'
BEFORE writing its close frame, so re-entry here is expected and inert."
  (unless (ebp-websocket--connection-shutdown-started conn)
    (setf (ebp-websocket--connection-shutdown-started conn) t)
    (let ((conts (jsonrpc--continuations conn))
          (ws (ebp-websocket--connection-ws conn)))
      (setf (jsonrpc--continuations conn) nil)
      (dolist (c conts)
        (when-let* ((timer (nth 4 c)))
          (ignore-errors (cancel-timer timer))))
      (when (and close-socket ws (process-live-p (websocket-conn ws)))
        (ignore-errors (websocket-close ws)))
      (dolist (c conts)
        (condition-case err
            (funcall (nth 3 c) '(:code -1 :message "Transport closed"))
          (error (message "ebp-websocket: continuation error-fn failed (%s)"
                          (car err)))))
      (condition-case err
          (funcall (ebp-websocket--connection-on-shutdown conn) conn)
        (error (message "ebp-websocket: on-shutdown failed (%s)" (car err)))))))

;;;; Listener lifecycle (the registry hooks)

(defun ebp-websocket--check (host port config)
  "Registry `:check': loopback only, an integer port, a non-empty allowlist."
  (unless (member host '(nil "127.0.0.1"))
    (error "ebp: loopback-websocket binds 127.0.0.1 only (SPEC 5.5), got HOST %S"
           host))
  (unless (and (integerp port) (< 0 port 65536))
    (error "ebp: loopback-websocket needs an integer PORT, got %S" port))
  (let ((origins (or (plist-get config :allowed-origins)
                     ebp-websocket-allowed-origins)))
    (unless (and (consp origins)
                 (cl-every #'ebp-websocket--origin-syntax-p origins))
      (error "ebp: loopback-websocket needs a non-empty :allowed-origins list \
of \"scheme://host[:port]\" strings (SPEC 5.5), got %S" origins))))

(defun ebp-websocket--listen (client)
  "Registry `:listen': ensure CLIENT's listener is bound; idempotent.
The listener process is built here rather than by `websocket-server'
for one reason: `:reuseaddr', which the library omits and without which
a restart on the same port fails while sockets sit in TIME_WAIT.  The
ten other arguments are the library's own (websocket.el 884-894), and
`:ebp-client' on the plist is the scoping marker both advices key on."
  (let ((existing (ebp-websocket--listener client)))
    (if (and existing
             (process-live-p (ebp-websocket--listener-process existing)))
        existing
      (let* ((port (ebp-client-port client))
             (listener (ebp-websocket--make-listener
                        :client client :port port
                        :origins (ebp-websocket--client-origins client)))
             (proc (make-network-process
                    :name (format "ebp-websocket listener on %d" port)
                    :server t :family 'ipv4 :host 'local :service port
                    :noquery t :reuseaddr t
                    :filter #'websocket-server-filter
                    :log #'websocket-server-accept
                    :filter-multibyte nil
                    :plist (list :host 'local
                                 :on-open #'ebp-websocket--on-open
                                 :on-message #'ebp-websocket--on-message
                                 :on-close #'ebp-websocket--on-close
                                 :on-error #'ebp-websocket--on-error
                                 :ebp-client client))))
        (setf (ebp-websocket--listener-process listener) proc
              (ebp-client-transport-state client) listener)
        (ebp-websocket--install-advice)
        listener))))

(defun ebp-websocket--close (client)
  "Registry `:close': drop every pending candidate, then the listener."
  (when-let* ((listener (ebp-websocket--listener client)))
    (dolist (entry (copy-sequence (ebp-websocket--listener-pending listener)))
      (ebp-websocket--drop-pending listener entry '(listener-closed)))
    (let ((proc (ebp-websocket--listener-process listener)))
      (when (and proc (process-live-p proc))
        (ignore-errors (websocket-server-close proc))))
    (setf (ebp-client-transport-state client) nil)))

(defun ebp-websocket--adopted (client candidate)
  "Registry `:adopt': CANDIDATE became CLIENT's session; forget its entry."
  (when-let* ((listener (ebp-websocket--listener client))
              (entry (ebp-websocket--find-pending listener :candidate candidate)))
    (ebp-websocket--forget listener entry)))

(ebp-register-transport 'loopback-websocket
                        :role 'binder
                        :check #'ebp-websocket--check
                        :listen #'ebp-websocket--listen
                        :close #'ebp-websocket--close
                        :adopt #'ebp-websocket--adopted)

;;;; The pre-authentication pool (SPEC 5.6)

(cl-defun ebp-websocket--find-pending (listener &key socket candidate)
  "LISTENER's pending entry for SOCKET or CANDIDATE, or nil."
  (cl-find-if (lambda (entry)
                (or (and socket (eq (ebp-websocket--pending-socket entry) socket))
                    (and candidate
                         (eq (ebp-websocket--pending-candidate entry) candidate))))
              (ebp-websocket--listener-pending listener)))

(defun ebp-websocket--forget (listener entry)
  "Remove ENTRY from LISTENER's pool and cancel its deadline."
  (when-let* ((timer (ebp-websocket--pending-timer entry)))
    (ignore-errors (cancel-timer timer))
    (setf (ebp-websocket--pending-timer entry) nil))
  (setf (ebp-websocket--listener-pending listener)
        (delq entry (ebp-websocket--listener-pending listener))))

(defun ebp-websocket--drop-pending (listener entry reason)
  "Forget ENTRY and close what it holds: a candidate, or a bare socket."
  (ebp-websocket--forget listener entry)
  (let ((candidate (ebp-websocket--pending-candidate entry))
        (socket (ebp-websocket--pending-socket entry)))
    (cond
     (candidate (ebp-client-close candidate reason))
     ((and socket (process-live-p socket))
      (if-let* ((ws (process-get socket :websocket)))
          (ignore-errors (websocket-close ws))
        (delete-process socket))))))

(defun ebp-websocket--expire (listener entry)
  "SPEC 5.6: ENTRY did not authenticate within the deadline."
  (when (memq entry (ebp-websocket--listener-pending listener))
    (ebp-websocket--drop-pending listener entry '(preauth-timeout))))

(defun ebp-websocket--on-accept (server socket &rest _)
  "`websocket-server-accept' :after: admit SOCKET to our pool, newest wins.
The clock starts at TCP accept, so a connection that never sends an
upgrade is bounded as well."
  (when-let* ((client (process-get server :ebp-client))
              (listener (ebp-websocket--listener client)))
    (if (ebp-client-terminal-p client)
        (ignore-errors (delete-process socket))
      (while (>= (length (ebp-websocket--listener-pending listener))
                 (max 1 ebp-websocket-max-pending))
        (ebp-websocket--drop-pending
         listener (car (ebp-websocket--listener-pending listener))
         '(preauth-evicted)))
      (let ((entry (ebp-websocket--make-pending :socket socket
                                                :accepted-at (float-time))))
        (setf (ebp-websocket--pending-timer entry)
              (run-at-time ebp-websocket--preauth-deadline nil
                           #'ebp-websocket--expire listener entry)
              (ebp-websocket--listener-pending listener)
              (append (ebp-websocket--listener-pending listener) (list entry)))))))

;;;; The upgrade (SPEC 5.5 Origin, SPEC 6.2 accumulation bound)

(defun ebp-websocket--origin-allowed-p (head origins)
  "Non-nil when header section HEAD carries exactly one allowed Origin."
  (let ((case-fold-search t) (found '()) (start 0))
    (while (string-match "^Origin:[ \t]*\\([^\r\n]*?\\)[ \t]*\r\n" head start)
      (push (match-string 1 head) found)
      (setq start (match-end 0)))
    (and (= (length found) 1)
         (let ((origin (car found)))
           (and (not (string-empty-p origin))
                (not (string-equal-ignore-case origin "null"))
                (cl-some (lambda (allowed)
                           (string-equal-ignore-case allowed origin))
                         origins))))))

(defun ebp-websocket--refuse-upgrade (process status)
  "Answer PROCESS's upgrade with HTTP STATUS (nil: silently) and close it."
  (when status
    (ignore-errors
      (process-send-string
       process
       (format "HTTP/1.1 %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
               status))))
  (ignore-errors (delete-process process)))

(defun ebp-websocket--cap-for-client (client)
  "CLIENT's SPEC 5.5 message bound: negotiated, never above the fixed cap."
  (min ebp-max-body-octets
       (or (plist-get (ebp-client-limits client) :max_frame_bytes)
           ebp-max-body-octets)))

(defun ebp-websocket--server-filter (orig process output)
  "`websocket-server-filter' :around, for our listener only.
During the upgrade: bound the header section, answer a malformed request
400 ourselves (so the library's raw-request diagnostic never runs, SPEC
23.3), and refuse an absent or unlisted Origin with 403 BEFORE the 101
is written (SPEC 5.5).  Once open: bound the library's unparsed
accumulation by max_frame_bytes plus the header cap (SPEC 6.2).  Any
other server's connection passes through untouched."
  (let* ((ws (process-get process :websocket))
         (server (and ws (websocket-server-conn ws)))
         (client (and server (process-get server :ebp-client))))
    (if (null client)
        (funcall orig process output)
      (pcase (websocket-ready-state ws)
        ('connecting
         (let* ((text (concat (websocket-inflight-input ws) output))
                (end (string-match "\r\n\r\n" text)))
           (cond
            ((and (null end) (> (length text) ebp-max-header-octets))
             (ebp-websocket--refuse-upgrade process nil))
            ((null end)
             (funcall orig process output))
            ((> (+ end 4) ebp-max-header-octets)
             (ebp-websocket--refuse-upgrade process nil))
            (t
             (let ((head (substring text 0 (+ end 4))))
               (cond
                ((null (websocket-verify-client-headers head))
                 (ebp-websocket--refuse-upgrade process "400 Bad Request"))
                ((not (ebp-websocket--origin-allowed-p
                       head (ebp-websocket--client-origins client)))
                 (ebp-websocket--refuse-upgrade process "403 Forbidden"))
                (t (funcall orig process output))))))))
        ('open
         (funcall orig process output)
         (when (and (process-live-p process)
                    (> (length (or (websocket-inflight-input ws) ""))
                       (+ (ebp-websocket--cap-for-client client)
                          ebp-max-header-octets)))
           (if-let* ((conn (websocket-client-data ws)))
               (ebp-websocket--refuse conn 'inflight-overflow)
             (ignore-errors (websocket-close ws)))))
        (_ nil)))))

(defun ebp-websocket--install-advice ()
  "Install the two scoped advices once."
  (unless (advice-member-p #'ebp-websocket--on-accept 'websocket-server-accept)
    (advice-add 'websocket-server-accept :after #'ebp-websocket--on-accept))
  (unless (advice-member-p #'ebp-websocket--server-filter 'websocket-server-filter)
    (advice-add 'websocket-server-filter :around #'ebp-websocket--server-filter)))

;;;; Per-connection callbacks

(defun ebp-websocket--on-open (ws)
  "An upgrade completed: run the handshake on a fresh candidate (SPEC 5.5/5.6)."
  (let* ((server (websocket-server-conn ws))
         (client (and server (process-get server :ebp-client)))
         (listener (and client (ebp-websocket--listener client)))
         (socket (websocket-conn ws)))
    (if (or (null listener) (ebp-client-terminal-p client))
        (ignore-errors (websocket-close ws))
      (let* ((candidate (ebp-client--make-candidate client))
             (conn (apply #'make-instance 'ebp-websocket--connection
                          :name "ebp-websocket" :ws ws
                          ;; SPEC 23.3: no bodies in the clear by default.
                          :events-buffer-config
                          (if ebp-log-events '(:size nil :format full) '(:size 0))
                          (ebp--connection-initargs))))
        (setf (ebp-client-connection candidate) conn
              (ebp-client-process candidate) socket
              (ebp--connection-client conn) candidate
              (websocket-client-data ws) conn)
        (if-let* ((entry (ebp-websocket--find-pending listener :socket socket)))
            (setf (ebp-websocket--pending-candidate entry) candidate)
          ;; Accepted before the pool saw it (cannot happen with the
          ;; accept advice installed); still bound it by the deadline.
          (let ((entry (ebp-websocket--make-pending
                        :socket socket :accepted-at (float-time)
                        :candidate candidate)))
            (setf (ebp-websocket--pending-timer entry)
                  (run-at-time ebp-websocket--preauth-deadline nil
                               #'ebp-websocket--expire listener entry))
            (push entry (ebp-websocket--listener-pending listener))))
        (condition-case err
            (ebp-client-start candidate)
          (error
           (message "ebp-websocket: session.hello failed (%s); closing" (car err))
           (ebp-client-close candidate (list 'hello-failed (car err)))))))))

(defun ebp-websocket--on-message (ws frame)
  "One frame from WS: reassemble, decode strictly, deliver (SPEC 5.5)."
  (when-let* ((conn (websocket-client-data ws)))
    (unless (ebp-websocket--connection-shutdown-started conn)
      (let ((outermost (not ebp--in-filter))
            (ebp--in-filter t))
        (unwind-protect
            (when-let* ((bytes (ebp-websocket--accumulate conn frame)))
              (ebp-websocket--receive conn bytes))
          (when outermost
            (when-let* ((client (ebp--connection-client conn)))
              (ebp-client--inbound-check client))))))))

(defun ebp-websocket--on-close (ws)
  "WS closed, by us or the peer: conclude its connection and candidate."
  (let* ((server (websocket-server-conn ws))
         (client (and server (process-get server :ebp-client)))
         (listener (and client (ebp-websocket--listener client)))
         (conn (websocket-client-data ws)))
    (when listener
      (when-let* ((entry (ebp-websocket--find-pending
                          listener :socket (websocket-conn ws))))
        (ebp-websocket--forget listener entry)))
    (when conn
      (ebp-websocket--conclude conn nil)
      (when-let* ((c (ebp--connection-client conn)))
        (when (ebp-client-parent c)
          (ebp-client-close c '(transport-lost)))))))

(defun ebp-websocket--on-error (ws type err)
  "A callback failed: fail closed on this connection, logging no payload."
  (message "ebp-websocket: %s failed (%s); closing the connection"
           type (car-safe err))
  (if-let* ((conn (websocket-client-data ws)))
      (ignore-errors (jsonrpc-shutdown conn))
    (ignore-errors (websocket-close ws))))

;;;; The inbound pipeline

(defun ebp-websocket--refuse (conn why)
  "Close CONN for WHY: a protocol violation this endpoint MUST not tolerate."
  (message "ebp-websocket: closing connection (%s)" why)
  (ignore-errors (jsonrpc-shutdown conn)))

(defun ebp-websocket--max-frame-bytes (conn)
  "The SPEC 5.5 message bound for CONN's client."
  (if-let* ((client (ebp--connection-client conn)))
      (ebp-websocket--cap-for-client client)
    ebp-max-body-octets))

(defun ebp-websocket--report-frame-too-large (conn bytes max)
  "SPEC 5.5/6.2: one rate-limited `1400 frame-too-large' in SYNCING or READY."
  (when-let* ((client (ebp--connection-client conn)))
    (let ((now (float-time))
          (last (ebp-websocket--connection-last-diagnostic conn)))
      (when (and (ebp-client--authenticated-p client)
                 (or (null last)
                     (>= (- now last) ebp-websocket--diagnostic-interval)))
        (setf (ebp-websocket--connection-last-diagnostic conn) now)
        (ignore-errors
          (ebp-client-notify client 'log.error
                             (list :code 1400
                                   :message "Frame exceeds size cap"
                                   :data (list :kind "frame-too-large"
                                               :bytes bytes :max max))))))))

(defun ebp-websocket--accumulate (conn frame)
  "Fold FRAME into CONN's message; return the complete unibyte message or nil.
SPEC 5.5: a binary message closes the connection; a message that would
exceed the bound is discarded through its final frame, reported once,
and the connection stays open.  RFC 6455 sequencing (a continuation with
nothing in progress, a new text frame inside a message) is a violation
and closes."
  (let* ((opcode (websocket-frame-opcode frame))
         (payload (or (websocket-frame-payload frame) ""))
         (final (websocket-frame-completep frame))
         (in-progress (or (ebp-websocket--connection-chunks conn)
                          (ebp-websocket--connection-discarding conn))))
    (cond
     ((eq opcode 'binary)
      (ebp-websocket--refuse conn 'binary-message) nil)
     ((and (eq opcode 'continuation) (not in-progress))
      (ebp-websocket--refuse conn 'stray-continuation) nil)
     ((and (eq opcode 'text) in-progress)
      (ebp-websocket--refuse conn 'interleaved-message) nil)
     ((not (memq opcode '(text continuation))) nil)
     ((ebp-websocket--connection-discarding conn)
      (when final (setf (ebp-websocket--connection-discarding conn) nil))
      nil)
     (t
      (let* ((cap (ebp-websocket--max-frame-bytes conn))
             (total (+ (ebp-websocket--connection-buffered-octets conn)
                       (length payload))))
        (cond
         ((> total cap)
          (setf (ebp-websocket--connection-chunks conn) nil
                (ebp-websocket--connection-buffered-octets conn) 0
                (ebp-websocket--connection-discarding conn) (not final))
          (ebp-websocket--report-frame-too-large conn total cap)
          nil)
         (final
          (let ((chunks (ebp-websocket--connection-chunks conn)))
            (setf (ebp-websocket--connection-chunks conn) nil
                  (ebp-websocket--connection-buffered-octets conn) 0)
            (if chunks
                (apply #'concat (nreverse (cons payload chunks)))
              payload)))
         (t
          (push payload (ebp-websocket--connection-chunks conn))
          (setf (ebp-websocket--connection-buffered-octets conn) total)
          nil)))))))

(defun ebp-websocket--reply-error (conn id code message kind)
  "Answer a body fault on CONN with a SPEC 8 error response; ID may be nil."
  (ignore-errors
    (jsonrpc-connection-send conn :id id
                             :error (list :code code :message message
                                          :data (list :kind kind)))))

(defun ebp-websocket--schedule (conn msg)
  "Deliver MSG on CONN from a 0-delay timer whose args are (CONN MSG).
Byte-for-byte jsonrpc.el's own delivery shape (jsonrpc.el 883-897), so
`ebp-client--backlog' counts it and `ebp--isolate-parsed-messages'
rewrites it; timers cannot fire inside the socket's process filter, so
ordering matches the process transport."
  (let ((timer (timer-create)))
    (timer-set-time timer (current-time))
    (timer-set-function timer
                        (lambda (c m)
                          (with-temp-buffer
                            (jsonrpc-connection-receive c m)))
                        (list conn msg))
    (timer-activate timer)))

(defun ebp-websocket--receive (conn bytes)
  "Decode one complete message BYTES under the SPEC 4.1/6.2 receiver rules.
A parse fault answers -32700, an invalid request -32600, both with id
null unless the message carried a valid one, and the connection continues
\(SPEC 6.2).  A valid message is scheduled for dispatch and then run
through `ebp--isolate-parsed-messages' for the unknown-method sentinel."
  (let* ((client (ebp--connection-client conn))
         (msg (condition-case err
                  (let ((parsed (let ((obarray (obarray-make)))
                                  (ebp--parse-message bytes))))
                    (ebp--remap-decoded parsed)
                    (ebp--validate-message-plist parsed))
                (ebp-parse-error
                 (ebp-websocket--reply-error conn nil -32700 "Parse error"
                                             "parse-error")
                 nil)
                (ebp-invalid-request
                 (ebp-websocket--reply-error conn (nth 1 (cdr err)) -32600
                                             "Invalid Request" "invalid-request")
                 nil))))
    (when msg
      (when ebp-log-events
        (setq msg (plist-put msg :jsonrpc-json (ebp--decode-utf-8 bytes))))
      (ebp-websocket--schedule conn msg)
      (when client (ebp--isolate-parsed-messages client)))))

;;;; Entry point

;;;###autoload
(defun ebp-websocket-listen (&rest config)
  "Bind the SPEC 5.5 listener on 127.0.0.1 and return one logical EBP client.
CONFIG is `ebp-connect' config plus `:port' (default `ebp-websocket-port')
and `:allowed-origins' (REQUIRED unless `ebp-websocket-allowed-origins'
is set).  The returned client is `closed' for `(listening)' until a
browser Companion dials from an allowed Origin and authenticates; it
then runs READY on that connection, survives its loss (idle again, no
redial — the Companion redials, SPEC 5.6), and is superseded only by the
next connection that authenticates.  Register actions and hooks on this
client only; the candidates that run each handshake are internal.
`ebp-client-close' closes the listener with every connection."
  (let ((port (or (plist-get config :port) ebp-websocket-port)))
    (apply #'ebp-connect "127.0.0.1" port :transport 'loopback-websocket
           (cl-loop for (k v) on config by #'cddr
                    unless (eq k :port) append (list k v)))))

(provide 'ebp-websocket)
;;; ebp-websocket.el ends here

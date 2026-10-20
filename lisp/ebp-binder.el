;;; ebp-binder.el --- EBP binder profiles: SPEC 5.7 pool and strict receiver -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; The machinery every BINDER transport profile shares — the profiles under
;; which Emacs listens and the Companion dials: `loopback-websocket' (SPEC
;; 5.5, `ebp-websocket.el') and `emacs-unix' (SPEC 5.6, `ebp-unix.el').
;; Three things live here:
;;
;;   the pre-authentication pool (SPEC 5.7): every accepted connection runs
;;     the ordinary handshake on a CANDIDATE client, bounded in number and
;;     by a deadline, newest-wins; at welcome-verified the engine's
;;     `ebp-client--adopt' promotes the candidate into the logical client;
;;   the strict receiver (SPEC 6.2, REQUIRED of a binding Emacs): the
;;     reference decoder from `ebp-wire.el' applied to every inbound frame,
;;     where a dialing Emacs may rent jsonrpc.el's tolerances;
;;   a strict Content-Length `jsonrpc-connection' over a raw process, for
;;     binders whose socket is an Emacs process object.
;;
;; A profile module adds only its socket: bind, accept, close, and the
;; registry entry (`ebp-register-transport' with `:role' binder).  The
;; dialer profiles never load this file.
;;
;; Every function cites the section it implements.  Behavior with no
;; section is a bug in this file or an amendment owed to the EBP spec.

;;; Code:

(require 'cl-lib)
(require 'jsonrpc)
(require 'ebp-wire)
(require 'ebp)

;;;; Binder profiles (SPEC 5.7): the pre-authentication pool

;; Under a profile in which Emacs binds (SPEC 5.5 `loopback-websocket',
;; SPEC 5.6 `emacs-unix') every accepted connection attempts the Section 9
;; handshake on a CANDIDATE client while the logical client's session
;; stays live.  SPEC 5.7 bounds those attempts: at most
;; `ebp-binder-max-pending' concurrent pre-authentication connections, each
;; closed after `ebp--binder-preauth-deadline' seconds, and when the bound
;; is reached a new dial evicts the OLDEST rather than being refused —
;; newest wins, mirroring supersession.  Nothing in that rule is
;; transport-specific, so the pool lives here and each binder module
;; supplies only its accept, its socket close, and its connection class.

(defcustom ebp-binder-max-pending 8
  "Bound on concurrent pre-authentication connections (SPEC 5.7).
When reached, a new dial evicts the OLDEST pending connection — newest
wins, mirroring supersession — rather than being refused.  Applies to
every profile under which Emacs binds."
  :type 'integer
  :group 'ebp)

(defvar ebp--binder-preauth-deadline 10
  "Seconds an accepted connection has to finish the Section 9 handshake.
SPEC 5.7 fixes it at 10; not a user option.  Tests bind it shorter.")

(cl-defstruct (ebp--binder (:constructor ebp--make-binder))
  "A binding client's listener state, held in `ebp-client-transport-state'.
CLIENT is the logical client; PROCESS the listening process; ADDRESS the
port or path it is bound to; PENDING the pre-authentication pool, oldest
first; CLOSE-SOCKET a function of one bare (candidate-less) socket that
closes it, defaulting to `delete-process'."
  client process address (pending nil) close-socket)

(cl-defstruct (ebp--pending (:constructor ebp--make-pending))
  "One pooled connection: its SOCKET, ACCEPTED-AT, deadline TIMER, and the
CANDIDATE running its handshake, nil until one exists."
  socket accepted-at timer candidate)

(defun ebp--binder (client)
  "CLIENT's `ebp--binder', or nil for a dialer or an unbound binder."
  (let ((state (ebp-client-transport-state client)))
    (and (ebp--binder-p state) state)))

(cl-defun ebp--binder-find-pending (binder &key socket candidate)
  "BINDER's pending entry for SOCKET or CANDIDATE, or nil."
  (cl-find-if (lambda (entry)
                (or (and socket (eq (ebp--pending-socket entry) socket))
                    (and candidate
                         (eq (ebp--pending-candidate entry) candidate))))
              (ebp--binder-pending binder)))

(defun ebp--binder-forget (binder entry)
  "Remove ENTRY from BINDER's pool and cancel its deadline."
  (when-let* ((timer (ebp--pending-timer entry)))
    (ignore-errors (cancel-timer timer))
    (setf (ebp--pending-timer entry) nil))
  (setf (ebp--binder-pending binder)
        (delq entry (ebp--binder-pending binder))))

(defun ebp--binder-drop-pending (binder entry reason)
  "Forget ENTRY and close what it holds: a candidate, or a bare socket."
  (ebp--binder-forget binder entry)
  (let ((candidate (ebp--pending-candidate entry))
        (socket (ebp--pending-socket entry)))
    (cond
     (candidate (ebp-client-close candidate reason))
     ((and socket (process-live-p socket))
      (funcall (or (ebp--binder-close-socket binder) #'delete-process)
               socket)))))

(defun ebp--binder-expire (binder entry)
  "SPEC 5.7: ENTRY did not authenticate within the deadline."
  (when (memq entry (ebp--binder-pending binder))
    (ebp--binder-drop-pending binder entry '(preauth-timeout))))

(defun ebp--binder-admit (binder socket)
  "Admit SOCKET to BINDER's pool, newest wins; return its entry.
The deadline clock starts here, at accept, so a connection that never
sends a byte is bounded as well.  Evicts the oldest entries while the
pool is at `ebp-binder-max-pending'."
  (while (>= (length (ebp--binder-pending binder))
             (max 1 ebp-binder-max-pending))
    (ebp--binder-drop-pending binder (car (ebp--binder-pending binder))
                              '(preauth-evicted)))
  (let ((entry (ebp--make-pending :socket socket :accepted-at (float-time))))
    (setf (ebp--pending-timer entry)
          (run-at-time ebp--binder-preauth-deadline nil
                       #'ebp--binder-expire binder entry)
          (ebp--binder-pending binder)
          (append (ebp--binder-pending binder) (list entry)))
    entry))

(defun ebp--binder-start-candidate (binder socket conn)
  "Run one handshake for BINDER's client over CONN, an accepted SOCKET.
Creates the candidate (`ebp-client--make-candidate'), points CONN and the
pool entry at it, and sends `session.hello'.  A hello that cannot be
written closes the candidate as `(hello-failed ERR)'.  Returns the
candidate."
  (let* ((client (ebp--binder-client binder))
         (candidate (ebp-client--make-candidate client)))
    (setf (ebp-client-connection candidate) conn
          (ebp-client-process candidate) socket
          (ebp--connection-client conn) candidate)
    (if-let* ((entry (ebp--binder-find-pending binder :socket socket)))
        (setf (ebp--pending-candidate entry) candidate)
      ;; Accepted before the pool saw it; still bound it by the deadline.
      (setf (ebp--pending-candidate (ebp--binder-admit binder socket))
            candidate))
    (condition-case err
        (ebp-client-start candidate)
      (error
       (message "ebp: session.hello failed (%s); closing" (car err))
       (ebp-client-close candidate (list 'hello-failed (car err)))))
    candidate))

(defun ebp--binder-adopted (client candidate)
  "Registry `:adopt' for every binder: CANDIDATE became CLIENT's session."
  (when-let* ((binder (ebp--binder client))
              (entry (ebp--binder-find-pending binder :candidate candidate)))
    (ebp--binder-forget binder entry)))

(defun ebp--binder-close (client &optional close-listener)
  "Drop every pending candidate of CLIENT, then its listener.
CLOSE-LISTENER, a function of the listening process, defaults to
`delete-process'.  Clears `ebp-client-transport-state'."
  (when-let* ((binder (ebp--binder client)))
    (dolist (entry (copy-sequence (ebp--binder-pending binder)))
      (ebp--binder-drop-pending binder entry '(listener-closed)))
    (let ((proc (ebp--binder-process binder)))
      (when (and proc (process-live-p proc))
        (ignore-errors (funcall (or close-listener #'delete-process) proc))))
    (setf (ebp-client-transport-state client) nil)))

(defun ebp--binder-connection-lost (conn)
  "CONN's transport is gone: forget its pool entry and close its candidate.
An adopted connection reaches the logical client through CONN's
`:on-shutdown' (`ebp-client--transport-lost'); a candidate is closed
here as `(transport-lost)', which is terminal for the candidate only."
  (when-let* ((c (ebp--connection-client conn)))
    (when-let* ((parent (ebp-client-parent c))
                (binder (ebp--binder parent))
                (entry (ebp--binder-find-pending binder :candidate c)))
      (ebp--binder-forget binder entry))
    (when (ebp-client-parent c)
      (ebp-client-close c '(transport-lost)))))

;;;; Binder profiles: the strict receiver (SPEC 6.2 REQUIRED of a binding Emacs)

(defun ebp--reply-error (conn id code message kind)
  "Answer a body fault on CONN with a SPEC 8 error response; ID may be nil."
  (ignore-errors
    (jsonrpc-connection-send conn :id id
                             :error (list :code code :message message
                                          :data (list :kind kind)))))

(defun ebp--schedule-message (conn msg)
  "Deliver MSG on CONN from a 0-delay timer whose args are (CONN MSG).
Byte-for-byte jsonrpc.el's own delivery shape (jsonrpc.el 883-897), so
`ebp-client--backlog' counts it and `ebp--isolate-parsed-messages'
rewrites it; timers cannot fire inside a process filter, so ordering
matches the process transport."
  (let ((timer (timer-create)))
    (timer-set-time timer (current-time))
    (timer-set-function timer
                        (lambda (c m)
                          (with-temp-buffer
                            (jsonrpc-connection-receive c m)))
                        (list conn msg))
    (timer-activate timer)))

(defun ebp--receive-strict (conn bytes)
  "Decode one complete message body BYTES under the SPEC 4.1/6.2 receiver rules.
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
                 (ebp--reply-error conn nil -32700 "Parse error" "parse-error")
                 nil)
                (ebp-invalid-request
                 (ebp--reply-error conn (nth 1 (cdr err)) -32600
                                   "Invalid Request" "invalid-request")
                 nil))))
    (when msg
      (when ebp-log-events
        (setq msg (plist-put msg :jsonrpc-json (ebp--decode-utf-8 bytes))))
      (ebp--schedule-message conn msg)
      (when client (ebp--isolate-parsed-messages client)))))

;;;; Binder profiles: a strict Content-Length connection over a process

;; `ebp--connection' rents jsonrpc.el's process transport and its tolerant
;; reader, which SPEC 6.2 permits a DIALING Emacs.  A binding Emacs owes
;; the strict receiver (SPEC 5.6), so this class owns the process filter
;; itself and runs the reference decoder: `ebp--decoder-next' for framing,
;; `ebp--receive-strict' for each body.  Everything above the socket —
;; dispatchers, continuations, events — is jsonrpc.el's `jsonrpc-connection'.

(defclass ebp--strict-process-connection (ebp--endpoint-mixin jsonrpc-connection)
  ((process :initarg :process :initform nil
            :accessor ebp--strict-connection-process)
   (decoder :initform nil :accessor ebp--strict-connection-decoder)
   (on-shutdown :initarg :on-shutdown :initform #'ignore
                :accessor ebp--strict-connection-on-shutdown)
   (shutdown-started :initform nil
                     :accessor ebp--strict-connection-shutdown-started))
  "One accepted stream socket, Content-Length framed, strictly decoded.")

(cl-defmethod initialize-instance :after ((conn ebp--strict-process-connection) _slots)
  "Take ownership of CONN's process: binary coding, our filter and sentinel."
  (let ((proc (ebp--strict-connection-process conn)))
    (setf (ebp--strict-connection-decoder conn) (ebp-make-decoder))
    (process-put proc :ebp-connection conn)
    (set-process-coding-system proc 'binary 'binary)
    (set-process-filter proc #'ebp--strict-filter)
    (set-process-sentinel proc #'ebp--strict-sentinel)))

(defun ebp--strict-live-p (conn)
  "Non-nil while CONN's process is open and no shutdown has begun."
  (let ((proc (ebp--strict-connection-process conn)))
    (and proc (not (ebp--strict-connection-shutdown-started conn))
         (process-live-p proc))))

(cl-defmethod jsonrpc-connection-send ((conn ebp--strict-process-connection)
                                       &rest args
                                       &key id method _params
                                       (_result nil result-supplied-p) error
                                       &allow-other-keys)
  "SPEC 6.1 sender: one message, serialized under 4.1, in exact framing.
SPEC 4.5's sender bound applies: a body over `ebp-max-body-octets'
signals `ebp-frame-close' from `ebp-encode-frame', and
`ebp-client--request' rolls its claim back."
  (let* ((method (cond ((null method) nil)
                       ((keywordp method) (substring (symbol-name method) 1))
                       ((symbolp method) (symbol-name method))
                       ((stringp method) method)
                       (t (error "ebp: bad method %S" method))))
         (message (cl-loop for (k v) on (copy-sequence args) by #'cddr
                           unless (eq k :partial)
                           append (list k (if (eq k :method) method v))))
         (kind (cond ((or result-supplied-p error) 'reply)
                     (id 'request)
                     (method 'notification)))
         (converted (jsonrpc-convert-to-endpoint conn message kind))
         (json (json-serialize converted :null-object nil :false-object :json-false))
         (frame (ebp-encode-frame json)))
    (unless (ebp--strict-live-p conn)
      (error "ebp: connection is closed"))
    (process-send-string (ebp--strict-connection-process conn) frame)
    (jsonrpc--event conn 'client :json json :kind kind
                    :message message :foreign-message converted)))

(cl-defmethod jsonrpc-running-p ((conn ebp--strict-process-connection))
  (ebp--strict-live-p conn))

(cl-defmethod jsonrpc-shutdown ((conn ebp--strict-process-connection) &optional _cleanup)
  (ebp--strict-conclude conn t))

(defun ebp--strict-conclude (conn close-socket)
  "Conclude CONN once: fail its continuations locally, then run on-shutdown.
The sentinel jsonrpc.el's process transport gets for free: every
outstanding continuation's timer is cancelled and its error-fn called
with code -1 (`ebp--transport-error-p'), after the continuation list has
been cleared so a throwing error-fn cannot abandon the rest.  CLOSE-SOCKET
non-nil also deletes the process; its sentinel then re-enters here and
is inert."
  (unless (ebp--strict-connection-shutdown-started conn)
    (setf (ebp--strict-connection-shutdown-started conn) t)
    (let ((conts (jsonrpc--continuations conn))
          (proc (ebp--strict-connection-process conn)))
      (setf (jsonrpc--continuations conn) nil)
      (dolist (c conts)
        (when-let* ((timer (nth 4 c)))
          (ignore-errors (cancel-timer timer))))
      (when (and close-socket proc (process-live-p proc))
        (ignore-errors (delete-process proc)))
      (dolist (c conts)
        (condition-case err
            (funcall (nth 3 c) '(:code -1 :message "Transport closed"))
          (error (message "ebp: continuation error-fn failed (%s)" (car err)))))
      (condition-case err
          (funcall (ebp--strict-connection-on-shutdown conn) conn)
        (error (message "ebp: on-shutdown failed (%s)" (car err)))))))

(defun ebp--strict-filter (proc bytes)
  "Feed unibyte BYTES from PROC through the strict receiver.
Framing faults (`ebp-frame-close': a malformed header, an oversized
declaration, a header section over the bound) close the connection as
SPEC 6.2 requires; body faults are answered by `ebp--receive-strict' and
the connection continues.  The SPEC 22.3 backlog check runs at the
outermost exit, as for the dialer's filter wrapper."
  (when-let* ((conn (process-get proc :ebp-connection)))
    (unless (ebp--strict-connection-shutdown-started conn)
      (let ((outermost (not ebp--in-filter))
            (ebp--in-filter t)
            (decoder (ebp--strict-connection-decoder conn)))
        (unwind-protect
            (condition-case err
                (progn
                  (setf (ebp-decoder-buffer decoder)
                        (concat (ebp-decoder-buffer decoder) bytes))
                  (let (body)
                    (while (and (not (ebp--strict-connection-shutdown-started conn))
                                (setq body (ebp--decoder-next decoder)))
                      (ebp--receive-strict conn body))))
              (ebp-frame-close
               (message "ebp: closing connection (%s)" (cadr err))
               (ignore-errors (jsonrpc-shutdown conn))))
          (when outermost
            (when-let* ((client (ebp--connection-client conn)))
              (ebp-client--inbound-check client))))))))

(defun ebp--strict-sentinel (proc _event)
  "PROC changed state: once it is no longer live, conclude its connection."
  (unless (process-live-p proc)
    (when-let* ((conn (process-get proc :ebp-connection)))
      (ebp--strict-conclude conn nil)
      (ebp--binder-connection-lost conn))))

(provide 'ebp-binder)
;;; ebp-binder.el ends here

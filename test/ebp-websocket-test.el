;;; ebp-websocket-test.el --- SPEC 5.5 conformance suite -*- lexical-binding: t; -*-

;;; Commentary:

;; `loopback-websocket' over a live loopback: Emacs binds, an in-process
;; browser-shaped Companion built on `websocket-open' dials.  The
;; Companion speaks through the reference codec (`ebp--parse-body' /
;; `ebp--json-serialize') and runs the same KAT scripts as the wire suite,
;; so the SPEC 9.3 known answers hold over this transport too.

;;; Code:

(require 'ert)
(require 'cl-lib)
(require 'ebp)
(require 'ebp-binder) ; `ebp-binder-max-pending' and the deadline are let-bound below
(require 'ebp-test-common)
(require 'websocket)
(require 'ebp-websocket)

(defconst ebp-wstest--origin "http://127.0.0.1:5173")

(defun ebp-wstest--listen (&rest extra)
  "A listener on a free port over the KAT pairing; returns the logical client."
  (apply #'ebp-websocket-listen
         :port (ebp-test--free-port)
         :allowed-origins (list ebp-wstest--origin)
         (append extra (ebp-test--kat-config))))

(cl-defun ebp-wstest--dial (client script &key (origin ebp-wstest--origin) fragment)
  "Dial CLIENT's listener as a browser Companion running SCRIPT.
ORIGIN nil sends no Origin header.  FRAGMENT non-nil splits every reply
into a text frame and a final continuation frame.  Returns a plist of
closures: :received :errors :closed-p :open-p :send :raw :stop."
  (let* ((port (ebp-client-port client))
         (received '()) (errors '()) (closed nil) (opened nil) (chunks nil)
         (ws nil)
         (send (lambda (reply)
                 (let ((bytes (encode-coding-string (ebp--json-serialize reply)
                                                    'utf-8)))
                   (if fragment
                       (let ((mid (/ (length bytes) 2)))
                         (websocket-send ws (make-websocket-frame
                                             :opcode 'text
                                             :payload (substring bytes 0 mid)
                                             :completep nil))
                         (websocket-send ws (make-websocket-frame
                                             :opcode 'continuation
                                             :payload (substring bytes mid)
                                             :completep t)))
                     (websocket-send ws (make-websocket-frame
                                         :opcode 'text :payload bytes
                                         :completep t)))))))
    (setq ws (websocket-open
              (format "ws://127.0.0.1:%d/" port)
              :custom-header-alist (and origin `(("Origin" . ,origin)))
              :on-open (lambda (_w) (setq opened t))
              :on-message (lambda (_w frame)
                            (push (websocket-frame-payload frame) chunks)
                            (when (websocket-frame-completep frame)
                              (let ((msg (ebp--parse-body
                                          (apply #'concat (nreverse chunks)))))
                                (setq chunks nil)
                                (push msg received)
                                (when script (funcall script msg send)))))
              :on-close (lambda (_w) (setq closed t))
              :on-error (lambda (_w type err) (push (cons type err) errors))))
    (list :ws ws
          :received (lambda () (reverse received))
          :errors (lambda () errors)
          :closed-p (lambda () closed)
          :open-p (lambda () opened)
          :send send
          :raw (lambda (frame) (websocket-send ws frame))
          :stop (lambda () (ignore-errors (websocket-close ws))))))

(defun ebp-wstest--methods (companion)
  "The methods COMPANION received from Emacs, in order."
  (mapcar (lambda (m) (alist-get 'method m))
          (funcall (plist-get companion :received))))

(defun ebp-wstest--ready-p (client)
  (lambda () (eq (ebp-client-state client) 'ready)))

(defun ebp-wstest--raw-request (client request)
  "Send REQUEST bytes to CLIENT's listener; return whatever came back."
  (let* ((out "")
         (proc (make-network-process
                :name "ebp-wstest-raw" :host "127.0.0.1"
                :service (ebp-client-port client) :noquery t :coding 'binary
                :filter (lambda (_p s) (setq out (concat out s))))))
    (process-send-string proc request)
    (ebp-test--wait (lambda () (or (string-match-p "\r\n\r\n" out)
                                   (not (process-live-p proc))))
                    3)
    (ignore-errors (delete-process proc))
    out))

(defun ebp-wstest--raw-upgrade (client origin)
  "A handcrafted, otherwise valid upgrade request carrying ORIGIN (or none)."
  (ebp-wstest--raw-request
   client
   (concat "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
           "Sec-WebSocket-Version: 13\r\n"
           (if origin (format "Origin: %s\r\n" origin) "")
           "\r\n")))

(defun ebp-wstest--stop-all (&rest companions)
  (dolist (c companions) (when c (funcall (plist-get c :stop)))))

;;;; The handshake and the listener lifecycle

(ert-deftest ebp-websocket-test-handshake-to-ready ()
  "SPEC 5.5: Emacs binds, the Companion dials, Emacs still speaks first."
  (let* ((ready 0)
         (client (ebp-wstest--listen :ready-function (lambda (_c) (cl-incf ready))))
         companion)
    (unwind-protect
        (progn
          (should (eq (ebp-client-state client) 'closed))
          (should (equal (ebp-client-close-reason client) '(listening)))
          (should (ebp-client-active-p client))
          (should (eq (ebp-client--transport-role client) 'binder))
          (setq companion (ebp-wstest--dial client (ebp-test--kat-script)))
          (should (ebp-test--wait (lambda () (= ready 1))))
          (should (eq (ebp-client-state client) 'ready))
          (should (equal (ebp-wstest--methods companion)
                         '("session.hello" "auth.response"
                           "queue.replay" "session.ready")))
          (should (equal (ebp-client-granted client) ["theme"]))
          (should (object-of-class-p (ebp-client-connection client)
                                     'ebp-websocket--connection))
          (should (null (ebp-client-parent client)))
          (should (null (ebp--binder-pending
                         (ebp-websocket--listener client)))))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-fragmented-messages-reassemble ()
  "SPEC 5.5: one message may arrive as several frames."
  (let* ((client (ebp-wstest--listen))
         (companion (ebp-wstest--dial client (ebp-test--kat-script) :fragment t)))
    (unwind-protect
        (should (ebp-test--wait (ebp-wstest--ready-p client)))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-origin-gates-the-upgrade ()
  "SPEC 5.5: an absent or unlisted Origin is refused with 403 before the 101."
  (let ((client (ebp-wstest--listen)) absent right)
    (unwind-protect
        (progn
          (setq absent (ebp-wstest--dial client nil :origin nil))
          (should (ebp-test--wait (lambda () (or (funcall (plist-get absent :errors))
                                                 (funcall (plist-get absent :closed-p))))))
          (should (null (funcall (plist-get absent :received))))
          (should (string-prefix-p "HTTP/1.1 403" (ebp-wstest--raw-upgrade client nil)))
          (should (string-prefix-p "HTTP/1.1 403"
                                   (ebp-wstest--raw-upgrade client "http://evil.example")))
          (should (string-prefix-p "HTTP/1.1 403" (ebp-wstest--raw-upgrade client "null")))
          (should (string-prefix-p "HTTP/1.1 101"
                                   (ebp-wstest--raw-upgrade client ebp-wstest--origin)))
          ;; ASCII case-insensitive, like origin serialization itself.
          (should (string-prefix-p "HTTP/1.1 101"
                                   (ebp-wstest--raw-upgrade client "HTTP://127.0.0.1:5173")))
          ;; None of that touched the logical client.
          (should (eq (ebp-client-state client) 'closed))
          (setq right (ebp-wstest--dial client (ebp-test--kat-script)))
          (should (ebp-test--wait (ebp-wstest--ready-p client))))
      (ebp-wstest--stop-all absent right)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-malformed-upgrade-is-quiet ()
  "SPEC 23.3: a bad upgrade is answered 400 and its bytes reach no log sink."
  (let ((client (ebp-wstest--listen)))
    (unwind-protect
        (let ((response (ebp-wstest--raw-request
                         client
                         (concat "GET / HTTP/1.1\r\nHost: x\r\nX-Token: "
                                 ebp-test--secret "\r\n\r\n"))))
          (should (string-prefix-p "HTTP/1.1 400" response))
          (should-not (string-search ebp-test--secret (ebp-test--sink-text))))
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-transport-loss-waits-without-redial ()
  "SPEC 5.7: the binder never redials; the next dial re-establishes."
  (let* ((ready 0)
         (client (ebp-wstest--listen :ready-function (lambda (_c) (cl-incf ready))))
         (a (ebp-wstest--dial client (ebp-test--kat-script)))
         b)
    (unwind-protect
        (progn
          (should (ebp-test--wait (lambda () (= ready 1))))
          (funcall (plist-get a :stop))
          (should (ebp-test--wait (lambda () (eq (ebp-client-state client) 'closed))))
          (should (equal (ebp-client-close-reason client) '(transport-lost)))
          (should (ebp-client-active-p client))
          (should-not (ebp-client-reconnect-timer client))
          (should (process-live-p (ebp--binder-process
                                   (ebp-websocket--listener client))))
          ;; Explicit intent is harmless for a binder: still listening.
          (ebp-client-reconnect-now client)
          (should (ebp-client-active-p client))
          (should (process-live-p (ebp--binder-process
                                   (ebp-websocket--listener client))))
          (setq b (ebp-wstest--dial client (ebp-test--kat-script)))
          (should (ebp-test--wait (lambda () (= ready 2))))
          (should (eq (ebp-client-state client) 'ready)))
      (ebp-wstest--stop-all a b)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-close-tears-down-the-listener ()
  "`ebp-client-close' takes the listener and every connection with it."
  (let* ((client (ebp-wstest--listen))
         (a (ebp-wstest--dial client (ebp-test--kat-script)))
         (port (ebp-client-port client)))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (let ((listener (ebp--binder-process
                           (ebp-websocket--listener client))))
            (ebp-client-close client 'test-done)
            (should (ebp-client-terminal-p client))
            (should-not (process-live-p listener))
            (should (ebp-test--wait (lambda () (funcall (plist-get a :closed-p)))))
            (should (null (ebp-client-transport-state client)))
            (should-error (websocket-open (format "ws://127.0.0.1:%d/" port))
                          :type 'file-error)))
      (ebp-wstest--stop-all a)
      (ebp-client-close client 'test-done))))

;;;; SPEC 5.7: supersession and the pre-authentication pool

(ert-deftest ebp-websocket-test-newest-authenticated-connection-supersedes ()
  "SPEC 5.5/5.7: a newer AUTHENTICATED connection takes over; the older
session's outstanding requests conclude locally with -1."
  (let* ((ready 0)
         (client (ebp-wstest--listen :ready-function (lambda (_c) (cl-incf ready))))
         (kat (ebp-test--kat-script))
         (a (ebp-wstest--dial client
                              (lambda (msg send)
                                (unless (equal (alist-get 'method msg) "surface.update")
                                  (funcall kat msg send)))))
         (swallowed nil)
         b)
    (unwind-protect
        (progn
          (should (ebp-test--wait (lambda () (= ready 1))))
          (let ((conn-a (ebp-client-connection client)))
            (ebp-client-surface-update
             client "app:main" '(:type "text" :text "hi")
             :callback (lambda (status error) (setq swallowed (list status error))))
            (should (ebp-test--wait
                     (lambda () (member "surface.update" (ebp-wstest--methods a)))))
            (should-not swallowed)
            (setq b (ebp-wstest--dial client (ebp-test--kat-script)))
            (should (ebp-test--wait (lambda () (= ready 2))))
            (should (eq (ebp-client-state client) 'ready))
            (should-not (eq (ebp-client-connection client) conn-a))
            (should (ebp-test--wait (lambda () (funcall (plist-get a :closed-p)))))
            (should (equal swallowed '(nil (:code -1 :message "Transport closed"))))
            (should-not (ebp-client-terminal-p client))
            (should (null (ebp--binder-pending
                           (ebp-websocket--listener client))))
            ;; The new session is live: a request round-trips on it.
            (let (done)
              (ebp-client-surface-update
               client "app:main" '(:type "text" :text "again")
               :callback (lambda (status _error) (setq done status)))
              (should (ebp-test--wait (lambda () done)))
              (should (equal done "applied")))))
      (ebp-wstest--stop-all a b)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-failed-candidate-leaves-the-session-alone ()
  "SPEC 5.7: an attempt that fails authentication disturbs nothing."
  (let* ((ready 0)
         (client (ebp-wstest--listen :ready-function (lambda (_c) (cl-incf ready))))
         (a (ebp-wstest--dial client (ebp-test--kat-script)))
         b)
    (unwind-protect
        (progn
          (should (ebp-test--wait (lambda () (= ready 1))))
          (setq b (ebp-wstest--dial
                   client
                   (ebp-test--kat-script
                    :welcome-fn (lambda (w)
                                  (plist-put (copy-sequence w)
                                             :server_proof (make-string 64 ?0))))))
          (should (ebp-test--wait (lambda () (funcall (plist-get b :closed-p)))))
          (should (= ready 1))
          (should (eq (ebp-client-state client) 'ready))
          (should-not (funcall (plist-get a :closed-p)))
          (should (ebp-test--wait
                   (lambda () (null (ebp--binder-pending
                                     (ebp-websocket--listener client))))))
          (let (done)
            (ebp-client-surface-update
             client "app:main" '(:type "text" :text "x")
             :callback (lambda (status _error) (setq done status)))
            (should (ebp-test--wait (lambda () done)))))
      (ebp-wstest--stop-all a b)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-preauth-pool-bound-and-deadline ()
  "SPEC 5.7: a bounded pre-auth pool, newest wins, 10 s to authenticate."
  (let* ((ebp--binder-preauth-deadline 1.5)
         (ebp-binder-max-pending 2)
         (client (ebp-wstest--listen))
         socks)
    (unwind-protect
        (progn
          (dotimes (_ 3)
            (push (make-network-process
                   :name "ebp-wstest-silent" :host "127.0.0.1"
                   :service (ebp-client-port client) :noquery t :coding 'binary)
                  socks)
            ;; Long enough for the accept to land, short against the deadline.
            (dotimes (_ 2) (accept-process-output nil 0.05)))
          (setq socks (nreverse socks))
          ;; The oldest was evicted at the third accept ...
          (should (ebp-test--wait (lambda () (not (process-live-p (car socks))))))
          (should (= 2 (length (ebp--binder-pending
                                (ebp-websocket--listener client)))))
          ;; ... and the rest expire at the deadline.
          (should (ebp-test--wait
                   (lambda () (cl-every (lambda (s) (not (process-live-p s))) socks))
                   4))
          (should (null (ebp--binder-pending
                         (ebp-websocket--listener client))))
          (let ((c (ebp-wstest--dial client (ebp-test--kat-script))))
            (unwind-protect
                (should (ebp-test--wait (ebp-wstest--ready-p client)))
              (ebp-wstest--stop-all c))))
      (dolist (s socks) (ignore-errors (delete-process s)))
      (ebp-client-close client 'test-done))))

;;;; SPEC 5.5 message bound, binary refusal, and receiver strictness

(ert-deftest ebp-websocket-test-message-bound-keeps-the-connection ()
  "SPEC 5.5: an oversize message is discarded, reported once, and the
connection keeps dispatching."
  (let* ((ebp-websocket--diagnostic-interval 60)
         (seen '())
         (client (ebp-wstest--listen
                  :state-changed-function (lambda (_c _s _r id _v) (push id seen))))
         (companion
          (ebp-wstest--dial
           client
           (ebp-test--kat-script
            :welcome-fn (lambda (w)
                          (plist-put (copy-sequence w) :limits
                                     (plist-put (copy-sequence ebp-test--welcome-limits)
                                                :max_frame_bytes 4096)))))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (should (= 4096 (plist-get (ebp-client-limits client) :max_frame_bytes)))
          (let ((send (plist-get companion :send))
                (raw (plist-get companion :raw))
                (received (plist-get companion :received)))
            (cl-flet ((state-changed (id value)
                        `(:jsonrpc "2.0" :method "state.changed"
                          :params (:surface "app:main" :revision_seen 0
                                   :id ,id :value ,value)))
                      (reports ()
                        (cl-count-if (lambda (m)
                                       (and (equal (alist-get 'method m) "log.error")
                                            (eql (alist-get 'code (alist-get 'params m))
                                                 1400)))
                                     (funcall received))))
              ;; One oversize text message: discarded and reported.
              (funcall send (state-changed "big" (make-string 5000 ?x)))
              (should (ebp-test--wait (lambda () (= 1 (reports)))))
              ;; A fragmented overflow: both halves discarded, no second
              ;; report inside the interval.
              (let* ((bytes (encode-coding-string
                             (ebp--json-serialize
                              (state-changed "big2" (make-string 6000 ?y)))
                             'utf-8))
                     (mid (/ (length bytes) 2)))
                (funcall raw (make-websocket-frame :opcode 'text
                                                   :payload (substring bytes 0 mid)
                                                   :completep nil))
                (funcall raw (make-websocket-frame :opcode 'continuation
                                                   :payload (substring bytes mid)
                                                   :completep t)))
              ;; The next message dispatches.
              (funcall send (state-changed "small" "v"))
              (should (ebp-test--wait (lambda () (member "small" seen))))
              (should-not (member "big" seen))
              (should-not (member "big2" seen))
              (should (= 1 (reports)))
              (should (eq (ebp-client-state client) 'ready))
              (should-not (funcall (plist-get companion :closed-p))))))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-binary-message-closes ()
  "SPEC 5.5: a binary message is refused by closing the connection."
  (let* ((client (ebp-wstest--listen))
         (companion (ebp-wstest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (funcall (plist-get companion :raw)
                   (make-websocket-frame :opcode 'binary :payload "abc" :completep t))
          (should (ebp-test--wait (lambda () (funcall (plist-get companion :closed-p)))))
          (should (ebp-test--wait (lambda () (eq (ebp-client-state client) 'closed))))
          (should (equal (ebp-client-close-reason client) '(transport-lost)))
          (should (ebp-client-active-p client))
          (should-not (ebp-client-reconnect-timer client))
          (should (process-live-p (ebp--binder-process
                                   (ebp-websocket--listener client)))))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-receiver-strictness ()
  "SPEC 4.1/6.2 REQUIRED of the binding Emacs: faults answered, connection kept."
  (let* ((seen '())
         (client (ebp-wstest--listen
                  :state-changed-function (lambda (_c _s _r id _v) (push id seen))))
         (companion (ebp-wstest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (let ((raw (plist-get companion :raw))
                (received (plist-get companion :received)))
            (cl-flet ((send-text (bytes)
                        (funcall raw (make-websocket-frame :opcode 'text
                                                           :payload bytes
                                                           :completep t)))
                      (errors ()
                        (cl-loop for m in (funcall received)
                                 for e = (alist-get 'error m)
                                 when e collect (list (alist-get 'code e)
                                                      (alist-get 'kind (alist-get 'data e))
                                                      (alist-get 'id m)))))
              (send-text "{\"jsonrpc\":\"2.0\",\"method\":\"x\"")
              (send-text (unibyte-string ?{ 255 ?}))
              (send-text (concat (make-string 65 ?\[) (make-string 65 ?\])))
              (send-text "{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":{\"n\":99999999999999999999}}")
              (send-text "[]")
              (send-text "{\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\",\"method\":\"x\"}")
              (send-text "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"x\",\"extra\":1}")
              (send-text "{\"jsonrpc\":\"2.0\",\"method\":\"state.changed\",\"params\":{\"surface\":\"app:main\",\"revision_seen\":0,\"id\":\"after\",\"value\":\"v\"}}")
              (should (ebp-test--wait (lambda () (member "after" seen))))
              (should (ebp-test--wait (lambda () (= 7 (length (errors))))))
              (should (equal (errors)
                             '((-32700 "parse-error" :null)
                               (-32700 "parse-error" :null)
                               (-32700 "parse-error" :null)
                               (-32700 "parse-error" :null)
                               (-32600 "invalid-request" :null)
                               (-32600 "invalid-request" :null)
                               (-32600 "invalid-request" 7))))
              (should (eq (ebp-client-state client) 'ready)))))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-decode-isolation-and-unknown-method ()
  "SPEC 23.5 over WS: peer-invented names never reach the global obarray."
  (let* ((client (ebp-wstest--listen))
         (companion (ebp-wstest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (let* ((stamp (format "%x%x" (random 100000000) (random 100000000)))
                 (method (format "peer.invented.%s" stamp))
                 (params (mapconcat (lambda (i) (format "\"m%s_%d\":%d" stamp i i))
                                    (number-sequence 1 400) ","))
                 (count (lambda () (let ((n 0)) (mapatoms (lambda (_) (cl-incf n))) n)))
                 (before (funcall count)))
            (funcall (plist-get companion :raw)
                     (make-websocket-frame
                      :opcode 'text :completep t
                      :payload (encode-coding-string
                                (format "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"%s\",\"params\":{%s}}"
                                        method params)
                                'utf-8)))
            (should (ebp-test--wait
                     (lambda () (cl-some (lambda (m) (eql (alist-get 'id m) 9))
                                         (funcall (plist-get companion :received))))))
            (let ((reply (cl-find-if (lambda (m) (eql (alist-get 'id m) 9))
                                     (funcall (plist-get companion :received))))
                  (after (funcall count)))
              (should (eql (alist-get 'code (alist-get 'error reply)) -32601))
              (should-not (intern-soft method))
              (should-not (intern-soft (format ":m%s_1" stamp)))
              (should (< (- after before) 50)))))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

;;;; Bounds on this endpoint's own behavior

(ert-deftest ebp-websocket-test-sender-bound ()
  "SPEC 4.5: this endpoint never emits a body above max_frame_bytes."
  (let* ((client (ebp-wstest--listen))
         (companion (ebp-wstest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (should-error (ebp-client-notify
                         client 'log.error
                         (list :code 1 :message (make-string (1+ ebp-max-body-octets) ?x)))
                        :type 'ebp-frame-close)
          (should-error (ebp-client-surface-update
                         client "app:main"
                         (list :blob (make-string (1+ ebp-max-body-octets) ?x)))
                        :type 'ebp-frame-close)
          (should (= 0 (ebp-client-outstanding client)))
          (should (eq (ebp-client-state client) 'ready)))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(ert-deftest ebp-websocket-test-backpressure-pauses-the-socket ()
  "SPEC 22.3 over WS: the accepted socket is what pauses, and a send resumes it."
  (let* ((client (ebp-wstest--listen))
         (companion (ebp-wstest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-wstest--ready-p client)))
          (let ((proc (ebp-client-process client)))
            (should (eq (process-status proc) 'open))
            (cl-letf (((symbol-function 'ebp-client--backlog)
                       (lambda (_c) ebp-overload-hold)))
              (ebp-client--inbound-check client))
            (should (eq (process-status proc) 'stop))
            (should (ebp-client-inbound-paused client))
            (ebp-client-notify client 'log.error
                               '(:code 1 :message "ping" :data (:kind "test")))
            (should (eq (process-status proc) 'open))
            (should-not (ebp-client-inbound-paused client))))
      (ebp-wstest--stop-all companion)
      (ebp-client-close client 'test-done))))

(provide 'ebp-websocket-test)
;;; ebp-websocket-test.el ends here

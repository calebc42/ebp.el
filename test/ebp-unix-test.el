;;; ebp-unix-test.el --- SPEC 5.6 conformance suite -*- lexical-binding: t; -*-

;;; Commentary:

;; `emacs-unix' over a live filesystem socket: Emacs binds, an in-process
;; Companion built on `make-network-process :family local' dials.  The
;; Companion speaks through the reference codec (`ebp-make-decoder' /
;; `ebp-encode-frame') and runs the same KAT scripts as the wire suite,
;; so the SPEC 9.3 known answers hold over this transport too.

;;; Code:

(require 'ert)
(require 'cl-lib)
(require 'ebp)
(require 'ebp-binder) ; `ebp-binder-max-pending' and the deadline are let-bound below
(require 'ebp-test-common)
(require 'ebp-unix)

(defun ebp-utest--dir ()
  "A fresh private directory for one test's socket."
  (let ((dir (make-temp-file "ebp-unix-test" t)))
    (set-file-modes dir #o700)
    dir))

(defun ebp-utest--listen (&rest extra)
  "A listener on a fresh socket over the KAT pairing; returns the client."
  (apply #'ebp-unix-listen
         :path (expand-file-name "ebp.sock" (ebp-utest--dir))
         (append extra (ebp-test--kat-config))))

(defun ebp-utest--dial (client script)
  "Dial CLIENT's socket as a Companion running SCRIPT.
Returns a plist of closures: :received :closed-p :send :raw :stop."
  (let* ((path (ebp-client-host client))
         (received '()) (closed nil)
         (decoder (ebp-make-decoder))
         (proc nil)
         (send (lambda (reply)
                 (process-send-string
                  proc (ebp-encode-frame (ebp--json-serialize reply))))))
    (setq proc (make-network-process
                :name "ebp-utest-companion" :family 'local :service path
                :noquery t :coding 'binary
                :filter (lambda (_p bytes)
                          (dolist (msg (ebp-decoder-feed decoder bytes))
                            (push msg received)
                            (when script (funcall script msg send))))
                :sentinel (lambda (p _e)
                            (unless (process-live-p p) (setq closed t)))))
    (list :process proc
          :received (lambda () (reverse received))
          :closed-p (lambda () closed)
          :send send
          :raw (lambda (bytes) (process-send-string proc bytes))
          :stop (lambda () (when (process-live-p proc) (delete-process proc))))))

(defun ebp-utest--methods (companion)
  "The methods COMPANION received from Emacs, in order."
  (mapcar (lambda (m) (alist-get 'method m))
          (funcall (plist-get companion :received))))

(defun ebp-utest--ready-p (client)
  (lambda () (eq (ebp-client-state client) 'ready)))

(defun ebp-utest--stop-all (&rest companions)
  (dolist (c companions) (when c (funcall (plist-get c :stop)))))

(defun ebp-utest--cleanup (client)
  "Close CLIENT and remove its socket directory."
  (let ((dir (file-name-directory (ebp-client-host client))))
    (ebp-client-close client 'test-done)
    (ignore-errors (delete-directory dir t))))

;;;; The handshake and the listener lifecycle

(ert-deftest ebp-unix-test-handshake-to-ready ()
  "SPEC 5.6: Emacs binds, the Companion dials, Emacs still speaks first."
  (let* ((ready 0)
         (client (ebp-utest--listen :ready-function (lambda (_c) (cl-incf ready))))
         companion)
    (unwind-protect
        (progn
          (should (eq (ebp-client-state client) 'closed))
          (should (equal (ebp-client-close-reason client) '(listening)))
          (should (ebp-client-active-p client))
          (should (eq (ebp-client--transport-role client) 'binder))
          (setq companion (ebp-utest--dial client (ebp-test--kat-script)))
          (should (ebp-test--wait (lambda () (= ready 1))))
          (should (eq (ebp-client-state client) 'ready))
          (should (equal (ebp-utest--methods companion)
                         '("session.hello" "auth.response"
                           "queue.replay" "session.ready")))
          (should (equal (ebp-client-granted client) ["theme"]))
          (should (object-of-class-p (ebp-client-connection client)
                                     'ebp--strict-process-connection))
          (should (null (ebp-client-parent client)))
          (should (null (ebp--binder-pending (ebp--binder client)))))
      (ebp-utest--stop-all companion)
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-socket-and-directory-modes ()
  "SPEC 5.6: the directory is 0700 and the socket admits only its user."
  (let ((client (ebp-utest--listen)))
    (unwind-protect
        (let* ((path (ebp-client-host client))
               (dir (directory-file-name (file-name-directory path))))
          (should (eq (aref (file-attribute-modes (file-attributes path)) 0) ?s))
          (should (zerop (logand (file-modes path 'nofollow) #o077)))
          (should (zerop (logand (file-modes dir 'nofollow) #o077))))
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-unsafe-directory-is-refused ()
  "SPEC 5.6: a directory accessible by others is never bound in."
  (let ((dir (ebp-utest--dir)))
    (unwind-protect
        (progn
          (set-file-modes dir #o755)
          (should-error (ebp-unix-listen :path (expand-file-name "ebp.sock" dir))
                        :type 'error))
      (ignore-errors (delete-directory dir t)))))

(ert-deftest ebp-unix-test-stale-socket-is-unlinked-and-rebound ()
  "SPEC 5.6: a socket file of ours that refuses connections is stale."
  (let* ((client (ebp-utest--listen))
         (path (ebp-client-host client))
         (dir (file-name-directory path)))
    (unwind-protect
        (progn
          ;; Kill the listener process behind the client's back: the file
          ;; stays, nothing accepts on it.
          (delete-process (ebp--binder-process (ebp--binder client)))
          (should (file-exists-p path))
          (should-not (ebp-unix--connectable-p path))
          (let ((again (apply #'ebp-unix-listen :path path (ebp-test--kat-config))))
            (unwind-protect
                (let ((c (ebp-utest--dial again (ebp-test--kat-script))))
                  (unwind-protect
                      (should (ebp-test--wait (ebp-utest--ready-p again)))
                    (ebp-utest--stop-all c)))
              (ebp-client-close again 'test-done))))
      (ebp-client-close client 'test-done)
      (ignore-errors (delete-directory dir t)))))

(ert-deftest ebp-unix-test-live-socket-is-refused-never-unlinked ()
  "SPEC 5.6: a connectable socket is another Emacs authority on the path."
  (let* ((client (ebp-utest--listen))
         (path (ebp-client-host client)))
    (unwind-protect
        (progn
          (should (ebp-unix--connectable-p path))
          (let ((err (should-error (apply #'ebp-unix-listen :path path
                                          (ebp-test--kat-config))
                                   :type 'ebp-transport-refused)))
            (should (eq (cadr err) 'socket-in-use)))
          ;; The refusal left the live listener alone.
          (should (file-exists-p path))
          (should (process-live-p (ebp--binder-process (ebp--binder client))))
          (let ((c (ebp-utest--dial client (ebp-test--kat-script))))
            (unwind-protect
                (should (ebp-test--wait (ebp-utest--ready-p client)))
              (ebp-utest--stop-all c))))
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-transport-loss-waits-without-redial ()
  "SPEC 5.7: the binder never redials; the next dial re-establishes."
  (let* ((ready 0)
         (client (ebp-utest--listen :ready-function (lambda (_c) (cl-incf ready))))
         (a (ebp-utest--dial client (ebp-test--kat-script)))
         b)
    (unwind-protect
        (progn
          (should (ebp-test--wait (lambda () (= ready 1))))
          (funcall (plist-get a :stop))
          (should (ebp-test--wait (lambda () (eq (ebp-client-state client) 'closed))))
          (should (equal (ebp-client-close-reason client) '(transport-lost)))
          (should (ebp-client-active-p client))
          (should-not (ebp-client-reconnect-timer client))
          (should (process-live-p (ebp--binder-process (ebp--binder client))))
          (ebp-client-reconnect-now client)
          (should (ebp-client-active-p client))
          (should (process-live-p (ebp--binder-process (ebp--binder client))))
          (setq b (ebp-utest--dial client (ebp-test--kat-script)))
          (should (ebp-test--wait (lambda () (= ready 2))))
          (should (eq (ebp-client-state client) 'ready)))
      (ebp-utest--stop-all a b)
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-close-tears-down-listener-and-unlinks ()
  "`ebp-client-close' takes the listener, every connection, and the file."
  (let* ((client (ebp-utest--listen))
         (a (ebp-utest--dial client (ebp-test--kat-script)))
         (path (ebp-client-host client)))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-utest--ready-p client)))
          (let ((listener (ebp--binder-process (ebp--binder client))))
            (ebp-client-close client 'test-done)
            (should (ebp-client-terminal-p client))
            (should-not (process-live-p listener))
            (should (ebp-test--wait (lambda () (funcall (plist-get a :closed-p)))))
            (should (null (ebp-client-transport-state client)))
            (should-not (file-exists-p path))))
      (ebp-utest--stop-all a)
      (ebp-utest--cleanup client))))

;;;; SPEC 5.7: supersession and the pre-authentication pool

(ert-deftest ebp-unix-test-newest-authenticated-connection-supersedes ()
  "SPEC 5.6/5.7: a newer AUTHENTICATED connection takes over; the older
session's outstanding requests conclude locally with -1."
  (let* ((ready 0)
         (client (ebp-utest--listen :ready-function (lambda (_c) (cl-incf ready))))
         (kat (ebp-test--kat-script))
         (a (ebp-utest--dial client
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
                     (lambda () (member "surface.update" (ebp-utest--methods a)))))
            (should-not swallowed)
            (setq b (ebp-utest--dial client (ebp-test--kat-script)))
            (should (ebp-test--wait (lambda () (= ready 2))))
            (should (eq (ebp-client-state client) 'ready))
            (should-not (eq (ebp-client-connection client) conn-a))
            (should (ebp-test--wait (lambda () (funcall (plist-get a :closed-p)))))
            (should (equal swallowed '(nil (:code -1 :message "Transport closed"))))
            (should-not (ebp-client-terminal-p client))
            (should (null (ebp--binder-pending (ebp--binder client))))
            (let (done)
              (ebp-client-surface-update
               client "app:main" '(:type "text" :text "again")
               :callback (lambda (status _error) (setq done status)))
              (should (ebp-test--wait (lambda () done)))
              (should (equal done "applied")))))
      (ebp-utest--stop-all a b)
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-failed-candidate-leaves-the-session-alone ()
  "SPEC 5.7: an attempt that fails authentication disturbs nothing."
  (let* ((ready 0)
         (client (ebp-utest--listen :ready-function (lambda (_c) (cl-incf ready))))
         (a (ebp-utest--dial client (ebp-test--kat-script)))
         b)
    (unwind-protect
        (progn
          (should (ebp-test--wait (lambda () (= ready 1))))
          (setq b (ebp-utest--dial
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
                   (lambda () (null (ebp--binder-pending (ebp--binder client))))))
          (let (done)
            (ebp-client-surface-update
             client "app:main" '(:type "text" :text "x")
             :callback (lambda (status _error) (setq done status)))
            (should (ebp-test--wait (lambda () done)))))
      (ebp-utest--stop-all a b)
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-preauth-pool-bound-and-deadline ()
  "SPEC 5.7: a bounded pre-auth pool, newest wins, 10 s to authenticate."
  (let* ((ebp--binder-preauth-deadline 1.5)
         (ebp-binder-max-pending 2)
         (client (ebp-utest--listen))
         (path (ebp-client-host client))
         socks)
    (unwind-protect
        (progn
          (dotimes (_ 3)
            (push (make-network-process
                   :name "ebp-utest-silent" :family 'local :service path
                   :noquery t :coding 'binary)
                  socks)
            (dotimes (_ 2) (accept-process-output nil 0.05)))
          (setq socks (nreverse socks))
          ;; The oldest was evicted at the third accept ...
          (should (ebp-test--wait (lambda () (not (process-live-p (car socks))))))
          (should (= 2 (length (ebp--binder-pending (ebp--binder client)))))
          ;; ... and the rest expire at the deadline.
          (should (ebp-test--wait
                   (lambda () (cl-every (lambda (s) (not (process-live-p s))) socks))
                   4))
          (should (null (ebp--binder-pending (ebp--binder client))))
          (let ((c (ebp-utest--dial client (ebp-test--kat-script))))
            (unwind-protect
                (should (ebp-test--wait (ebp-utest--ready-p client)))
              (ebp-utest--stop-all c))))
      (dolist (s socks) (ignore-errors (delete-process s)))
      (ebp-utest--cleanup client))))

;;;; SPEC 6.2/4.1 receiver strictness, REQUIRED of the binding Emacs

(ert-deftest ebp-unix-test-receiver-strictness ()
  "SPEC 5.6: body faults answered, connection kept, session untouched."
  (let* ((seen '())
         (client (ebp-utest--listen
                  :state-changed-function (lambda (_c _s _r id _v) (push id seen))))
         (companion (ebp-utest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-utest--ready-p client)))
          (let ((raw (plist-get companion :raw))
                (received (plist-get companion :received)))
            (cl-flet ((send-body (bytes)
                        (funcall raw (concat (format "Content-Length: %d\r\n\r\n"
                                                     (length bytes))
                                             bytes)))
                      (errors ()
                        (cl-loop for m in (funcall received)
                                 for e = (alist-get 'error m)
                                 when e collect (list (alist-get 'code e)
                                                      (alist-get 'kind (alist-get 'data e))
                                                      (alist-get 'id m)))))
              (send-body "{\"jsonrpc\":\"2.0\",\"method\":\"x\"")
              (send-body (unibyte-string ?{ 255 ?}))
              (send-body (concat (make-string 65 ?\[) (make-string 65 ?\])))
              (send-body "{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":{\"n\":99999999999999999999}}")
              (send-body "[]")
              (send-body "{\"jsonrpc\":\"2.0\",\"jsonrpc\":\"2.0\",\"method\":\"x\"}")
              (send-body "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"x\",\"extra\":1}")
              (send-body "{\"jsonrpc\":\"2.0\",\"method\":\"state.changed\",\"params\":{\"surface\":\"app:main\",\"revision_seen\":0,\"id\":\"after\",\"value\":\"v\"}}")
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
      (ebp-utest--stop-all companion)
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-framing-fault-closes-the-connection ()
  "SPEC 6.2 REQUIRED of the binding Emacs: a malformed header, an oversized
declaration, and an over-long header section each close; the listener
stays and the next dial authenticates."
  (let ((client (ebp-utest--listen)))
    (unwind-protect
        (dolist (bad (list "Content-Length 2\r\n\r\n{}"
                           (format "Content-Length: %d\r\n\r\n" (1+ ebp-max-body-octets))
                           (concat "X: " (make-string (1+ ebp-max-header-octets) ?a))))
          (let ((c (ebp-utest--dial client (ebp-test--kat-script))))
            (unwind-protect
                (progn
                  (should (ebp-test--wait (ebp-utest--ready-p client)))
                  (funcall (plist-get c :raw) bad)
                  (should (ebp-test--wait (lambda () (funcall (plist-get c :closed-p)))))
                  (should (ebp-test--wait
                           (lambda () (eq (ebp-client-state client) 'closed))))
                  (should (ebp-client-active-p client))
                  (should (process-live-p (ebp--binder-process (ebp--binder client)))))
              (ebp-utest--stop-all c))))
      (ebp-utest--cleanup client))))

(ert-deftest ebp-unix-test-decode-isolation-and-unknown-method ()
  "SPEC 23.5 over a Unix socket: peer-invented names never reach the obarray."
  (let* ((client (ebp-utest--listen))
         (companion (ebp-utest--dial client (ebp-test--kat-script))))
    (unwind-protect
        (progn
          (should (ebp-test--wait (ebp-utest--ready-p client)))
          (let* ((stamp (format "%x%x" (random 100000000) (random 100000000)))
                 (method (format "peer.invented.%s" stamp))
                 (member (format "m%s" stamp))
                 (body (format "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"%s\",\"params\":{\"%s\":1}}"
                               method member)))
            (funcall (plist-get companion :raw)
                     (concat (format "Content-Length: %d\r\n\r\n" (length body)) body))
            (should (ebp-test--wait
                     (lambda ()
                       (cl-some (lambda (m) (eql (alist-get 'id m) 9))
                                (funcall (plist-get companion :received))))))
            (let ((reply (cl-find-if (lambda (m) (eql (alist-get 'id m) 9))
                                     (funcall (plist-get companion :received)))))
              (should (eql (alist-get 'code (alist-get 'error reply)) -32601)))
            (should-not (intern-soft method))
            (should-not (intern-soft (concat ":" member)))
            (should (eq (ebp-client-state client) 'ready))))
      (ebp-utest--stop-all companion)
      (ebp-utest--cleanup client))))

(provide 'ebp-unix-test)
;;; ebp-unix-test.el ends here

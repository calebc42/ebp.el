;;; ebp-test-common.el --- Shared fixtures for the ebp.el suites -*- lexical-binding: t; -*-

;;; Commentary:

;; The SPEC 9.3 known-answer pairing, the scripted Companion every suite
;; drives, and the small helpers, factored out of ebp-wire-test.el so the
;; transport suites (ebp-websocket-test.el) can reuse them without
;; loading that suite's tests.  No `ert-deftest' lives here.

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'ebp)

(defconst ebp-test--kat-token (ebp-decode-pairing-token "AAECAwQFBgcICQoLDA0ODw"))

(defconst ebp-test--kat-pid "101112131415161718191a1b1c1d1e1f")

(defconst ebp-test--kat-cn "202122232425262728292a2b2c2d2e2f")

(defconst ebp-test--kat-sn "303132333435363738393a3b3c3d3e3f")

(defconst ebp-test--welcome-limits
  '(:max_frame_bytes 4194304 :max_queued_events 256
    :max_queued_bytes 8388608 :max_event_bytes 262144
    :max_surfaces 16 :max_surface_ids 1024
    :max_field_bytes 65536 :max_input_state_bytes 262144
    :max_capture_fields 64))

(defun ebp-test--welcome-result (&optional server-proof drop surfaces)
  "A minimal SPEC 10.2 welcome result plist.
SERVER-PROOF overrides the correct KAT proof; DROP removes that member;
SURFACES overrides the empty surfaces map."
  (let ((welcome
         `(:server_proof ,(or server-proof
                              (ebp-server-proof ebp-test--kat-token
                                                ebp-test--kat-pid
                                                ebp-test--kat-cn
                                                ebp-test--kat-sn))
           :protocol 3
           :server (:name "kat-companion" :version "1.0.0")
           :granted ["theme"]
           :surface_profiles
           (:app (:node_types ["text" "row" "column" "box" "spacer"
                               "divider" "button" "text_input"]
                  :builtins ["view.switch" "companion.settings.open"]
                  :features []
                  :extensions []))
           :surfaces ,(or surfaces ebp--empty-object)
           :queued_events 0
           :limits ,ebp-test--welcome-limits)))
    (if drop
        (cl-loop for (k v) on welcome by #'cddr
                 unless (eq k drop) append (list k v))
      welcome)))

(cl-defun ebp-test--kat-script (&key welcome-fn after-ready surface-fn
                                     replay-fn data-fn)
  "The default conformant companion script over the KAT pairing.
REPLAY-FN, when given, is called with the 1-based replay call number and
returns that call's summary plist.  DATA-FN, like SURFACE-FN, scripts the
result of a `surface.data' request."
  (let ((replay-calls 0))
    (lambda (msg send)
      (let* ((method (alist-get 'method msg))
             (id (alist-get 'id msg))
             (reply (lambda (result)
                      (funcall send `(:jsonrpc "2.0" :id ,id :result ,result)))))
        (pcase method
          ("session.hello"
           (funcall reply `(:server_nonce ,ebp-test--kat-sn)))
          ("auth.response"
           (funcall reply (funcall (or welcome-fn #'identity)
                                   (ebp-test--welcome-result))))
          ("queue.replay"
           (cl-incf replay-calls)
           (funcall reply
                    (if replay-fn
                        (funcall replay-fn replay-calls)
                      '(:delivered 0 :rejected 0 :expired 0 :remaining 0
                        :blocked_by :null))))
        ("session.ready"
         (funcall reply ebp--empty-object)
         (when after-ready (funcall after-ready send)))
        ("surface.update"
         (funcall reply
                  (funcall (or surface-fn
                               (lambda (m)
                                 `(:status "applied"
                                   :revision ,(alist-get
                                               'revision (alist-get 'params m))
                                   :present t)))
                           msg)))
        ("surface.data"
         (funcall reply
                  (funcall (or data-fn
                               (lambda (m)
                                 `(:status "applied"
                                   :revision ,(alist-get
                                               'revision (alist-get 'params m))
                                   :present t)))
                           msg)))
        ("surface.remove"
         (funcall reply `(:status "applied"
                          :revision ,(alist-get 'revision (alist-get 'params msg))
                          :present :false))))))))

(defun ebp-test--wait (pred &optional timeout)
  "Pump the event loop until PRED or TIMEOUT (default 5 s); return PRED."
  (let ((deadline (+ (float-time) (or timeout 5))))
    (while (and (not (funcall pred)) (< (float-time) deadline))
      (accept-process-output nil 0.05))
    (funcall pred)))

(defconst ebp-test--secret "SUPERSECRET-PASSWORD-VALUE-9d41"
  "A distinctive volatile value planted in an undecodable frame body.")

(defun ebp-test--sink-text ()
  "The concatenated text of both SPEC 23.3 log sinks."
  (concat (with-current-buffer (get-buffer-create "*Messages*") (buffer-string))
          (if-let* ((w (get-buffer "*Warnings*")))
              (with-current-buffer w (buffer-string))
            "")))

(defun ebp-test--kat-config (&rest extra)
  "The KAT client config every transport test dials with, plus EXTRA."
  (append extra
          (list :client-name "test-client" :client-version "0.0.1"
                :pairing-id ebp-test--kat-pid :token ebp-test--kat-token
                :wants '("theme") :client-nonce ebp-test--kat-cn
                :receipt-file (make-temp-file "ebp-transport-receipts"))))

(defun ebp-test--buffer-has (buf needle)
  "Non-nil when BUF's text contains NEEDLE."
  (with-current-buffer buf
    (save-excursion (goto-char (point-min)) (search-forward needle nil t))))

(defun ebp-test--buffer-count (buf needle)
  "How many times NEEDLE occurs in BUF."
  (with-current-buffer buf
    (save-excursion
      (goto-char (point-min))
      (cl-loop while (search-forward needle nil t) count t))))

(defun ebp-test--free-port ()
  "An ephemeral TCP port nothing is bound to right now."
  (let* ((probe (make-network-process
                 :name "ebp-test-port-probe" :server t :host "127.0.0.1"
                 :service t :reuseaddr t :noquery t))
         (port (cadr (process-contact probe))))
    (delete-process probe)
    port))

(provide 'ebp-test-common)
;;; ebp-test-common.el ends here

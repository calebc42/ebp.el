;;; ebp-revision-test.el --- ERT for persistent surface revisions -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:

;; SPEC 13.1: Emacs MUST persist its next revision per surface.  These
;; tests cover the durable floor seam end to end: the store contract in
;; `ebp-sqlite', the send-time reservation in `ebp-client--surface-request'
;; (committed BEFORE the frame is built, so a death before the send never
;; reuses a number), the welcome/result absorption that only ever rises,
;; and the schema version 1 -> 2 upgrade that carries receipts across.
;;
;; Outbound frames are captured by stubbing `ebp-client--request', exactly
;; as ebp-sync-test does; nothing here opens a socket.

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'sqlite)
(require 'ebp)

(defconst ebp-revision-test-pair (make-string 32 ?c))
(defconst ebp-revision-test-event "00000000000000000000000000000011")

(cl-defmacro ebp-revision-test--with-file ((file) &rest body)
  "Bind FILE to a fresh path in a temporary directory around BODY."
  (declare (indent 1) (debug ((symbolp) body)))
  `(progn
     (skip-unless (and (fboundp 'sqlite-available-p) (sqlite-available-p)))
     (let ((directory (make-temp-file "ebp-revision-test-" t)))
       (unwind-protect
           (let ((,file (expand-file-name "store.sqlite" directory)))
             ,@body)
         (delete-directory directory t)))))

(defun ebp-revision-test--client (file)
  "A client whose receipts and floors live in FILE, partitioned by pairing."
  (ebp-client-create :receipt-file file
                     :pairing-id ebp-revision-test-pair))

(defun ebp-revision-test--floors (file)
  "FILE's persisted floors for the test pairing, through a fresh handle."
  (let ((store (ebp-sqlite-open file)))
    (unwind-protect
        (ebp-store-surface-floors store ebp-revision-test-pair)
      (ebp-store-close store))))

(ert-deftest ebp-revision-raise-floor-persists-across-reopen ()
  "(a) A raised floor is durable: a fresh handle on the same file sees it."
  (ebp-revision-test--with-file (file)
    (let ((store (ebp-sqlite-open file)))
      (unwind-protect
          (progn
            (should-not (ebp-store-surface-floors store ebp-revision-test-pair))
            (should (= 4 (ebp-store-raise-floor
                          store ebp-revision-test-pair "app:main" 4 100)))
            (should (= 0 (ebp-store-raise-floor
                          store ebp-revision-test-pair "app:old" 0 100))))
        (ebp-store-close store)))
    (should (equal '(("app:main" . 4) ("app:old" . 0))
                   (ebp-revision-test--floors file)))))

(ert-deftest ebp-revision-raise-floor-never-lowers ()
  "(b) Floors only rise: a lower request returns and keeps the higher."
  (ebp-revision-test--with-file (file)
    (let ((store (ebp-sqlite-open file)))
      (unwind-protect
          (progn
            (should (= 9 (ebp-store-raise-floor
                          store ebp-revision-test-pair "app:main" 9 100)))
            (should (= 9 (ebp-store-raise-floor
                          store ebp-revision-test-pair "app:main" 2 200)))
            (should (= 10 (ebp-store-raise-floor
                           store ebp-revision-test-pair "app:main" 10 300)))
            ;; Another pairing is another partition.
            (should-not (ebp-store-surface-floors
                         store (make-string 32 ?d))))
        (ebp-store-close store)))
    (should (equal '(("app:main" . 10)) (ebp-revision-test--floors file)))))

(ert-deftest ebp-revision-raise-floor-validates-arguments ()
  "A Surface ID and a non-negative integer revision are required."
  (ebp-revision-test--with-file (file)
    (let ((store (ebp-sqlite-open file)))
      (unwind-protect
          (progn
            (should-error (ebp-store-raise-floor
                           store ebp-revision-test-pair "main" 1 100)
                          :type 'wrong-type-argument)
            (should-error (ebp-store-raise-floor
                           store ebp-revision-test-pair "app:main" -1 100)
                          :type 'wrong-type-argument)
            (should-error (ebp-store-raise-floor
                           store ebp-revision-test-pair "app:main" 1.5 100)
                          :type 'wrong-type-argument)
            (should-error (ebp-store-raise-floor
                           store "not-a-pairing" "app:main" 1 100)
                          :type 'wrong-type-argument))
        (ebp-store-close store)))))

(ert-deftest ebp-revision-reservation-commits-before-send ()
  "(c) The reserved revision is durable when the send begins."
  (ebp-revision-test--with-file (file)
    (let ((client (ebp-revision-test--client file))
          (seen nil))
      (unwind-protect
          (progn
            (should (ebp-client-store client))
            (cl-letf (((symbol-function 'ebp-client--request)
                       (lambda (c _method params _callback &optional _t)
                         ;; Inside the send: the floor is already on disk.
                         (setq seen (ebp-store-surface-floors
                                     (ebp-client-store c)
                                     ebp-revision-test-pair))
                         (should (= (plist-get params :revision) 0)))))
              (should (= 0 (ebp-client-surface-update
                            client "app:main" '(:t "text" :text "hi")))))
            (should (equal seen '(("app:main" . 0))))
            (should (= 0 (ebp-client--surface-floor client "app:main"))))
        (ebp-client-close client 'test-done)))))

(ert-deftest ebp-revision-persistence-failure-sends-nothing ()
  "(d) A store that cannot commit the reservation fails closed."
  (ebp-revision-test--with-file (file)
    (let ((client (ebp-revision-test--client file))
          (called nil))
      (unwind-protect
          (cl-letf (((symbol-function 'ebp-client--request)
                     (lambda (&rest _) (setq called t))))
            (let ((ebp-sqlite--fault-function
                   (lambda (point)
                     (when (eq point 'before-commit)
                       (error "Injected floor commit failure")))))
              (should-error (ebp-client-surface-update
                             client "app:main" '(:t "text" :text "hi"))
                            :type 'ebp-store-error))
            (should-not called)
            ;; Nothing was claimed in memory either.
            (should (= -1 (ebp-client--surface-floor client "app:main")))
            (should-not (ebp-store-surface-floors (ebp-client-store client)
                                                  ebp-revision-test-pair))
            ;; The rollback left the store usable: the next push succeeds.
            (should (= 0 (ebp-client-surface-update
                          client "app:main" '(:t "text" :text "hi"))))
            (should called))
        (ebp-client-close client 'test-done)))))

(ert-deftest ebp-revision-survives-death-before-send ()
  "(e) A second life on the same partition allocates above the first."
  (ebp-revision-test--with-file (file)
    (let ((first (ebp-revision-test--client file)))
      (cl-letf (((symbol-function 'ebp-client--request)
                 (lambda (&rest _) nil)))
        (should (= 0 (ebp-client-surface-update
                      first "app:main" '(:t "text" :text "one"))))
        (should (= 1 (ebp-client-surface-update
                      first "app:main" '(:t "text" :text "two"))))
        ;; The first life dies here without ever hearing a result.
        (ebp-client-close first 'died)
        (let ((second (ebp-revision-test--client file)))
          (unwind-protect
              (progn
                ;; Restored at open, before any welcome.
                (should (= 1 (ebp-client--surface-floor second "app:main")))
                (should (= 2 (ebp-client-surface-update
                              second "app:main" '(:t "text" :text "three")))))
            (ebp-client-close second 'test-done))))
      (should (equal '(("app:main" . 2)) (ebp-revision-test--floors file))))))

(ert-deftest ebp-revision-absorb-never-lowers-and-persists ()
  "(f) A reported floor below the persisted one leaves both untouched."
  (ebp-revision-test--with-file (file)
    (let ((client (ebp-revision-test--client file)))
      (unwind-protect
          (progn
            (should (= 7 (ebp-client--absorb-floor client "app:x" 7)))
            (should (= 7 (ebp-client--absorb-floor client "app:x" 3)))
            (should (= 7 (ebp-client--surface-floor client "app:x")))
            (should (equal '(("app:x" . 7))
                           (ebp-store-surface-floors (ebp-client-store client)
                                                     ebp-revision-test-pair)))
            (should (ebp-client-active-p client))
            ;; A welcome-style lower report after a restart: the persisted
            ;; floor wins and the next push climbs above it.
            (ebp-client-close client 'restart)
            (setq client (ebp-revision-test--client file))
            (should (= 7 (ebp-client--absorb-floor client "app:x" 3)))
            (cl-letf (((symbol-function 'ebp-client--request)
                       (lambda (&rest _) nil)))
              (should (= 8 (ebp-client-surface-update
                            client "app:x" '(:t "text" :text "hi"))))))
        (ebp-client-close client 'test-done)))))

(ert-deftest ebp-revision-absorb-failure-closes-the-client ()
  "A floor that cannot be committed closes the client, fail closed."
  (ebp-revision-test--with-file (file)
    (let ((client (ebp-revision-test--client file)))
      (unwind-protect
          (progn
            (let ((ebp-sqlite--fault-function
                   (lambda (point)
                     (when (eq point 'after-floor-write)
                       (error "Injected floor commit failure")))))
              (should-not (ebp-client--absorb-floor client "app:x" 5)))
            (should-not (ebp-client-active-p client))
            (should (eq (car (ebp-client-close-reason client))
                        'revision-persistence-failed))
            (should (equal (cadr (ebp-client-close-reason client)) "app:x")))
        (ignore-errors (ebp-client-close client 'test-done))))))

(ert-deftest ebp-revision-welcome-floors-rise-through-absorb ()
  "SPEC 10.3 step 1 goes through the absorb seam: persisted and rising."
  (ebp-revision-test--with-file (file)
    (let ((client (ebp-revision-test--client file))
          (pushed nil))
      (unwind-protect
          (progn
            ;; A previous life left a floor above what the Companion reports.
            (ebp-client--absorb-floor client "app:main" 41)
            (ebp-client-close client 'restart)
            (setq client (ebp-revision-test--client file))
            (setf (ebp-client-client-nonce client) (make-string 32 ?1))
            (cl-letf (((symbol-function 'ebp-verify-server-proof)
                       (lambda (&rest _) t))
                      ((symbol-function 'ebp-client--request)
                       (lambda (_c method params _cb &optional _t)
                         (push (cons method params) pushed))))
              ;; Drive the pure SPEC 10.1 machine to `awaiting-welcome'.
              (ebp-client--step client 'hello-sent)
              (ebp-client--step client 'nonce-received)
              (ebp-client--step client 'auth-sent)
              (should (eq (ebp-client-state client) 'awaiting-welcome))
              (ebp-client--on-welcome
               client (make-string 32 ?2)
               (list :server_proof (make-string 64 ?a) :protocol 3
                     :server '(:name "s" :version "1")
                     :granted []
                     :surface_profiles
                     '(:app (:node_types ["text"] :builtins [] :features []
                             :extensions []))
                     :surfaces '(:app:main (:revision 9 :present t)
                                 :app:old (:revision 3 :present :false))
                     :queued_events 0
                     :limits '(:max_frame_bytes 4194304))
               nil))
            (should (eq (ebp-client-state client) 'syncing))
            (should (= 41 (ebp-client--surface-floor client "app:main")))
            (should (= 3 (ebp-client--surface-floor client "app:old")))
            (should (equal '(("app:main" . 41) ("app:old" . 3))
                           (ebp-store-surface-floors (ebp-client-store client)
                                                     ebp-revision-test-pair)))
            ;; The barrier went on: replay was requested.
            (should (assq 'queue.replay pushed)))
        (ebp-client-close client 'test-done)))))

(ert-deftest ebp-revision-v1-file-upgrades-in-place ()
  "(g) A schema version 1 file gains `surface_floors' and keeps receipts."
  (ebp-revision-test--with-file (file)
    (let ((db (sqlite-open file)))
      (unwind-protect
          (progn
            (dolist (statement ebp-sqlite--schema-ddl)
              (sqlite-execute db statement))
            (sqlite-execute db "PRAGMA user_version = 1")
            (sqlite-execute db "INSERT INTO pairing_partitions VALUES (?, ?)"
                            (list ebp-revision-test-pair 100))
            (sqlite-execute
             db "INSERT INTO accepted_events
                   (pairing_id, event_id, accepted_at_ms, completed_at_ms)
                   VALUES (?, ?, ?, ?)"
             (list ebp-revision-test-pair ebp-revision-test-event 100 100)))
        (sqlite-close db)))
    ;; The upgrade is atomic: an injected failure leaves version 1 intact.
    (let ((ebp-sqlite--fault-function
           (lambda (point)
             (when (eq point 'after-v2-upgrade)
               (error "Injected upgrade failure")))))
      (should-error (ebp-sqlite-open file) :type 'ebp-store-error))
    (let ((db (sqlite-open file)))
      (unwind-protect
          (progn
            (should (= 1 (caar (sqlite-select db "PRAGMA user_version"))))
            (should (equal '("accepted_events" "action_work"
                             "pairing_partitions")
                           (ebp-sqlite--user-tables db))))
        (sqlite-close db)))
    (let ((store (ebp-sqlite-open file)))
      (unwind-protect
          (progn
            (should (= 2 (caar (sqlite-select (ebp-sqlite-store-db store)
                                              "PRAGMA user_version"))))
            (should (equal ebp-sqlite--schema-tables
                           (ebp-sqlite--user-tables
                            (ebp-sqlite-store-db store))))
            (should (ebp-store-known-p store ebp-revision-test-pair
                                       ebp-revision-test-event))
            (should-not (ebp-store-surface-floors store ebp-revision-test-pair))
            (should (= 5 (ebp-store-raise-floor
                          store ebp-revision-test-pair "app:main" 5 200))))
        (ebp-store-close store)))))

(ert-deftest ebp-revision-forget-pairing-erases-floors ()
  "SPEC 9.1 local removal takes the pairing's floors with its receipts."
  (ebp-revision-test--with-file (file)
    (let ((store (ebp-sqlite-open file)))
      (unwind-protect
          (progn
            (ebp-store-raise-floor store ebp-revision-test-pair "app:main" 3 100)
            (ebp-store-raise-floor store (make-string 32 ?d) "app:main" 8 100)
            (ebp-store-forget-pairing store ebp-revision-test-pair)
            (should-not (ebp-store-surface-floors store ebp-revision-test-pair))
            (should (equal '(("app:main" . 8))
                           (ebp-store-surface-floors store (make-string 32 ?d)))))
        (ebp-store-close store)))))

(provide 'ebp-revision-test)
;;; ebp-revision-test.el ends here

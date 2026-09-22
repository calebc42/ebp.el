;;; ebp-store-test.el --- EBP durable store tests -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:

;; Storage-contract and built-in SQLite backend tests.  These tests have no
;; dependency on Jetpacs application code or on the protocol endpoint.

;;; Code:

(require 'cl-lib)
(require 'ert)
(require 'sqlite)
(require 'ebp-sqlite)

(defconst ebp-store-test-pair-a (make-string 32 ?a))
(defconst ebp-store-test-pair-b (make-string 32 ?b))
(defconst ebp-store-test-event-a "00000000000000000000000000000001")
(defconst ebp-store-test-event-b "00000000000000000000000000000002")
(defconst ebp-store-test-event-c "00000000000000000000000000000003")

(cl-defmacro ebp-store-test--with-store ((store file) &rest body)
  "Open a temporary STORE at FILE while evaluating BODY."
  (declare (indent 1) (debug ((symbolp symbolp) body)))
  `(progn
     (skip-unless (and (fboundp 'sqlite-available-p)
                       (sqlite-available-p)))
     (let* ((directory (make-temp-file "ebp-store-test-" t))
            (,file (expand-file-name "store.sqlite" directory))
            (,store nil))
       (unwind-protect
           (progn
             (setq ,store (ebp-sqlite-open ,file))
             ,@body)
         (when (and ,store
                    (ebp-sqlite-store-p ,store)
                    (not (ebp-sqlite-store-closed-p ,store)))
           (ebp-store-close ,store))
         (delete-directory directory t)))))

(defun ebp-store-test--admit
    (store event-id &optional pairing-id now-ms payload)
  "Admit EVENT-ID to STORE using compact deterministic test data."
  (ebp-store-admit
   store (or pairing-id ebp-store-test-pair-a) event-id
   "test.render" (or payload "{\"value\":1}") (or now-ms 100)))

(defun ebp-store-test--write-legacy (file rows)
  "Write the shipped pre-v1 flat receipt store at FILE holding ROWS.
Each row is a cons (EVENT-ID . TS); a nil half is stored as SQL NULL."
  (let ((db (sqlite-open file)))
    (unwind-protect
        (progn
          (sqlite-execute
           db "CREATE TABLE receipts (event_id TEXT PRIMARY KEY, ts REAL)")
          (dolist (row rows)
            (cond
             ;; SQLite permits NULL in a TEXT PRIMARY KEY column, so the
             ;; shipped legacy table really could hold this row.
             ((null (car row))
              (sqlite-execute db "INSERT INTO receipts VALUES (NULL, ?)"
                              (list (cdr row))))
             ((cdr row)
              (sqlite-execute db "INSERT INTO receipts VALUES (?, ?)"
                              (list (car row) (cdr row))))
             (t
              (sqlite-execute db "INSERT INTO receipts VALUES (?, NULL)"
                              (list (car row)))))))
      (sqlite-close db))))

(cl-defmacro ebp-store-test--with-legacy ((file rows) &rest body)
  "Bind FILE to a fresh pre-v1 flat receipt store holding ROWS for BODY."
  (declare (indent 1) (debug ((symbolp form) body)))
  `(progn
     (skip-unless (and (fboundp 'sqlite-available-p)
                       (sqlite-available-p)))
     (let ((directory (make-temp-file "ebp-store-legacy-test-" t)))
       (unwind-protect
           (let ((,file (expand-file-name "receipts.sqlite" directory)))
             (ebp-store-test--write-legacy ,file ,rows)
             ,@body)
         (delete-directory directory t)))))

(defun ebp-store-test--raw-tables (file)
  "Return FILE's sorted non-internal table names, opened raw."
  (let ((db (sqlite-open file)))
    (unwind-protect
        (sort (mapcar #'car
                      (sqlite-select
                       db
                       "SELECT name FROM sqlite_master
                          WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
              #'string<)
      (sqlite-close db))))

(defun ebp-store-test--raw-version (file)
  "Return FILE's `user_version', opened raw."
  (let ((db (sqlite-open file)))
    (unwind-protect
        (caar (sqlite-select db "PRAGMA user_version"))
      (sqlite-close db))))

(defun ebp-store-test--raw-legacy-rows (file)
  "Return FILE's legacy `receipts' rows ordered by id, opened raw."
  (let ((db (sqlite-open file)))
    (unwind-protect
        (sqlite-select db "SELECT event_id, ts FROM receipts
                            ORDER BY event_id")
      (sqlite-close db))))

(ert-deftest ebp-sqlite-creates-and-verifies-versioned-schema ()
  (ebp-store-test--with-store (store file)
    (let ((db (ebp-sqlite-store-db store)))
      (should (= 2 (caar (sqlite-select db "PRAGMA user_version"))))
      (should (= 1 (caar (sqlite-select db "PRAGMA foreign_keys"))))
      (should (= 2 (caar (sqlite-select db "PRAGMA synchronous"))))
      (should (= ebp-sqlite-busy-timeout-ms
                 (caar (sqlite-select db "PRAGMA busy_timeout"))))
      (should (equal "wal"
                     (downcase
                      (format "%s"
                              (caar (sqlite-select
                                     db "PRAGMA journal_mode"))))))
      (should
       (equal
        '("accepted_events" "action_work" "pairing_partitions"
          "surface_floors")
        (sort
         (mapcar
          #'car
          (sqlite-select
           db
           "SELECT name FROM sqlite_master
              WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"))
         #'string<)))
      (should (equal '(("ok")) (sqlite-select db "PRAGMA integrity_check")))
      (should-not (sqlite-select db "PRAGMA foreign_key_check")))))

(ert-deftest ebp-sqlite-refuses-unknown-or-unversioned-existing-schema ()
  (skip-unless (and (fboundp 'sqlite-available-p) (sqlite-available-p)))
  (let ((directory (make-temp-file "ebp-store-schema-test-" t)))
    (unwind-protect
        (let ((unknown (expand-file-name "unknown.sqlite" directory))
              (legacy (expand-file-name "legacy.sqlite" directory)))
          (let ((db (sqlite-open unknown)))
            (sqlite-execute db "PRAGMA user_version = 99")
            (sqlite-close db))
          (should-error (ebp-sqlite-open unknown)
                        :type 'ebp-store-error)
          (let ((db (sqlite-open legacy)))
            (sqlite-execute db "CREATE TABLE legacy_data (id INTEGER)")
            (sqlite-close db))
          (should-error (ebp-sqlite-open legacy)
                        :type 'ebp-store-error)
          ;; An adopting pairing id unlocks ONLY the exact shipped pre-v1
          ;; flat layout: neither a versioned stranger, nor an unknown
          ;; unversioned table, nor `receipts' alongside anything else.
          (should-error (ebp-sqlite-open unknown ebp-store-test-pair-a)
                        :type 'ebp-store-error)
          (should-error (ebp-sqlite-open legacy ebp-store-test-pair-a)
                        :type 'ebp-store-error)
          (let ((mixed (expand-file-name "mixed.sqlite" directory)))
            (ebp-store-test--write-legacy
             mixed (list (cons ebp-store-test-event-a 1700000000.5)))
            (let ((db (sqlite-open mixed)))
              (sqlite-execute db "CREATE TABLE extra_data (id INTEGER)")
              (sqlite-close db))
            (should-error (ebp-sqlite-open mixed ebp-store-test-pair-a)
                          :type 'ebp-store-error)
            (should (= 0 (ebp-store-test--raw-version mixed)))
            (should (equal '("extra_data" "receipts")
                           (ebp-store-test--raw-tables mixed)))))
      (delete-directory directory t))))

(ert-deftest ebp-sqlite-fails-closed-when-sqlite-is-unavailable ()
  (cl-letf (((symbol-function 'sqlite-available-p)
             (lambda () nil)))
    (should-error
     (ebp-sqlite-open
      (expand-file-name "unavailable.sqlite" temporary-file-directory))
     :type 'ebp-store-unavailable)))

(ert-deftest ebp-sqlite-admission-is-idempotent-across-reopen ()
  (ebp-store-test--with-store (store file)
    (should (eq 'admitted
                (ebp-store-test--admit
                 store ebp-store-test-event-a nil 100 "{\"first\":true}")))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-a))
    (should
     (eq 'duplicate
         (ebp-store-admit
          store ebp-store-test-pair-a ebp-store-test-event-a
          "test.other" "{\"replacement\":true}" 200)))
    (let ((work (car (ebp-store-list-work store))))
      (should (equal "test.render" (ebp-store-work-action work)))
      (should (equal "{\"first\":true}" (ebp-store-work-payload-json work)))
      (should (eq 'pending (ebp-store-work-state work))))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-a))
    (should (= 1 (length (ebp-store-list-work store))))))

(ert-deftest ebp-sqlite-partitions-identical-event-ids-by-pairing ()
  (ebp-store-test--with-store (store file)
    (should (eq 'admitted
                (ebp-store-test--admit
                 store ebp-store-test-event-a ebp-store-test-pair-a)))
    (should (eq 'admitted
                (ebp-store-test--admit
                 store ebp-store-test-event-a ebp-store-test-pair-b)))
    (should (= 1 (length
                  (ebp-store-list-work store ebp-store-test-pair-a))))
    (should (= 1 (length
                  (ebp-store-list-work store ebp-store-test-pair-b))))
    (should (= 1
               (ebp-store-forget-pairing store ebp-store-test-pair-a)))
    (should (= 0
               (ebp-store-forget-pairing store ebp-store-test-pair-a)))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (should (ebp-store-known-p
             store ebp-store-test-pair-b ebp-store-test-event-a))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should (= 1 (length (ebp-store-list-work store))))
    (should (equal ebp-store-test-pair-b
                   (ebp-store-work-pairing-id
                    (car (ebp-store-list-work store)))))))

(ert-deftest ebp-sqlite-rolls-back-partial-admission ()
  (ebp-store-test--with-store (store file)
    (let ((ebp-sqlite--fault-function
           (lambda (point)
             (when (eq point 'after-receipt)
               (error "Injected admission failure")))))
      (should-error
       (ebp-store-test--admit store ebp-store-test-event-a)
       :type 'ebp-store-error))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (should-not (ebp-store-list-work store))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (should-not (ebp-store-list-work store))))

(ert-deftest ebp-sqlite-never-accepts-a-false-commit-result ()
  (ebp-store-test--with-store (store file)
    (cl-letf (((symbol-function 'sqlite-commit)
               (lambda (_db) nil)))
      (should-error
       (ebp-store-test--admit store ebp-store-test-event-a)
       :type 'ebp-store-error))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (should-not (ebp-store-list-work store))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))))

(ert-deftest ebp-sqlite-claims-in-admission-order-and-can-scope-pairing ()
  (ebp-store-test--with-store (store file)
    (ebp-store-test--admit
     store ebp-store-test-event-a ebp-store-test-pair-a 10)
    (ebp-store-test--admit
     store ebp-store-test-event-b ebp-store-test-pair-b 20)
    (ebp-store-test--admit
     store ebp-store-test-event-c ebp-store-test-pair-a 30)
    (let ((pair-b-work
           (ebp-store-claim-next
            store "worker-b" 30 100 ebp-store-test-pair-b)))
      (should (equal ebp-store-test-pair-b
                     (ebp-store-work-pairing-id pair-b-work))))
    (let ((first (ebp-store-claim-next store "worker-a" 30 100)))
      (should (equal ebp-store-test-event-a
                     (ebp-store-work-event-id first))))
    (let ((next (ebp-store-claim-next store "worker-c" 30 100)))
      (should (equal ebp-store-test-event-c
                     (ebp-store-work-event-id next))))))

(ert-deftest ebp-sqlite-recovers-expired-leases-and-retains-blocked-work ()
  (ebp-store-test--with-store (store file)
    (ebp-store-test--admit store ebp-store-test-event-a nil 100)
    (let ((first (ebp-store-claim-next store "worker-a" 100 50)))
      (should (= 1 (ebp-store-work-attempt-count first)))
      (should (= 150 (ebp-store-work-lease-until-ms first)))
      (should-not (ebp-store-claim-next store "worker-b" 149 50))
      (ebp-store-close store)
      (setq store (ebp-sqlite-open file))
      (let ((recovered (ebp-store-claim-next store "worker-b" 150 50)))
        (should (= 2 (ebp-store-work-attempt-count recovered)))
        (should-not (equal (ebp-store-work-lease-id first)
                           (ebp-store-work-lease-id recovered)))
        (should-error (ebp-store-complete store first 151)
                      :type 'ebp-store-stale-lease)
        (should (ebp-store-retry
                 store recovered 151 200 "transient"))
        (should-not (ebp-store-claim-next store "worker-c" 199 50))
        (let ((retried (ebp-store-claim-next store "worker-c" 200 50)))
          (should (= 3 (ebp-store-work-attempt-count retried)))
          (should (ebp-store-block store retried 201 "manual.review")))))
    (let ((blocked (car (ebp-store-list-work store nil 'blocked))))
      (should blocked)
      (should (equal "manual.review"
                     (ebp-store-work-last-error-kind blocked))))
    (should-not (ebp-store-claim-next store "worker-d" 10000 50))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should (= 1 (length (ebp-store-list-work store nil 'blocked))))))

(ert-deftest ebp-sqlite-checkpoint-is-atomic-and-lease-checked ()
  (ebp-store-test--with-store (store file)
    (ebp-store-test--admit
     store ebp-store-test-event-a nil 100 "{\"cursor\":0}")
    (let* ((work (ebp-store-claim-next store "worker-a" 100 50))
           (next (ebp-store-checkpoint
                  store work "{\"cursor\":1}" 110)))
      (should (equal "{\"cursor\":1}"
                     (ebp-store-work-payload-json next)))
      (should (= 110 (ebp-store-work-updated-at-ms next)))
      (should (equal (ebp-store-work-lease-id work)
                     (ebp-store-work-lease-id next)))
      (let ((ebp-sqlite--fault-function
             (lambda (point)
               (when (eq point 'after-checkpoint)
                 (error "Injected checkpoint failure")))))
        (should-error
         (ebp-store-checkpoint store next "{\"cursor\":2}" 120)
         :type 'ebp-store-error))
      (should
       (equal "{\"cursor\":1}"
              (ebp-store-work-payload-json
               (car (ebp-store-list-work store nil 'leased)))))
      (ebp-store-close store)
      (setq store (ebp-sqlite-open file))
      (should
       (equal "{\"cursor\":1}"
              (ebp-store-work-payload-json
               (car (ebp-store-list-work store nil 'leased)))))
      (let ((reclaimed (ebp-store-claim-next store "worker-b" 150 50)))
        (should-error
         (ebp-store-checkpoint store next "{\"stale\":true}" 151)
         :type 'ebp-store-stale-lease)
        (should (equal "{\"cursor\":1}"
                       (ebp-store-work-payload-json reclaimed)))))))

(ert-deftest ebp-sqlite-completion-is-atomic-and-erases-work-payload ()
  (ebp-store-test--with-store (store file)
    (ebp-store-test--admit
     store ebp-store-test-event-a nil 100 "{\"secretless\":\"input\"}")
    (let ((work (ebp-store-claim-next store "worker-a" 100 50)))
      (let ((ebp-sqlite--fault-function
             (lambda (point)
               (when (eq point 'after-work-delete)
                 (error "Injected completion failure")))))
        (should-error (ebp-store-complete store work 110)
                      :type 'ebp-store-error))
      (should (= 1 (length (ebp-store-list-work store nil 'leased))))
      (should (ebp-store-complete store work 111)))
    (should-not (ebp-store-list-work store))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-a))
    (should
     (= 111
        (caar
         (sqlite-select
          (ebp-sqlite-store-db store)
          "SELECT completed_at_ms FROM accepted_events
            WHERE pairing_id = ? AND event_id = ?"
          (list ebp-store-test-pair-a ebp-store-test-event-a)))))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should-not (ebp-store-list-work store))
    (should
     (eq 'duplicate
         (ebp-store-test--admit store ebp-store-test-event-a)))))

(ert-deftest ebp-sqlite-prunes-only-old-completed-receipts ()
  (ebp-store-test--with-store (store file)
    (ebp-store-test--admit store ebp-store-test-event-a nil 0)
    (let ((work (ebp-store-claim-next store "worker-a" 0 10)))
      (ebp-store-complete store work 1))
    (ebp-store-test--admit store ebp-store-test-event-b nil 0)
    (should-error
     (ebp-store-prune
      store ebp-store-minimum-retention-ms
      (1- ebp-store-minimum-retention-ms))
     :type 'wrong-type-argument)
    (should
     (= 1
        (ebp-store-prune
         store (1+ ebp-store-minimum-retention-ms)
         ebp-store-minimum-retention-ms)))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-b))
    (should (= 1 (length (ebp-store-list-work store))))))

(ert-deftest ebp-sqlite-admit-completed-records-receipt-without-work ()
  (ebp-store-test--with-store (store file)
    (should (eq 'admitted
                (ebp-store-admit-completed
                 store ebp-store-test-pair-a ebp-store-test-event-a 100)))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-a))
    (should-not (ebp-store-list-work store))
    (should
     (equal
      '((100 100))
      (sqlite-select
       (ebp-sqlite-store-db store)
       "SELECT accepted_at_ms, completed_at_ms FROM accepted_events
         WHERE pairing_id = ? AND event_id = ?"
       (list ebp-store-test-pair-a ebp-store-test-event-a))))
    ;; A redelivered id is a duplicate through either admission arm, and
    ;; neither arm may retroactively create work for a completed effect.
    (should (eq 'duplicate
                (ebp-store-admit-completed
                 store ebp-store-test-pair-a ebp-store-test-event-a 200)))
    (should (eq 'duplicate
                (ebp-store-test--admit
                 store ebp-store-test-event-a nil 200)))
    (should-not (ebp-store-list-work store))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-a))
    (should-not (ebp-store-list-work store))))

(ert-deftest ebp-sqlite-admit-completed-rolls-back-without-commit ()
  (ebp-store-test--with-store (store file)
    (cl-letf (((symbol-function 'sqlite-commit)
               (lambda (_db) nil)))
      (should-error
       (ebp-store-admit-completed
        store ebp-store-test-pair-a ebp-store-test-event-a 100)
       :type 'ebp-store-error))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (let ((ebp-sqlite--fault-function
           (lambda (point)
             (when (eq point 'after-completed-receipt)
               (error "Injected completed-receipt failure")))))
      (should-error
       (ebp-store-admit-completed
        store ebp-store-test-pair-a ebp-store-test-event-a 100)
       :type 'ebp-store-error))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))
    (ebp-store-close store)
    (setq store (ebp-sqlite-open file))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))))

(ert-deftest ebp-sqlite-admit-completed-is-prunable ()
  (ebp-store-test--with-store (store file)
    (should (eq 'admitted
                (ebp-store-admit-completed
                 store ebp-store-test-pair-a ebp-store-test-event-a 0)))
    (should (= 1 (ebp-store-prune
                  store (1+ ebp-store-minimum-retention-ms)
                  ebp-store-minimum-retention-ms)))
    (should-not (ebp-store-known-p
                 store ebp-store-test-pair-a ebp-store-test-event-a))))

(ert-deftest ebp-sqlite-admit-completed-validates-arguments ()
  (ebp-store-test--with-store (store file)
    (should-error
     (ebp-store-admit-completed store "nope" ebp-store-test-event-a 100)
     :type 'wrong-type-argument)
    (should-error
     (ebp-store-admit-completed store ebp-store-test-pair-a "nope" 100)
     :type 'wrong-type-argument)
    (should-error
     (ebp-store-admit-completed
      store ebp-store-test-pair-a ebp-store-test-event-a -1)
     :type 'wrong-type-argument)))

(ert-deftest ebp-sqlite-opens-zero-byte-file-as-new-store ()
  (skip-unless (and (fboundp 'sqlite-available-p) (sqlite-available-p)))
  ;; Every wire fixture hands the client a `make-temp-file' path: a
  ;; zero-byte file is an EMPTY database, not an unversioned stranger.
  (let ((file (make-temp-file "ebp-store-zero-byte-")))
    (unwind-protect
        (let ((store nil))
          (should (= 0 (file-attribute-size (file-attributes file))))
          (setq store (ebp-sqlite-open file))
          (should (ebp-sqlite-store-p store))
          (let ((db (ebp-sqlite-store-db store)))
            (should (= 2 (caar (sqlite-select db "PRAGMA user_version"))))
            (should (equal '("accepted_events" "action_work"
                             "pairing_partitions" "surface_floors")
                           (ebp-sqlite--user-tables db))))
          (ebp-store-close store))
      (dolist (f (list file (concat file "-wal") (concat file "-shm")))
        (when (file-exists-p f) (delete-file f))))))

(ert-deftest ebp-sqlite-migrates-legacy-receipts-in-place ()
  (ebp-store-test--with-legacy
      (file (list (cons ebp-store-test-event-a 1700000000.5)
                  (cons ebp-store-test-event-b 1600000000.0)))
    (let ((store (ebp-sqlite-open file ebp-store-test-pair-a)))
      (unwind-protect
          (let ((db (ebp-sqlite-store-db store)))
            (should (= 2 (caar (sqlite-select db "PRAGMA user_version"))))
            (should (equal '("accepted_events" "action_work"
                             "pairing_partitions" "surface_floors")
                           (ebp-sqlite--user-tables db)))
            (should (ebp-store-known-p
                     store ebp-store-test-pair-a ebp-store-test-event-a))
            (should (ebp-store-known-p
                     store ebp-store-test-pair-a ebp-store-test-event-b))
            ;; SPEC 14.4 scopes EventId uniqueness to the pairing.
            (should-not (ebp-store-known-p
                         store ebp-store-test-pair-b ebp-store-test-event-a))
            (should
             (equal
              '((1700000000500 1700000000500))
              (sqlite-select
               db
               "SELECT accepted_at_ms, completed_at_ms FROM accepted_events
                 WHERE pairing_id = ? AND event_id = ?"
               (list ebp-store-test-pair-a ebp-store-test-event-a))))
            (should-not (ebp-store-list-work store))
            (should (eq 'duplicate
                        (ebp-store-admit-completed
                         store ebp-store-test-pair-a
                         ebp-store-test-event-a 100))))
        (ebp-store-close store)))
    ;; The migrated file is an ordinary current-version store: no pairing
    ;; id needed.
    (let ((store (ebp-sqlite-open file)))
      (unwind-protect
          (should (ebp-store-known-p
                   store ebp-store-test-pair-a ebp-store-test-event-a))
        (ebp-store-close store)))))

(ert-deftest ebp-sqlite-refuses-legacy-receipts-without-pairing-id ()
  (ebp-store-test--with-legacy
      (file (list (cons ebp-store-test-event-a 1700000000.5)))
    (should-error (ebp-sqlite-open file) :type 'ebp-store-error)
    (should (= 0 (ebp-store-test--raw-version file)))
    (should (equal '("receipts") (ebp-store-test--raw-tables file)))
    (should (equal (list (list ebp-store-test-event-a 1700000000.5))
                   (ebp-store-test--raw-legacy-rows file)))))

(ert-deftest ebp-sqlite-legacy-migration-rolls-back-atomically ()
  (ebp-store-test--with-legacy
      (file (list (cons ebp-store-test-event-a 1700000000.5)))
    (let ((ebp-sqlite--fault-function
           (lambda (point)
             (when (eq point 'after-legacy-import)
               (error "Injected legacy import failure")))))
      (should-error (ebp-sqlite-open file ebp-store-test-pair-a)
                    :type 'ebp-store-error))
    (should (= 0 (ebp-store-test--raw-version file)))
    (should (equal '("receipts") (ebp-store-test--raw-tables file)))
    (should (equal (list (list ebp-store-test-event-a 1700000000.5))
                   (ebp-store-test--raw-legacy-rows file)))
    ;; Rollback restored the exact starting point, so a retry after the
    ;; cause is fixed migrates the same file.
    (let ((store (ebp-sqlite-open file ebp-store-test-pair-a)))
      (unwind-protect
          (progn
            (should (= 2 (caar (sqlite-select (ebp-sqlite-store-db store)
                                              "PRAGMA user_version"))))
            (should (ebp-store-known-p
                     store ebp-store-test-pair-a ebp-store-test-event-a)))
        (ebp-store-close store)))))

(ert-deftest ebp-sqlite-refuses-legacy-receipts-with-malformed-rows ()
  (ebp-store-test--with-legacy
      (file (list (cons ebp-store-test-event-a 1700000000.5)
                  (cons "BAD" 1600000000.0)))
    (should-error (ebp-sqlite-open file ebp-store-test-pair-a)
                  :type 'ebp-store-error)
    (should (= 0 (ebp-store-test--raw-version file)))
    (should (equal '("receipts") (ebp-store-test--raw-tables file))))
  (ebp-store-test--with-legacy
      (file (list (cons ebp-store-test-event-a 1700000000.5)
                  (cons ebp-store-test-event-b nil)))
    (should-error (ebp-sqlite-open file ebp-store-test-pair-a)
                  :type 'ebp-store-error)
    (should (= 0 (ebp-store-test--raw-version file)))
    (should (equal '("receipts") (ebp-store-test--raw-tables file))))
  ;; A NULL event id: `length(NULL)' is NULL, so the pre-check needs its
  ;; own IS NULL arm to name this corruption instead of leaving it to the
  ;; v1 column constraint's generic transaction failure.
  (ebp-store-test--with-legacy
      (file (list (cons ebp-store-test-event-a 1700000000.5)
                  (cons nil 1600000000.0)))
    ;; The pre-check's own diagnostic, not the v1 column constraint's
    ;; generic transaction failure: that is what the IS NULL arm buys.
    (should (equal "Legacy receipt store holds malformed rows"
                   (cadr (should-error
                          (ebp-sqlite-open file ebp-store-test-pair-a)
                          :type 'ebp-store-error))))
    (should (= 0 (ebp-store-test--raw-version file)))
    (should (equal '("receipts") (ebp-store-test--raw-tables file)))))

(ert-deftest ebp-sqlite-known-p-and-list-work-map-sqlite-errors ()
  "The contract says storage failures are `ebp-store-error', so the two
read-only methods — which have no transaction wrapper to convert for
them — must map a live handle's `sqlite-error' themselves, WITHOUT
invalidating a store that a failed query says nothing about."
  (ebp-store-test--with-store (store file)
    (ebp-store-test--admit store ebp-store-test-event-a)
    (cl-letf (((symbol-function 'sqlite-select)
               (lambda (&rest _)
                 (signal 'sqlite-error '("disk I/O error")))))
      (should-error
       (ebp-store-known-p
        store ebp-store-test-pair-a ebp-store-test-event-a)
       :type 'ebp-store-error)
      (should-error (ebp-store-list-work store)
                    :type 'ebp-store-error))
    ;; The handle survived: the store was never invalidated.
    (should-not (ebp-sqlite-store-closed-p store))
    (should (ebp-store-known-p
             store ebp-store-test-pair-a ebp-store-test-event-a))
    (should (= 1 (length (ebp-store-list-work store))))))

(ert-deftest ebp-sqlite-open-rejects-invalid-legacy-pairing-id ()
  (skip-unless (and (fboundp 'sqlite-available-p) (sqlite-available-p)))
  ;; Validated before any file I/O, so the path need not exist.
  (should-error
   (ebp-sqlite-open
    (expand-file-name "never-created.sqlite" temporary-file-directory)
    "nope")
   :type 'wrong-type-argument))

(ert-deftest ebp-sqlite-close-is-idempotent-and-fails-closed-afterward ()
  (ebp-store-test--with-store (store file)
    (should (ebp-store-close store))
    (should (ebp-store-close store))
    (should-error
     (ebp-store-known-p
      store ebp-store-test-pair-a ebp-store-test-event-a)
     :type 'ebp-store-unavailable)
    (should-error (ebp-store-list-work store)
                  :type 'ebp-store-unavailable)))

(provide 'ebp-store-test)
;;; ebp-store-test.el ends here

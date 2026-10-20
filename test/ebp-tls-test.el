;;; ebp-tls-test.el --- SPEC 5.4 network-tls conformance for ebp-tls.el -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:

;; The `network-tls' dialer: configuration vetoes, fingerprint spelling,
;; and the pinned handshake against a real TLS 1.3 listener
;; (test/ebp-tls-server.py, needs python3 and openssl).

;;; Code:

(require 'ert)
(require 'ebp)
(require 'ebp-tls)
(require 'ebp-test-common)

(defconst ebp-test--dir
  (file-name-directory (or load-file-name buffer-file-name default-directory))
  "This test file's directory, where the TLS listener fixture lives.")

(ert-deftest ebp-test-tls-connect-rejects-unpinned-dial ()
  "An unpinned network-tls dial is exactly the unverified connection SPEC
5.4 forbids, so the pin is demanded up front, before any client exists."
  (should-error (ebp-connect "127.0.0.1" 8766 :transport 'network-tls)
                :type 'error)
  (should-error (ebp-connect "127.0.0.1" 8766 :transport 'network-tls
                             :certificate-fingerprint "not-a-digest")
                :type 'error))

(ert-deftest ebp-test-fingerprint-normalization ()
  "SPEC 5.4's display form and GnuTLS's spelling name the same digest."
  (let ((hex (concat (make-string 32 ?a) (make-string 32 ?0))))
    (should (equal (ebp-tls--normalize-fingerprint hex) hex))
    (should (equal (ebp-tls--normalize-fingerprint (upcase hex)) hex))
    (should (equal (ebp-tls--normalize-fingerprint
                    (concat "sha256:"
                            (mapconcat #'identity (seq-partition hex 2) ":")))
                   hex))
    (should-not (ebp-tls--normalize-fingerprint (substring hex 1)))
    (should-not (ebp-tls--normalize-fingerprint (concat hex "0")))
    (should-not (ebp-tls--normalize-fingerprint "sha1:aa"))
    (should-not (ebp-tls--normalize-fingerprint nil))))

(defun ebp-test--tls-fixture ()
  "A throwaway certificate: (DIR CERT KEY DIGEST), DIGEST the 64-hex SPKI
SHA-256 exactly as SPEC 5.4 has the Companion display it, computed with
openssl independently of GnuTLS so the two implementations are compared."
  (let* ((dir (make-temp-file "ebp-tls" t))
         (cert (expand-file-name "cert.pem" dir))
         (key (expand-file-name "key.pem" dir)))
    (unless (zerop (call-process "openssl" nil nil nil "req" "-x509"
                                 "-newkey" "ec" "-pkeyopt"
                                 "ec_paramgen_curve:prime256v1" "-nodes"
                                 "-keyout" key "-out" cert
                                 "-subj" "/CN=ebp-test" "-days" "2"))
      (error "openssl req failed"))
    (let ((digest
           (string-trim
            (shell-command-to-string
             (format "openssl x509 -in %s -pubkey -noout \
| openssl pkey -pubin -outform DER | openssl dgst -sha256 | sed 's/.* //'"
                     (shell-quote-argument cert))))))
      (unless (string-match-p "\\`[0-9a-f]\\{64\\}\\'" digest)
        (error "could not compute the SPKI digest: %S" digest))
      (list dir cert key digest))))

(defun ebp-test--start-tls-server (cert key naccept)
  "Run test/ebp-tls-server.py for NACCEPT connections; return (PROC PORT BUF)."
  (let* ((port (ebp-test--free-port))
         (buf (generate-new-buffer " *ebp-tls-server*"))
         (proc (start-process "ebp-tls-server" buf "python3"
                              (expand-file-name "ebp-tls-server.py" ebp-test--dir)
                              (number-to-string port) cert key
                              (number-to-string naccept))))
    (set-process-query-on-exit-flag proc nil)
    (unless (ebp-test--wait (lambda () (ebp-test--buffer-has buf "LISTENING")) 10)
      (error "TLS fixture did not start: %s"
             (with-current-buffer buf (buffer-string))))
    (list proc port buf)))

(ert-deftest ebp-test-transport-network-tls-pin-gates-the-hello ()
  "SPEC 5.4: the pin is verified BEFORE `session.hello'.  A mismatch closes
the transport with nothing written and is terminal; a match — given in
GnuTLS's spelling — sends the hello inside a TLS 1.3 stream.  The digest
the pin is checked against was computed by openssl, so this also witnesses
that GnuTLS's `:public-key-id-sha256' is the SPKI SHA-256 the spec names."
  (skip-unless (and (gnutls-available-p)
                    (executable-find "openssl") (executable-find "python3")))
  (pcase-let* ((`(,dir ,cert ,key ,digest) (ebp-test--tls-fixture))
               (`(,server ,port ,buf) (ebp-test--start-tls-server cert key 2))
               ;; The pin is the whole verification: a hardened init.el
               ;; (`gnutls-verify-error' t) must not make the self-signed
               ;; per-pairing certificate fail CA validation before the pin
               ;; is ever compared.
               (gnutls-verify-error t))
    (unwind-protect
        (progn
          ;; 1. Wrong pin: refused, silent, terminal.
          (let ((err (should-error
                      (apply #'ebp-connect "127.0.0.1" port
                             (ebp-test--kat-config
                              :transport 'network-tls
                              :certificate-fingerprint
                              (concat (make-string 63 ?0) "1")
                              :reconnect-initial-delay 0.05
                              :reconnect-max-delay 0.1))
                      :type 'ebp-transport-refused)))
            (should (eq (cadr err) 'certificate-mismatch))
            ;; The observed digest rides the signal so a user can compare it
            ;; with what the Companion displays.
            (should (equal (nth 4 err) digest)))
          (should (ebp-test--wait
                   (lambda () (ebp-test--buffer-has buf "RECEIVED b''")) 10))
          (should-not (ebp-test--buffer-has buf "Content-Length"))
          ;; 2. Right pin, GnuTLS spelling: the hello goes out inside TLS 1.3,
          ;; synchronously, before anything else can happen.
          (let ((client (apply #'ebp-connect "127.0.0.1" port
                               (ebp-test--kat-config
                                :transport 'network-tls
                                :certificate-fingerprint
                                (concat "sha256:"
                                        (mapconcat #'identity
                                                   (seq-partition digest 2)
                                                   ":"))))))
            (unwind-protect
                (progn
                  (should (eq (ebp-client-state client) 'awaiting-nonce))
                  (should (ebp-test--wait
                           (lambda () (ebp-test--buffer-has buf "session.hello"))
                           10))
                  (should (= 2 (ebp-test--buffer-count buf "HANDSHAKE-OK TLSv1.3"))))
              (ignore-errors (ebp-client-close client 'test-done)))))
      (ignore-errors (delete-process server))
      (ignore-errors (kill-buffer buf))
      (delete-directory dir t))))

(provide 'ebp-tls-test)
;;; ebp-tls-test.el ends here

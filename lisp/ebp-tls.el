;;; ebp-tls.el --- EBP network-tls dialer (SPEC 5.4), GnuTLS-pinned -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; The SPEC 5.4 `network-tls' transport profile: Emacs dials HOST:PORT
;; inside TLS 1.3 or later and authenticates the Companion by PINNING its
;; public key — the 64-hex SHA-256 of the certificate's SubjectPublicKeyInfo
;; shown at pairing — rather than by any certificate authority.  Built on
;; the GnuTLS support compiled into Emacs; nothing here is loaded by
;; `ebp.el' itself, which knows only the mandatory loopback dialers.
;;
;; The profile plugs into the `ebp.el' transport registry like the binder
;; profiles do: `:check' refuses an unpinned configuration before any
;; client exists, `:open' performs the pinned dial, and `:secrets' names
;; the config key that pairing revocation erases.
;;
;; Every function cites the section it implements.  Behavior with no
;; section is a bug in this file or an amendment owed to the EBP spec.

;;; Code:

(require 'cl-lib)
(require 'gnutls)
(require 'ebp)

;; A C primitive that exists only in a GnuTLS-enabled build, declared so a
;; build without one still byte-compiles this file clean.  Its only caller,
;; `ebp-tls--open-socket', runs after `ebp-tls--check' has confirmed
;; `gnutls-available-p' — which every build defines, returning nil without
;; GnuTLS, so it needs no declaration or `fboundp' guard.
(declare-function gnutls-peer-status "gnutls.c" (proc))

(defun ebp-tls--normalize-fingerprint (value)
  "VALUE as 64 lowercase hex characters, or nil when it is not a digest.
Accepts the SPEC 5.4 display form (bare hex, any case) and GnuTLS's
\"sha256:aa:bb:...\" rendering, which is how `gnutls-peer-status' reports
the same digest.  Never signals."
  (when (stringp value)
    (let* ((bare (if (string-prefix-p "sha256:" value)
                     (substring value (length "sha256:"))
                   value))
           (hex (downcase (replace-regexp-in-string ":" "" bare t t))))
      (and (string-match-p "\\`[0-9a-f]\\{64\\}\\'" hex) hex))))

(defun ebp-tls--check (_host _port config)
  "SPEC 5.4: refuse the configuration unless a pinned dial is possible.
Run by `ebp-connect' before any client, store, or socket exists, so an
unpinned `network-tls' dial — exactly the unverified connection SPEC 5.4
forbids — can never be attempted."
  (unless (gnutls-available-p)
    (error "ebp: network-tls needs an Emacs built with GnuTLS"))
  (unless (ebp-tls--normalize-fingerprint
           (plist-get config :certificate-fingerprint))
    (error "ebp: network-tls needs :certificate-fingerprint, the 64-hex \
SHA-256 of the Companion's SubjectPublicKeyInfo shown at pairing (SPEC 5.4)")))

(defun ebp-tls--open-socket (host port fingerprint)
  "SPEC 5.4: dial HOST:PORT inside TLS and pin the Companion's public key.
A blocking `make-network-process' completes the TLS handshake before it
returns, so the peer certificate is known here, before any frame exists.
Certificate-authority and hostname checks are deliberately off
\(:verify-error nil): the pin IS the verification, and a self-signed
per-pairing certificate could pass no other.  The digest GnuTLS reports
as `:public-key-id-sha256' is the SHA-256 of the DER-encoded
SubjectPublicKeyInfo — the bytes `openssl x509 -pubkey' hashes and the
bytes a JVM's `PublicKey.getEncoded' yields — so both ends compute the
same 64 hex characters from the same certificate.  On a mismatch, or a
negotiated protocol below TLS 1.3, the socket is closed with nothing
written and `ebp-transport-refused' is signaled — terminal for redial.
FINGERPRINT is already normalized by `ebp-tls--normalize-fingerprint'.

`gnutls-verify-error' is bound to nil for the parameter build because
`gnutls-boot-parameters' treats an explicit :verify-error nil as \"fall
back to the user option\": under a hardened init.el (`gnutls-verify-error'
t) the self-signed certificate would fail CA validation inside the C
handshake, the dial would signal a plain `error', and `ebp-connect' would
redial forever as `transport-unavailable' instead of ever reaching the pin."
  (let ((proc (make-network-process
               :name "ebp" :host host :service port :noquery t
               :coding 'utf-8-unix
               :tls-parameters
               (cons 'gnutls-x509pki
                     (let ((gnutls-verify-error nil))
                       (gnutls-boot-parameters
                        :type 'gnutls-x509pki :hostname host
                        :verify-error nil :complete-negotiation t))))))
    (condition-case err
        (let* ((status (and (process-live-p proc) (gnutls-peer-status proc)))
               (protocol (plist-get status :protocol))
               (peer (ebp-tls--normalize-fingerprint
                      (plist-get (plist-get status :certificate)
                                 :public-key-id-sha256))))
          (unless status
            (error "TLS handshake did not complete"))
          (unless (and (stringp protocol)
                       (string-match "\\`TLS\\([0-9]+\\)\\.\\([0-9]+\\)\\'" protocol)
                       (or (> (string-to-number (match-string 1 protocol)) 1)
                           (>= (string-to-number (match-string 2 protocol)) 3)))
            (signal 'ebp-transport-refused
                    (list 'tls-version-too-low host port protocol)))
          (unless (and peer (string= peer fingerprint))
            (signal 'ebp-transport-refused
                    (list 'certificate-mismatch host port peer)))
          proc)
      (error
       (ignore-errors (delete-process proc))
       (signal (car err) (cdr err))))))

(defun ebp-tls--open (client)
  "SPEC 5.4: the registry `:open' — CLIENT's pinned dial."
  (ebp-tls--open-socket
   (ebp-client-host client)
   (ebp-client-port client)
   (ebp-tls--normalize-fingerprint
    (plist-get (ebp-client-config client) :certificate-fingerprint))))

(ebp-register-transport 'network-tls
                        :role 'dialer
                        :check #'ebp-tls--check
                        :open #'ebp-tls--open
                        :secrets '(:certificate-fingerprint))

(provide 'ebp-tls)
;;; ebp-tls.el ends here

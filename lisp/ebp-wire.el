;;; ebp-wire.el --- EBP 3 wire layer: JSON, framing, envelope, proofs -*- lexical-binding: t; -*-

;; SPDX-License-Identifier: GPL-3.0-or-later
;; Package-Requires: ((emacs "30.1"))

;;; Commentary:

;; The pure wire layer of the Emacs Bridge Protocol, written against the
;; neighboring ebp/SPEC.md (protocol 3, document 3.1.0-draft): the JSON
;; data-model receiver rules (SPEC 4.1), the general identifier grammar
;; (SPEC 4.4), the fixed limits (SPEC 4.5), Content-Length framing in
;; both directions (SPEC 6), the JSON-RPC envelope conventions (SPEC 7),
;; pairing-token decoding and HMAC proof construction (SPEC 9), the
;; handshake message builders (SPEC 9.2), and the client session state
;; machine (SPEC 10.1) as a pure step function.
;;
;; Nothing here holds state beyond a decoder's byte buffer, and nothing
;; here knows about a client, a socket, a timer, or jsonrpc.el: every
;; function maps octets, strings, and plists to octets, strings, plists,
;; or a signal.  That is what makes this file testable with nothing but
;; literal strings, and what `ebp.el' (the client engine), `ebp-websocket.el'
;; and `ebp-unix.el' (the binder profiles) build on.
;;
;; Every function cites the section it implements.  Behavior with no
;; section is a bug in this file or an amendment owed to the EBP spec.

;;; Code:

(require 'cl-lib)

;;;; Errors

;; SPEC 6.2: header-section failures force connection closure.
(define-error 'ebp-frame-close "EBP framing error requiring connection close")
;; SPEC 6.2: EOF in the middle of a frame terminates the session.
(define-error 'ebp-frame-incomplete "EBP frame incomplete at end of stream")
;; SPEC 6.2: invalid UTF-8 or invalid JSON after a complete body.
(define-error 'ebp-parse-error "EBP body is not valid UTF-8 JSON")
;; SPEC 6.2 / 4.1: top-level non-object, batch array, duplicate members.
(define-error 'ebp-invalid-request "EBP body is not a valid single message object")

;;;; Limits (SPEC 4.5, fixed)

(defconst ebp-max-header-octets 8192
  "SPEC 4.5: framing header section limit, including the final CRLF pair.")
(defconst ebp-max-body-octets 4194304
  "SPEC 4.5: JSON body limit in octets.")
(defconst ebp-max-request-id-octets 64
  "SPEC 7.2: request IDs are identifiers of at most 64 ASCII octets.")

;;;; JSON (SPEC 4.1)

(defun ebp--json-parse (text)
  "Parse TEXT as JSON, returning alists/lists.  Signals `ebp-parse-error'."
  (condition-case nil
      (json-parse-string text :object-type 'alist :array-type 'list
                         :null-object :null :false-object :false)
    (error (signal 'ebp-parse-error (list text)))))

(defconst ebp-max-safe-integer 9007199254740991
  "SPEC 4.2: the inclusive EBP integer bound (2^53 - 1).")

(defconst ebp-max-json-depth 64
  "SPEC 4.5: a JSON body nests at most 64 containers.")

(defun ebp--exceeds-depth-p (text)
  "Non-nil if TEXT nests JSON containers past `ebp-max-json-depth'.
One linear scan (string contents and escapes skipped) so a hostile body
is refused before the recursive parser can exhaust the stack (SPEC 4.5)."
  (let ((depth 0) (in-string nil) (escaped nil)
        (i 0) (n (length text)) (over nil))
    (while (and (< i n) (not over))
      (let ((c (aref text i)))
        (cond
         (in-string
          (cond (escaped (setq escaped nil))
                ((eq c ?\\) (setq escaped t))
                ((eq c ?\") (setq in-string nil))))
         ((eq c ?\") (setq in-string t))
         ((or (eq c ?{) (eq c ?\[))
          (setq depth (1+ depth))
          (when (> depth ebp-max-json-depth) (setq over t)))
         ((or (eq c ?}) (eq c ?\])) (setq depth (1- depth)))))
      (setq i (1+ i)))
    over))

(defun ebp--check-numbers (value)
  "Signal `ebp-parse-error' if VALUE carries a number SPEC 4.2 forbids.
Amendment #99: an integral literal outside the safe range, or a literal
that overflowed to an infinity, cannot be carried by this data model, so
it is refused during decoding on the same terms as the 4.5 depth limit.
Emacs reads oversized integers as bignums and overflowing literals as
infinities, so both survive `json-parse-string' silently otherwise.  A
literal that underflowed to zero decodes AS zero and is accepted.
VALUE is walked structurally: alist conses, array lists, plists, and
vectors alike, so both decoded shapes (the reference alist codec and the
jsonrpc plist codec of `ebp--parse-message') are covered."
  (cond
   ((vectorp value) (mapc #'ebp--check-numbers value))
   ((integerp value)
    (when (or (> value ebp-max-safe-integer)
              (< value (- ebp-max-safe-integer)))
      (signal 'ebp-parse-error (list "integer out of range"))))
   ((floatp value)
    (when (or (isnan value) (= value 1.0e+INF) (= value -1.0e+INF))
      (signal 'ebp-parse-error (list "number out of range"))))
   ((consp value)
    ;; Walk the spine iteratively: an object or array must cost nesting
    ;; depth, never recursion depth per member — a 400-member object
    ;; recursing down its cdr chain exceeds `max-lisp-eval-depth'.  A
    ;; dotted alist pair ends in a non-list cdr, checked last.
    (let ((cell value))
      (while (consp cell)
        (ebp--check-numbers (car cell))
        (setq cell (cdr cell)))
      (ebp--check-numbers cell)))))

(defun ebp--json-serialize (value)
  "Serialize VALUE (alists/plists per `json-serialize') to a JSON string."
  (json-serialize value :null-object :null :false-object :false))

(defconst ebp--empty-object (make-hash-table :test #'equal :size 1)
  "Serializes as {} — SPEC 7.1 requires object params, never null.")

(defun ebp--string-token-end (text start)
  "Index of the closing quote of the JSON string starting at START in TEXT."
  (let ((i (1+ start)) (n (length text)))
    (while (and (< i n) (not (eq (aref text i) ?\")))
      (setq i (if (eq (aref text i) ?\\) (+ i 2) (1+ i))))
    (when (>= i n) (signal 'ebp-parse-error (list "unterminated string")))
    i))

(defun ebp--duplicate-members-p (text)
  "Non-nil when valid-JSON TEXT contains an object with duplicate member names.
SPEC 4.1: a receiver MUST reject duplicate member names.  Key comparison is
semantic (after escape decoding), so \"a\" and \"\\u0061\" collide.
TEXT must already have parsed successfully."
  (let ((i 0) (n (length text)) (stack '()))
    (catch 'dup
      (while (< i n)
        (let ((c (aref text i)))
          (cond
           ((memq c '(?\s ?\t ?\n ?\r)) (cl-incf i))
           ((eq c ?{)
            (push (cons (make-hash-table :test #'equal) 'key) stack)
            (cl-incf i))
           ((eq c ?\[) (push 'arr stack) (cl-incf i))
           ((memq c '(?} ?\])) (pop stack) (cl-incf i))
           ((eq c ?\")
            (let* ((end (ebp--string-token-end text i))
                   (raw (substring text i (1+ end)))
                   (top (car stack)))
              (setq i (1+ end))
              (when (and (consp top) (eq (cdr top) 'key))
                (let ((key (ebp--json-parse raw)))
                  (when (gethash key (car top)) (throw 'dup t))
                  (puthash key t (car top))
                  (setcdr top 'colon)))))
           ((eq c ?:)
            (let ((top (car stack)))
              (when (and (consp top) (eq (cdr top) 'colon))
                (setcdr top 'value)))
            (cl-incf i))
           ((eq c ?,)
            (let ((top (car stack)))
              (when (consp top) (setcdr top 'key)))
            (cl-incf i))
           (t ;; number / true / false / null
            (while (and (< i n)
                        (not (memq (aref text i)
                                   '(?, ?} ?\] ?\s ?\t ?\n ?\r))))
              (cl-incf i))))))
      nil)))

(defun ebp--decode-utf-8 (bytes)
  "Decode unibyte BYTES as strict UTF-8 or signal `ebp-parse-error'.
SPEC 4.1: a receiver MUST reject a body containing invalid UTF-8."
  (let ((decoded (decode-coding-string bytes 'utf-8)))
    ;; Emacs maps undecodable bytes to raw-byte characters above #x10FFFF.
    (if (cl-find-if (lambda (ch) (> ch #x10FFFF)) decoded)
        (signal 'ebp-parse-error (list "invalid UTF-8"))
      decoded)))

;;;; Framing decoder (SPEC 6.2)

(cl-defstruct (ebp-decoder (:constructor ebp-make-decoder))
  (buffer "" :documentation "Pending unibyte bytes."))

(defconst ebp--content-length-re
  "\\`\\(?:0\\|[1-9][0-9]*\\)\\'"
  "SPEC 6.1/6.2: unsigned decimal, no leading zeroes except the value 0.
Anchored to the whole STRING (\\=\\` and \\=\\'), not to lines: Emacs `^' and
`$' match at line boundaries, so the line-anchored form accepted a bare
LF inside the value and a value like \"2\\nX: 1\" passed as 2.  The header
section is split on CRLF only, so such a value is reachable on the wire.")

(defun ebp--parse-header (head)
  "Parse the unibyte header section HEAD (without the final CRLFCRLF).
Return the declared body length or signal `ebp-frame-close' (SPEC 6.2)."
  (let ((lengths '()))
    (dolist (line (split-string head "\r\n" nil))
      (when (string-empty-p line)
        (signal 'ebp-frame-close (list "malformed header line")))
      (let ((colon (string-search ":" line)))
        (unless colon
          (signal 'ebp-frame-close (list "malformed header line")))
        (let ((name (substring line 0 colon))
              ;; Receiver MAY accept optional horizontal whitespace.
              (value (string-trim (substring line (1+ colon)) "[ \t]+" "[ \t]+")))
          (when (string-equal-ignore-case name "Content-Length")
            (unless (string-match-p ebp--content-length-re value)
              (signal 'ebp-frame-close (list "invalid Content-Length value")))
            (push (string-to-number value) lengths)))))
    (unless (= (length lengths) 1)
      (signal 'ebp-frame-close
              (list (if lengths "duplicate Content-Length" "missing Content-Length"))))
    (let ((len (car lengths)))
      (when (> len ebp-max-body-octets)
        ;; SPEC 6.2: close immediately on an oversized declaration.
        (signal 'ebp-frame-close (list "oversized body declaration")))
      len)))

(defun ebp--parse-body (bytes)
  "Decode one complete frame body BYTES into a message object.
SPEC 6.2 + 4.1: strict UTF-8, valid JSON, single top-level object,
no duplicate member names."
  (let ((text (ebp--decode-utf-8 bytes)))
    ;; SPEC 4.5/23.5: refuse an over-deep body before the recursive parser
    ;; can exhaust the stack — enforcement precedes expensive decoding.
    (when (ebp--exceeds-depth-p text)
      (signal 'ebp-parse-error (list "nesting depth exceeds 64")))
    (let ((value (ebp--json-parse text)))
      (unless (and (listp value) (or (null value) (consp (car value))))
        ;; Top-level arrays (batches) and scalars are prohibited.
        (signal 'ebp-invalid-request (list "top-level value is not an object")))
      ;; `nil' parses ambiguously ({} and [] both -> nil); {} is a valid
      ;; (if useless) message object, [] is a prohibited batch.  Disambiguate
      ;; on the first non-whitespace character.
      (when (and (null value)
                 (eq (aref (string-trim-left text) 0) ?\[))
        (signal 'ebp-invalid-request (list "batch arrays are prohibited")))
      (when (ebp--duplicate-members-p text)
        (signal 'ebp-invalid-request (list "duplicate member names")))
      ;; SPEC 4.2 (amendment #99): numbers this data model cannot carry.
      (ebp--check-numbers value)
      value)))

(defun ebp--parse-message (bytes)
  "Decode one complete message body BYTES into a jsonrpc-style keyword plist.
The SPEC 4.1/6.2 receiver rules `ebp--parse-body' applies for the
reference alist codec, applied to the live shape `jsonrpc-connection-receive'
dispatches: strict UTF-8, the 4.5 depth cap before parsing, a single
top-level object, no duplicate member names, no numbers the data model
cannot carry.  Arrays decode as vectors, `null' as nil, and `false' as
`:json-false', exactly as jsonrpc.el's own decoder does.  Signals
`ebp-parse-error' or `ebp-invalid-request'.  SPEC 23.5: the CALLER binds
a throwaway `obarray' around this call and runs `ebp--remap-decoded' on
the result outside it, as the process-filter wrapper in
`ebp-client--open-dialer-transport' does for jsonrpc.el's parse."
  (let ((text (ebp--decode-utf-8 bytes)))
    (when (ebp--exceeds-depth-p text)
      (signal 'ebp-parse-error (list "nesting depth exceeds 64")))
    (let ((value (condition-case nil
                     (json-parse-string text :object-type 'plist
                                        :array-type 'array
                                        :null-object nil
                                        :false-object :json-false)
                   (error (signal 'ebp-parse-error (list "invalid JSON"))))))
      ;; {} and null both decode to nil; [] is a vector.  The first
      ;; non-whitespace character settles what the text actually was.
      (unless (and (listp value)
                   (let ((lead (string-trim-left text)))
                     (and (> (length lead) 0) (eq (aref lead 0) ?{))))
        (signal 'ebp-invalid-request (list "top-level value is not an object")))
      (when (ebp--duplicate-members-p text)
        (signal 'ebp-invalid-request (list "duplicate member names")))
      (ebp--check-numbers value)
      value)))

(defun ebp--decoder-next (decoder)
  "Split the next complete frame off DECODER; return its unibyte body or nil.
The SPEC 6.2 framing half of the receiver: the header-section bound, the
`ebp--parse-header' close rules, and partial-frame retention across reads.
Signals `ebp-frame-close'.  Nil means no complete frame is buffered."
  (let* ((buf (ebp-decoder-buffer decoder))
         (term (string-search "\r\n\r\n" buf)))
    (cond
     ((null term)
      ;; SPEC 6.2: the header section may not exceed 8,192 octets.
      (when (> (length buf) ebp-max-header-octets)
        (signal 'ebp-frame-close (list "header section too large")))
      nil)
     ((> (+ term 4) ebp-max-header-octets)
      (signal 'ebp-frame-close (list "header section too large")))
     (t
      (let* ((len (ebp--parse-header (substring buf 0 term)))
             (body-start (+ term 4))
             (body-end (+ body-start len)))
        (if (< (length buf) body-end)
            nil                     ; retain partial data across reads
          (setf (ebp-decoder-buffer decoder) (substring buf body-end))
          (substring buf body-start body-end)))))))

(defun ebp-decoder-feed (decoder bytes)
  "Feed unibyte BYTES into DECODER; return the list of complete messages.
Implements the SPEC 6.2 receiver.  Signals `ebp-frame-close',
`ebp-parse-error', or `ebp-invalid-request' on the conditions the spec
assigns to each."
  (setf (ebp-decoder-buffer decoder)
        (concat (ebp-decoder-buffer decoder) bytes))
  (let ((messages '()) body)
    (while (setq body (ebp--decoder-next decoder))
      (push (ebp--parse-body body) messages))
    (nreverse messages)))

(defun ebp-decoder-finish (decoder)
  "Declare end of stream.  SPEC 6.2: EOF mid-frame terminates the session."
  (unless (string-empty-p (ebp-decoder-buffer decoder))
    (signal 'ebp-frame-incomplete
            (list (length (ebp-decoder-buffer decoder))))))

;;;; Framing encoder (SPEC 6.1)

(defun ebp-encode-frame (json-text)
  "Wrap JSON-TEXT in exact SPEC 6.1 framing; return unibyte bytes.
The length is computed after UTF-8 encoding, never from characters."
  (let ((body (encode-coding-string json-text 'utf-8)))
    (when (> (length body) ebp-max-body-octets)
      (signal 'ebp-frame-close (list "body exceeds max_frame_bytes")))
    (concat (format "Content-Length: %d\r\n\r\n" (length body)) body)))

;;;; Envelope (SPEC 7)

(defun ebp-valid-request-id-p (id)
  "SPEC 7.2: a string identifier of at most 64 ASCII octets (never
empty), or a safe integer.  Amendments #34/#80: jsonrpc.el's sequential
integer ids conform without adaptation; `null' and fractional numbers
do not."
  (or (and (integerp id)
           (<= (- ebp-max-safe-integer) id ebp-max-safe-integer))
      (and (stringp id)
           (<= 1 (length id) ebp-max-request-id-octets)
           (string-match-p "\\`[A-Za-z0-9][A-Za-z0-9._:/-]*\\'" id))))

(defun ebp-request (id method params)
  "Build a request plist (SPEC 7.1).  PARAMS must be a JSON object value."
  (unless (ebp-valid-request-id-p id) (error "Invalid request id: %S" id))
  `(:jsonrpc "2.0" :id ,id :method ,method :params ,params))

(defun ebp-notification (method params)
  "Build a notification plist (SPEC 7.1)."
  `(:jsonrpc "2.0" :method ,method :params ,params))

(defun ebp-result-response (id result)
  "Build a success response (SPEC 7.1).  Empty results are {}, never null."
  `(:jsonrpc "2.0" :id ,id :result ,result))

(defun ebp-error-response (id code message &optional data)
  "Build an error response carrying the SPEC 8 shape."
  `(:jsonrpc "2.0" :id ,id
    :error (:code ,code :message ,message
            ,@(when data (list :data data)))))

(defun ebp-message-class (msg)
  "Classify parsed alist MSG per SPEC 7.1.
Returns one of `request', `notification', `response', or nil for a
structurally invalid message."
  (let ((jsonrpc (alist-get 'jsonrpc msg))
        (method (alist-get 'method msg))
        (has-id (assq 'id msg))
        (has-result (assq 'result msg))
        (has-error (assq 'error msg)))
    (cond
     ((not (equal jsonrpc "2.0")) nil)
     ((and method has-id (not has-result) (not has-error)) 'request)
     ((and method (not has-id) (not has-result) (not has-error)) 'notification)
     ((and (not method) has-id (xor has-result has-error)) 'response)
     (t nil))))

(defconst ebp--envelope-members '(:jsonrpc :id :method :params :result :error)
  "SPEC 7.1: the members a message object may carry at the top level.")

(defun ebp--identifier-p (value)
  "Non-nil when VALUE obeys the general EBP identifier grammar (§4.4)."
  (and (stringp value)
       (<= 1 (length value) 128)
       (string-match-p "\\`[A-Za-z0-9][A-Za-z0-9._:/-]*\\'" value)))

(defun ebp--validate-message-plist (msg)
  "Check keyword plist MSG against SPEC 7.1 or signal `ebp-invalid-request'.
The signal data is (REASON ID): ID is MSG's request id when it carries a
valid one, else nil, so a responder can answer an invalid request with
its id where one exists and with null otherwise.  Runs AFTER
`ebp--remap-decoded', since the checks compare against source-literal
keywords.  An unknown top-level member is refused rather than ignored
because `jsonrpc-connection-receive' destructures the envelope strictly
and would otherwise fail inside the delivery timer, leaving a request
unanswered — the unbounded stall SPEC 6.2 forbids."
  (let* ((has-id (plist-member msg :id))
         (id (plist-get msg :id))
         (valid-id (and has-id (ebp-valid-request-id-p id) id))
         (fail (lambda (reason)
                 (signal 'ebp-invalid-request (list reason valid-id)))))
    (unless (equal (plist-get msg :jsonrpc) "2.0")
      (funcall fail "jsonrpc member is not \"2.0\""))
    (cl-loop for (k _v) on msg by #'cddr
             unless (memq k ebp--envelope-members)
             do (funcall fail "unknown envelope member"))
    (let ((has-method (plist-member msg :method))
          (method (plist-get msg :method))
          (has-result (plist-member msg :result))
          (has-error (plist-member msg :error)))
      (when (and has-method
                 (not (and (stringp method) (ebp--identifier-p method))))
        (funcall fail "method is not an identifier"))
      (when (and has-id (not valid-id))
        (funcall fail "id is not a valid request id"))
      (when (plist-member msg :params)
        (let ((params (plist-get msg :params)))
          (unless (or (null params)
                      (and (consp params) (symbolp (car params))))
            (funcall fail "params is not an object"))))
      (unless (or (and has-method has-id (not has-result) (not has-error))
                  (and has-method (not has-id) (not has-result) (not has-error))
                  (and (not has-method) has-id (xor has-result has-error)))
        (funcall fail "not a request, notification, or response"))
      msg)))

;;;; Pairing and proofs (SPEC 9)

(defun ebp--hmac-sha256 (key message)
  "HMAC-SHA256 (RFC 2104) of unibyte MESSAGE with unibyte KEY, binary output."
  (let* ((block 64)
         (key (if (> (length key) block)
                  (secure-hash 'sha256 key nil nil t)
                key))
         (key (concat key (make-string (- block (length key)) 0)))
         (ipad (apply #'unibyte-string
                      (mapcar (lambda (b) (logxor b #x36)) key)))
         (opad (apply #'unibyte-string
                      (mapcar (lambda (b) (logxor b #x5c)) key))))
    (secure-hash 'sha256
                 (concat opad (secure-hash 'sha256 (concat ipad message)
                                           nil nil t))
                 nil nil t)))

(defun ebp--hex (bytes)
  "Lowercase hexadecimal of unibyte BYTES."
  (mapconcat (lambda (b) (format "%02x" b)) bytes ""))

(defun ebp-decode-pairing-token (display)
  "Decode the 22-character base64url token DISPLAY to 16 raw octets.
SPEC 9.1: RFC 4648 base64url with padding omitted; both endpoints MUST
use the decoded raw octets as the HMAC key."
  (unless (and (stringp display) (= (length display) 22))
    (error "Pairing token must be 22 base64url characters"))
  (let ((raw (base64-decode-string (concat display "==") t)))
    (unless (= (length raw) 16)
      (error "Pairing token did not decode to 16 octets"))
    raw))

(defun ebp-valid-nonce-p (s)
  "SPEC 4.4/9.2: exactly 32 lowercase hexadecimal characters."
  (and (stringp s) (string-match-p "\\`[0-9a-f]\\{32\\}\\'" s)))

(defun ebp-valid-proof-p (s)
  "SPEC 4.4: exactly 64 lowercase hexadecimal characters."
  (and (stringp s) (string-match-p "\\`[0-9a-f]\\{64\\}\\'" s)))

(defun ebp-generate-nonce ()
  "Fresh 32-hex nonce from the operating system CSPRNG (SPEC 9.2)."
  (with-temp-buffer
    (set-buffer-multibyte nil)
    (let ((coding-system-for-read 'binary))
      ;; /dev/urandom is not seekable, so positioned reads are unusable;
      ;; take exactly 16 octets through a pipe instead.
      (call-process "head" "/dev/urandom" t nil "-c" "16"))
    (unless (= (buffer-size) 16)
      (error "CSPRNG read returned %d octets" (buffer-size)))
    (ebp--hex (buffer-string))))

(defun ebp-client-proof (token pairing-id client-nonce server-nonce)
  "SPEC 9.3 client proof over the exact ASCII concatenation."
  (ebp--hex (ebp--hmac-sha256
             token
             (format "EBP/3 client:%s:%s:%s"
                     pairing-id client-nonce server-nonce))))

(defun ebp-server-proof (token pairing-id client-nonce server-nonce)
  "SPEC 9.3 companion proof; note the swapped nonce order."
  (ebp--hex (ebp--hmac-sha256
             token
             (format "EBP/3 companion:%s:%s:%s"
                     pairing-id server-nonce client-nonce))))

(defun ebp--constant-time-equal (a b)
  "Compare strings A and B without early exit on the first difference."
  (and (stringp a) (stringp b)
       (= (length a) (length b))
       (let ((diff 0))
         (dotimes (i (length a))
           (setq diff (logior diff (logxor (aref a i) (aref b i)))))
         (zerop diff))))

(defun ebp-verify-server-proof (proof token pairing-id client-nonce server-nonce)
  "Verify a welcome's server proof (SPEC 9.3).  Malformed proofs never match."
  (and (ebp-valid-proof-p proof)
       (ebp--constant-time-equal
        proof (ebp-server-proof token pairing-id client-nonce server-nonce))))

;;;; Handshake messages (SPEC 9.2)

(defun ebp-hello-params (client-name client-version pairing-id client-nonce wants)
  "Build `session.hello' params (SPEC 9.2)."
  `(:protocol 3
    :client (:name ,client-name :version ,client-version)
    :pairing_id ,pairing-id
    :client_nonce ,client-nonce
    :wants ,(vconcat wants)))

(defun ebp-auth-params (pairing-id client-nonce server-nonce token)
  "Build `auth.response' params with the computed proof (SPEC 9.3)."
  `(:pairing_id ,pairing-id
    :client_nonce ,client-nonce
    :server_nonce ,server-nonce
    :client_proof ,(ebp-client-proof token pairing-id client-nonce server-nonce)))

;;;; Client session state machine (SPEC 10.1), pure

;; States: `connected' -> `challenged' -> `syncing' -> `ready'; any -> `closed'.
;; This is the Emacs-side view: we transition on our own sends and on
;; verified responses.  Transport wiring arrives in rung W3.

(defun ebp-session-step (state event)
  "Pure transition: STATE symbol + EVENT symbol -> new state, or nil if illegal.
Events: `hello-sent', `nonce-received', `auth-sent', `welcome-verified',
`ready-confirmed', `close'."
  (pcase (cons state event)
    (`(connected . hello-sent) 'awaiting-nonce)
    (`(awaiting-nonce . nonce-received) 'challenged)
    (`(challenged . auth-sent) 'awaiting-welcome)
    (`(awaiting-welcome . welcome-verified) 'syncing)
    (`(syncing . ready-confirmed) 'ready)
    (`(,_ . close) 'closed)
    (_ nil)))

(provide 'ebp-wire)
;;; ebp-wire.el ends here

(use-modules (ice-9 regex)
             (ice-9 popen)
             (ice-9 rdelim)
             (ice-9 ftw)
             (ice-9 threads)
             (srfi srfi-1)
             (srfi srfi-19))

; OpenSSL не учитывает текущую locale (место действия). Приспосабливаемся
(setlocale LC_ALL "en_US.UTF-8")

(define dump
  (let ((p (current-error-port))
        (m (make-mutex)))
    (lambda (fmt . args)
      (with-mutex m (apply format p fmt args)) (force-output p))))

(define (false? v) (and (boolean? v) (not v)))
(define (populated? l) (positive? (length l)))

; Дурная функция, потому что, например, (empty? 1) ⇒ #f
; (define (empty? v) (and (list? v) (null? v)))

(define fqdn-re (make-regexp "[0-9a-z-]+(\\.[0-9a-z-]+)+"))

; Удобно для поиска общих доменов в адресах разбить их на последовательности
; слов, которые в адресе разделяются точкой.
(define (string->fqdn s) (reverse (string-split s #\.)))
(define (fqdn->string n) (string-join (reverse n) "."))

; Сравнение fqdn (в заданном выше смысле). Возвращает #:less #:equal #:greater
(define (fqdn-compare s t)
  ; 1. Если t пустой адрес, то s ≥ t, разбираем случаи.
  ; 2. Если t не пустой, то пустой s < t.
  ; 3. Сравниваем первые компоненты имён. Если (car s) < (car t), возвращаем
  ; #:less. Если (car s) > (car t), возвращаем #:greater. В случае (car s) =
  ; (car t) сравниваем оставшиеся хвосты.  
  (cond ((null? t) (if (null? s) #:equal #:greater))
        ((null? s) #:less)
        (else (string-compare (car s) (car t)
                              (const #:less)
                              (lambda A (fqdn-compare (cdr s) (cdr t)))
                              (const #:greater)))))

(define (fqdn>? s t) (eqv? #:greater (fqdn-compare s t)))
(define (fqdn=? s t) (eqv? #:equal (fqdn-compare s t)))
(define (fqdn<? s t) (eqv? #:less (fqdn-compare s t)))

(define (pipe-lines . cmd)
  (let* ((p (apply open-pipe* OPEN_READ cmd))
         (l (unfold eof-object? identity (λ x (read-line p)) (read-line p))))
    (close-pipe p)
    l))

(define (unique L less? same?)
  (let ((S (sort L less?)))
    (if (null? S)
      '()
      (fold (lambda (x R) (if (same? (car R) x) R (cons x R)))
            (list (car S))
            (cdr S)))))

(define key car)
(define expire cadr)
(define subject cddr)

(define (certificate-subjects text)
  (unique (fold (lambda (s R)
                  (fold-matches fqdn-re s R
                                (lambda (m M)
                                  (cons (string->fqdn (match:substring m)) M))))
                '()
                text)
          fqdn<?
          fqdn=?))

; (define (read-subjects p)
;   (let loop ((v (read-line p))
;              (R '()))
;     (append-map (fold-matches fqdn-re s 
;                               compose string->fqdn
;                               match:substring
;                               (lambda (s) (list-matches fqdn-re s))))
;     (if (eof-object? v)
;       (map (compose string->fqdn match:substring) R)
;       (loop (read-line p)
;             (append-reverse (list-matches fqdn-re v) R)))))

; Вспомогательные процедуры вывода сообщений об ошибках. Возвращают значения,
; примерно соответствующие необходимой логике программы.

(define (warn fmt . args) (apply dump (string-append "WARNING: " fmt) args) #f)
(define (ignore fmt . args) (apply dump (string-append "IGNORING: " fmt) args) '())
 
; Беда: Guile не умеет понимать строковые обозначения временных зон. Поэтому
; надо извлечь обозначение временной зоны, убедиться что это GMT или UTC, и
; заменить его на +0000. Ожидается, что зоны обозначены словом из заглавных
; букв и записаны в конце.

(define zone-re (make-regexp "[A-Z]+$"))

(define (fix-timezone s)
  (let ((m (regexp-exec zone-re s)))
    (if (and (regexp-match? m)
             (member (match:substring m) '("GMT" "UTC") string=?))
      (string-append (match:prefix m) "+0000")
      (warn "Unexpected timezone: ~s~%" s))))

(define (expiration-time s)
  (let ((l (fix-timezone s)))
    (and l (date->time-utc (string->date l "notAfter=~b~d~H:~M:~S~Y~z"))))) 
 
(define (read-key cert)
  (catch 
    #t
    (lambda ()
      (let* ((L (pipe-lines "openssl" "x509" "-noout" "-in" cert
                            "-enddate"
                            "-subject"
                            "-ext" "subjectAltName"))
             (t (and (pair? L) (expiration-time (car L))))
             (S (and (pair? L) (certificate-subjects (cdr L)))))
        (if (and (time? t)
                 (populated? S))
          (map (lambda (s) (cons* cert t s)) S)
          (ignore "lack of data: ~a: ~s ~s~%" cert t S))))
    (lambda err
      (ignore "error: ~a: ~s~%" cert err))))

(define read-key-directory
  (let ((pass (lambda (path stat result) result))

        (fail (lambda (path stat errno result)
                (warn "~a: ~a~%" path (strerror errno))
                result))

        (leaf (lambda(path stat result)
                (cond
                  ((and (eq? 'regular (stat:type stat))
                        (string-suffix? ".pem" path))
                   (cons path result))

                  (else (warn "~a: not a regular .pem file~%" path)
                        result)))))
    (lambda (directory)
      (let ((pems (file-system-fold
                    ; Заходить директорию? 
                    (const #t)

                    ; Обработка записей в директориях.
                    leaf

                    ; Действия на входе из неё, на выходе, при её пропуске.
                    pass
                    pass
                    pass

                    ; Обработка ошибок.
                    fail

                    '()
                    (canonicalize-path directory)

                    ; Проходить по символическим ссылкам.
                    stat)))
        (concatenate (par-map read-key pems))))))

(define expiration-date (compose date->string time-utc->date expire))
(define subject-url (compose fqdn->string subject))

(define (only-fresh keys)
  (unique keys
          (lambda (k l)
            (case (fqdn-compare (subject k) (subject l))
              ((#:less) #f)
              ((#:greater) #t)
              ((#:equal) (time>? (expire k) (expire l)))))
          (lambda (k l)
            (and (fqdn=? (subject k) (subject l))
                 (begin (dump "WARNING: ignoring outdated: ~a: ~a: ~a~%"
                              (key l)
                              (subject-url l)
                              (expiration-date l))
                        #t)))))

(define key-directory
  (let* ((cl (command-line))
         (len (length cl))
         (path (or (and (= 2 len) (second cl))
                   (and (<= 3 len) (third cl)))))
    ; (dump "PATH: ~s~%" path)
    (if (and path
             (absolute-file-name? path)
             (file-exists? path)
             (file-is-directory? path))
      path
      (begin (dump "ERROR: expecting absolute dir path: ~s~%" cl)
             (exit 1)))))

(define (light-echo p)
  (format #t "$HTTP[\"host\"] == ~s {~%~/ssl.pemfile = ~s # ~s~%}~%~%"
          (subject-url p)
          (key p)
          (expiration-date p)))

(define nginx-echo
  (let ((template
          (string-append "server { "
                         "include \"https-proxy.conf\"; "
                         "server_name ~a; "
                         "ssl_certificate ~a; "
                         "ssl_certificate_key ~a; "
                         "} ")))
    (lambda (p)
      (format #t template (subject-url p) (key p) (key p)))))

(define engine
  (let* ((cl (command-line))
         (len (length cl)))
    (if (<= len 2)
      nginx-echo
      (let ((name (second cl)))
        (cond ((string=? "nginx" name) nginx-echo)
              ((string=? "lighttpd" name) light-echo)
              (else (dump "ERROR: unknown server: ~s~%" name)
                    (exit 1)))))))

(define key-records (only-fresh (read-key-directory key-directory)))

; (for-each write-line key-records)
; (exit 0)

; По идее, сравнения по указателям должны работать.
(let ((len (length key-records)))
  (when (and (eq? nginx-echo engine)
             (positive? len))
    (format #t
            "server_names_hash_bucket_size ~a; "
            (expt 2 (integer-length len)))))

(for-each engine key-records)

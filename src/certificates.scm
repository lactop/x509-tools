(use-modules (ice-9 regex)
             (ice-9 popen)
             (ice-9 rdelim)
             (ice-9 ftw)
             (ice-9 threads)
             (srfi srfi-1)
             (srfi srfi-19))

(define dump
  (let ((p (current-error-port))
        (m (make-mutex)))
    (lambda (fmt . args)
      (with-mutex m (apply format p fmt args)) (force-output p))))

(define (false? v) (and (boolean? v) (not v)))

; Беда: Guile не умеет понимать строковые обозначения временных зон. Поэтому
; надо извлечь обозначение временной зоны, убедиться что это GMT или UTC, и
; заменить его на +0000. 
(define (excavate-date s)
  ; (dump "DATE: ~s~%" s)
  (let ((l (string-length s)))
    (and (< 3 l)
       (let ((zone (substring/read-only s (- l 3)))
             (date (substring/read-only s 0 (- l 3))))
         (if (or (string=? "GMT" zone)
                 (string=? "UTC" zone))
           (string-append date "+0000")
           (begin (dump "WARNING: Unknown time-zone: ~s~%" s) 
                  #f))))))

(define (read-expire p)
  (let ((l (excavate-date (read-line p))))
    (and l (date->time-utc (string->date l "notAfter=~b~d~H:~M:~S~Y~z")))))

(define fqdn-re (make-regexp "[0-9a-z-]+(\\.[0-9a-z-]+)+"))

; Удобно для поиска общих доменов в адресах разбить их на последовательности
; слов, которые в адресе разделяются точкой.
(define (string->fqdn s) (reverse (string-split s #\.)))
(define (fqdn->string n) (string-join (reverse n) "."))

; Сравнение fqdn (в заданном выше смысле). Возвращает #:L #:E #:G
(define (fqdn-compare s t)
  ; (1) Если t пустой адрес, то s ≥ t, разбираем случаи.
  ; (2) Если t не пустой, то пустой s < t.
  ; (3) Сравниваем первые компоненты имён. Если (car s) < (car t), возвращаем
  ; #t. Если (car s) > (car t), возвращаем #f. В случае (car s) = (car t)
  ; сравниваем оставшиеся хвосты.  
  (cond ((null? t) (if (null? s) #:E #:G))
        ((null? s) #:L)
        (else (string-compare (car s) (car t)
                              (const #:L)
                              (lambda A (fqdn-compare (cdr s) (cdr t)))
                              (const #:G)))))

(define (fqdn>? s t) (eqv? #:G (fqdn-compare s t)))
(define (fqdn=? s t) (eqv? #:E (fqdn-compare s t)))
(define (fqdn<? s t) (eqv? #:L (fqdn-compare s t)))

(define (read-subjects p)
  (let loop ((v (read-line p))
             (R '()))
    (if (eof-object? v)
      (map (compose string->fqdn match:substring) R)
      (loop (read-line p)
            (append-reverse (list-matches fqdn-re v) R)))))

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
 
(define (read-key cert)
  (catch 
    #t
    (lambda ()
      (let ((p (open-pipe* OPEN_READ "openssl" "x509" "-noout" "-in" cert
                           "-enddate"
                           "-subject"
                           "-ext" "subjectAltName")))
        (let ((expire (read-expire p))
              (subjects (unique (read-subjects p) fqdn<? equal?)))
          (close-pipe p)
          (if (or (null? subject)
                  (not (time? expire)))
            (begin (dump "WARNING: ignoring due to lack of data: ~a: ~s ~s~%"
                         cert expire subjects)
                   '())
            (map (lambda (s) (cons cert (cons expire s))) subjects)))))
    (lambda err
      (dump "WARNING: ignoring due to error: ~a: ~s~%" cert err)
      '())))

(define read-key-directory
  (let ((pass (lambda (path stat result) result))

        (fail
          (lambda (path stat errno result)
            (dump "WARNING: ~a: ~a~%" path (strerror errno))
            result))

        (leaf
          (lambda(path stat result)
            (cond
              ((and (eq? 'regular (stat:type stat))
                    (string-suffix? ".pem" path))
               (cons path result))

              (else (dump "WARNING: ~a: not a regular .pem file~%" path)
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
              ((#:L) #f)
              ((#:G) #t)
              ((#:E) (time>? (expire k) (expire l)))))
          (lambda (k l)
            (and (fqdn=? (subject k) (subject l))
                 (begin (dump "WARNING: ignoring outdated: ~a: ~a: ~a~%"
                              (key l)
                              (subject-url l)
                              (expiration-date l))
                        #t)))
          ))

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

; По идее, сравнения по указателям должны работать.
(when (eq? nginx-echo engine)
  (format #t "server_names_hash_bucket_size ~a; "
          (expt 2 (integer-length (length key-records)))))

(for-each engine key-records)

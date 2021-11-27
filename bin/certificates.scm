#! /usr/bin/env guile
!#

(use-modules (ice-9 regex)
             (ice-9 popen)
             (ice-9 rdelim)
             (ice-9 ftw)
             (ice-9 threads)
             (ice-9 getopt-long)
             (ice-9 vlist)
             (ice-9 match)
             (srfi srfi-1)
             (srfi srfi-11)
             (srfi srfi-19)
             (srfi srfi-43))

; OpenSSL не учитывает текущую locale (место действия). Приспосабливаемся
(setlocale LC_ALL "en_US.UTF-8")

; ПРОСТЫЕ ВСПОМОГАТЕЛЬНЫЕ ПРОЦЕДУРЫ

(define dump
  (let ((p (current-error-port))
        (m (make-mutex)))
    (lambda (fmt . args)
      (with-mutex m (apply format p fmt args)) (force-output p))))

; Вспомогательные процедуры вывода сообщений об ошибках. Возвращают значения,
; примерно соответствующие необходимой логике программы.

(define (warn fmt . args)
  (apply dump (string-append "WARNING: " fmt) args)
  #f)

(define (ignore fmt . args)
  (apply dump (string-append "IGNORING: " fmt) args)
  #f) 

(define (false? v) (and (boolean? v) (not v)))
(define (populated? l) (positive? (length l)))

; Список строк выданных на stdout запущенной cmd
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

(define (of-strings . S) (lambda (s) (member s S string=?)))

; ПРОЦЕДУРЫ ДЛЯ РАБОТЫ С FQDN ВО ВНУТРЕННЕМ ФОРМАТЕ

; Удобно для поиска общих доменов в адресах разбить их на последовательности
; слов, которые в адресе разделяются точкой.
(define (string->fqdn s) (reverse (string-split s #\.)))
(define (fqdn->string n) (string-join (reverse n) ".")) 

; Сравнение fqdn (в заданном выше смысле). Возвращает #:less #:equal #:greater
(define (fqdn-compare s t)
  ; 1. Если t пустой адрес, то s ≥ t, разбираем случаи.
  ; 2. Если t не пустой, то пустой s < t.
  ; 3. Сравниваем первые компоненты имён.
  ;   3.1. (car s) < (car t) → #:less
  ;   3.2. (car s) > (car t) → #:greater
  ;   3.3. (car s) = (car t) → сравнение оставшихся хвостов
  (cond ((null? t) (if (null? s) #:equal #:greater))
        ((null? s) #:less)
        (else (string-compare (car s) (car t)
                              (const #:less)
                              (lambda A (fqdn-compare (cdr s) (cdr t)))
                              (const #:greater)))))

(define (fqdn>? s t) (eqv? #:greater (fqdn-compare s t)))
(define (fqdn=? s t) (eqv? #:equal (fqdn-compare s t)))
(define (fqdn<? s t) (eqv? #:less (fqdn-compare s t)))

; ЧТЕНИЕ НЕОБХОДИМЫХ ДАННЫХ О СЕРТИФИКАТАХ

(define certificate-subjects 
  (let ((fqdn-re (make-regexp "(^subject=|DNS:)[^0-9a-z-]*([0-9a-z-]+(\\.[0-9a-z-]+)+)"))
        (domain
          (lambda (m)
            ; В совпадении нужна 2 группа + 1 (группа всей строки)
            (let ((s (vector-ref m 3)))
              (substring/read-only (match:string m) (car s) (cdr s))))))
    (lambda (text)
      (unique (fold (lambda (s R)
                      (fold-matches fqdn-re s R
                                    (lambda (m M)
                                      (cons (string->fqdn (domain m)) M))))
                    '()
                    text)
              fqdn>?
              fqdn=?))))
 
; Беда: Guile не умеет понимать строковые обозначения временных зон. Поэтому
; надо извлечь обозначение временной зоны, убедиться что это GMT или UTC, и
; заменить его на +0000. Ожидается, что зоны обозначены словом из заглавных
; букв и записаны в конце.

(define fix-timezone 
  (let ((zone-re (make-regexp "[A-Z]+$"))
        (expected-zone? (of-strings "GMT" "UTC")))
    (lambda (s)
      (let ((m (regexp-exec zone-re s)))
        (if (and (regexp-match? m)
                 (expected-zone? (match:substring m)))
          (string-append (match:prefix m) "+0000")
          (warn "Unexpected timezone: ~s~%" s))))))

(define (expiration-time s)
  (let ((l (fix-timezone s)))
    (and l (date->time-utc (string->date l "notAfter=~b~d~H:~M:~S~Y~z"))))) 
 
; Примерно такой вот у нас формат прочитанных сертификатов
(define x509:file caar)
(define x509:expire cdar)
(define x509:subjects cdr)
 


(define read-certificate
  (let ((cert-opt (string-join '("no_subject"
                                 "no_header"
                                 "no_version"
                                 "no_serial"
                                 "no_signame"
                                 "no_validity"
                                 "no_issuer"
                                 "no_pubkey"
                                 "no_sigdump"
                                 "no_aux"
                                 "ext_error")
                               ",")))
    (lambda (cert)
      (catch 
        #t
        (lambda ()
          (let* ((L (pipe-lines "openssl" "x509" "-noout" "-in" cert
                                "-enddate"
                                "-subject"
                                "-text"
                                "-certopt" cert-opt))
                 (t (and (pair? L) (expiration-time (car L))))
                 (S (and (pair? L) (certificate-subjects (cdr L)))))
            (if (and (time? t)
                     (populated? S))
              (cons (cons cert t) S)
              (ignore "lack of data: ~a: ~s ~s~%" cert t S))))
        (lambda err
          (ignore "error: ~a: ~s~%" cert err))))))

(define read-certificate-directories
  (let* ((pass (lambda (path stat result) result))
         (fail (lambda (path stat errno result)
                 (warn "~a: ~a~%" path (strerror errno))
                 result))
         (leaf (lambda (path stat result)
                 (if (and (eq? 'regular (stat:type stat))
                          (string-suffix? ".pem" path))
                   (cons path result)
                   (begin (ignore "not a regular .pem file: ~a~%" path)
                          result))))
         (pems (lambda (path)
                 (file-system-fold
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
                   path

                   ; Проходить по символическим ссылкам.
                   stat))))
    (lambda (paths)
      (let ((C (par-map read-certificate (append-map pems paths))))
        ; (dump "LOADED~%")
        (filter identity C)))))

; ВЫВОД ИНФОРМАЦИИ О СЕРТИФИКАТЕ

(define (dump-certificate c)
  (dump "~%~/~a~%~/~/expiration date: ~a~%~/~/subjects: ~a~%"
        (x509:file c)
        (date->string (time-utc->date (x509:expire c)))
        (string-join (map fqdn->string (x509:subjects c)) " ")))

; ОБРАБОТКА СЕРТИФИКАТОВ

(define filter-expired
  (let* ((today (date->time-utc (current-date)))
         (active? (lambda (c) (time<? today (x509:expire c)))))
    (lambda (C)
      (partition active? C))))

(define (list-subjects V)
  (vector-fold (lambda (i R certificate)
                 (append-reverse
                   (map (lambda (c) (cons i c)) (x509:subjects certificate))
                   R))
               '()
               V))

(define (select-actual C)
  (let* ((V (list->vector C))
         (U (make-bitvector (vector-length V)))
         (subject cdr)
         (expire (lambda (s) (x509:expire (vector-ref V (car s)))))

         ; Расставляем ключи так, чтобы для одного subject сначала встречались
         ; более свежие сертификаты
         (less? (lambda (k l)
                  (case (fqdn-compare (subject k) (subject l))
                    ((#:less) #f)
                    ((#:greater) #t)
                    ((#:equal) (time>? (expire k) (expire l)))
                    (else (error "Ordering nonsense:" k l)))))

         ; Тест на равенство subject. Дополнительно отмечает сертификат с
         ; впервые встретившимся subject в векторе U (used). ВАЖНО: из-за
         ; особенностей unique первый элемент списка не встретится на втором
         ; месте при вызове same? Нужно отметить этот элемент дополнительно.
         (same? (lambda (k l) 
                  (or (fqdn=? (subject k) (subject l))
                      (begin (bitvector-set! U (car l) #t) #f))))

         (A (unique (list-subjects V) less? same?)))

    ; Поправка к same?
    (when (populated? A) (bitvector-set! U (car (car A)) #t))

    (values (map (lambda (s) (let ((c (vector-ref V (car s))))
                               (cons* (x509:file c) (x509:expire c) (cdr s))))
                 A)
            ; В этом списке неиспользуемые сертификаты, для которых (U i) = #f
            (vector-fold (lambda (i R c) (if (bitvector-ref U i) R (cons c R)))
                         '()
                         V))))

(define (separate-certificates paths quiet?)
  (let*-values (((C) (read-certificate-directories paths))
                ((valid expired) (filter-expired C))
                ((actual outdated) (select-actual valid)))
    (when (and (populated? expired) (not quiet?))
      (dump "EXPIRED:")
      (for-each dump-certificate expired)
      (dump "~%"))
    (when (and (populated? outdated) (not quiet?))
      (dump "OUTDATED:")
      (for-each dump-certificate outdated)
      (dump "~%"))
    (values actual outdated expired)))

; РАЗБОР ПАРАМЕТРОВ КОМАНДНОЙ СТРОКИ

(define usage
  (let* ((s "certificates.scm ")
         (n (string-length s))
         (f (string-join '("~a[-p path]"
                           "[-c nginx | lighttpd]"
                           "[-d expired | outdated | both]"
                           "[-q]"
                           "[-h]~%")
                         "~%~1@*~v_")))
    (lambda () (dump f s n))))

(define purify-options
  (let ((non-engine? (compose not (of-strings "nginx" "lighttpd")))
        (non-mode? (compose not (of-strings "both" "expired" "outdated")))
        (non-path? (compose not (lambda (p) (and (absolute-file-name? p)
                                                 (file-exists? p)
                                                 (file-is-directory? p))))))
    (lambda (paths modes engines flags)
      (let ((NP (filter non-path? paths))
            (NM (filter non-mode? modes))
            (NE (filter non-engine? engines)))
        (let ((p? (populated? NP))
              (e? (populated? NE))
              (m? (populated? NM))
              (u? (< 1 (length engines))))
          (when p? (dump "Not absolute directory paths: ~s~%" NP))
          (when m? (dump "Unknown erase modes: ~s~%" NM))
          (when e? (dump "Unknown configuration requests: ~s~%" NE))
          (when (and (not e?) u?)
            (dump "Ambiguous configuration requests: ~s~%" engines))

          (when (or p? m? e? u?) (usage) (exit 1))

          (values (unique (map canonicalize-path paths) string<? string=?)
                  modes
                  (if (null? engines) "" (car engines))
                  flags))))))

(define parse-command-line
  (let ((spec '((help (single-char #\h))
                (path (single-char #\p) (value #t))
                (quiet (single-char #\q))
                (delete (single-char #\d) (value #t))
                (configure (single-char #\c) (value #t))))

        (kv (lambda (put!)
              (match-lambda
                (('() . I) (when (populated? I)
                             (dump "unexpected command-line items: ~s~%" I)
                             (throw 'quit 1)))

                (('help . #t) (throw 'quit 1))

                (('path . p) (put! 'path p))
                (('quiet . #t) (put! 'flags 'quiet))
                (('delete . m) (put! 'mode m))
                (('configure . e) (put! 'engine e)))))

        (cons-to-key!
          (lambda (H)
            (lambda (key item)
              (let ((I (hashq-ref H key)))
                (if (false? I) 
                  (error "Invalid option key: ~s~%" key)
                  (hashq-set! H key (cons item I))))))))
    (lambda (cl)
      (let ((H (make-hash-table 3)))
        (hashq-set! H 'path '())
        (hashq-set! H 'mode '())
        (hashq-set! H 'flags '())
        (hashq-set! H 'engine '())

        (catch 'quit
               (lambda () (for-each (kv (cons-to-key! H)) (getopt-long cl spec)))
               (lambda err (usage) (exit 1)))

        (purify-options (hashq-ref H 'path)
                        (unique (hashq-ref H 'mode) string>? string=?)
                        (unique (hashq-ref H 'engine) string>? string=?)
                        (unique (hashq-ref H 'flags)
                                (lambda (s t) (string<? (symbol->string s)
                                                        (symbol->string t)))
                                eqv?))))))


; ЛОГИКА ВЕРХНЕГО УРОВНЯ

(define key car)
(define expiration-date (compose date->string time-utc->date cadr))
(define subject-url (compose fqdn->string cddr))

(define (light-echo p)
  (format #t "$HTTP[\"host\"] == ~s {~%~/ssl.pemfile = ~s # ~s~%}~%~%"
          (subject-url p)
          (key p)
          (expiration-date p)))

(define nginx-echo
  (let ((template (string-append "server { "
                                 "include \"https-proxy.conf\"; "
                                 "server_name ~a; "
                                 "ssl_certificate ~a; "
                                 "ssl_certificate_key ~a; "
                                 "} ")))
    (lambda (p)
      (format #t template (subject-url p) (key p) (key p))))) 

(define (echo-file s) (dump "~/~a~%" (x509:file s)))

(define (remove-file s)
  (catch 'system-error
         (lambda () (delete-file (x509:file s)))
         (lambda err (warn "cannot unlink: ~a: ~a~%"
                           (strerror (system-error-errno err))
                           (x509:file s)))))

(let*-values (((paths modes engine flags) (parse-command-line (command-line)))
              ((mode? quiet?) (values (apply of-strings modes)
                                      (memq 'quiet flags)))
              ((actual outdated expired) (separate-certificates paths quiet?))
              ((both? expired? outdated?) (values (mode? "both")
                                                  (mode? "expired")
                                                  (mode? "outdated"))))

  (when (not (string-null? engine))
    (let ((len (length actual))
          (echo (cond ((string=? "nginx" engine) nginx-echo)
                      ((string=? "lighttpd" engine) light-echo)
                      (else (error "Unknown echo engine:" engine)))))
      (when (and (positive? len)
                 (eq? echo nginx-echo))
        (format #t
                "server_names_hash_bucket_size ~a; "
                (expt 2 (integer-length len))))
      (for-each echo actual)))

  (when (and (populated? expired) (or expired? both?))
    (when (not quiet?)
      (dump "REMOVING EXPIRED:~%")
      (for-each echo-file expired)
      (dump "~%"))
    (for-each remove-file expired))

  (when (and (populated? outdated) (or outdated? both?))
    (when (not quiet?)
      (dump "REMOVING OUTDATED:~%")
      (for-each echo-file outdated)
      (dump "~%"))
    (for-each remove-file outdated)))


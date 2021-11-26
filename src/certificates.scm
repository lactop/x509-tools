(use-modules (ice-9 regex)
             (ice-9 popen)
             (ice-9 rdelim)
             (ice-9 ftw)
             (ice-9 threads)
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

(define (warn fmt . args) (apply dump (string-append "WARNING: " fmt) args) #f)
(define (ignore fmt . args) (apply dump (string-append "IGNORING: " fmt) args) '()) 

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

; ПРОЦЕДУРЫ ДЛЯ РАБОТЫ С FQDN ВО ВНУТРЕННЕМ ФОРМАТЕ

; Удобно для поиска общих доменов в адресах разбить их на последовательности
; слов, которые в адресе разделяются точкой.
(define (string->fqdn s) (reverse (string-split s #\.)))
(define (fqdn->string n) (string-join (reverse n) ".")) 

(define fqdn-re (make-regexp "[0-9a-z-]+(\\.[0-9a-z-]+)+"))

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

(define (certificate-subjects text)
  (unique (fold (lambda (s R)
                  (fold-matches fqdn-re s R
                                (lambda (m M)
                                  (cons (string->fqdn (match:substring m)) M))))
                '()
                text)
          fqdn>?
          fqdn=?))
 
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
 
; Примерно такой вот у нас формат прочитанных сертификатов
(define x509:file caar)
(define x509:expire cdar)
(define x509:subjects cdr)
 
(define (read-certificate cert)
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
          (cons (cons cert t) S)
          (ignore "lack of data: ~a: ~s ~s~%" cert t S))))
    (lambda err
      (ignore "error: ~a: ~s~%" cert err))))

(define read-certificate-directory
  (let ((pass (lambda (path stat result) result))
        (fail (lambda (path stat errno result)
                (warn "~a: ~a~%" path (strerror errno))
                result))
        (leaf (lambda (path stat result)
                (if (and (eq? 'regular (stat:type stat))
                         (string-suffix? ".pem" path))
                  (cons path result)
                  (begin (warn "~a: not a regular .pem file~%" path)
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
        (par-map read-certificate pems)))))

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

; (define (only-fresh keys)
;   (unique keys
;           (lambda (k l)
;             (case (fqdn-compare (subject k) (subject l))
;               ((#:less) #f)
;               ((#:greater) #t)
;               ((#:equal) (time>? (expire k) (expire l)))))
;           (lambda (k l)
;             (and (fqdn=? (subject k) (subject l))
;                  (begin (warn "ignoring outdated: ~a: ~a: ~a~%"
;                               (key l)
;                               (subject-url l)
;                               (expiration-date l))
;                         #t)))))

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

; ЛОГИКА ВЕРХНЕГО УРОВНЯ

(define certificate-directory
  (let* ((cl (command-line))
         (len (length cl))
         (path (or (and (= 2 len) (second cl))
                   (and (<= 3 len) (third cl)))))
    (if (and path
             (absolute-file-name? path)
             (file-exists? path)
             (file-is-directory? path))
      path
      (begin (dump "ERROR: expecting absolute dir path: ~s~%" cl)
             (exit 1)))))

(let*-values (((C) (read-certificate-directory certificate-directory))
              ((valid expired) (filter-expired C))
              ((actual outdated) (select-actual valid)))

;   (for-each write-line actual)
;   (write-line outdated)

  (when (populated? expired)
    (dump "EXPIRED:")
    (for-each dump-certificate expired)
    (dump "~%"))

  (when (populated? outdated)
    (dump "OUTDATED:")
    (for-each dump-certificate outdated)
    (dump "~%")))

(exit 0) 

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
                 (begin (warn "ignoring outdated: ~a: ~a: ~a~%"
                              (key l)
                              (subject-url l)
                              (expiration-date l))
                        #t)))))

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
(let ((len (length key-records)))
  (when (and (eq? nginx-echo engine)
             (positive? len))
    (format #t
            "server_names_hash_bucket_size ~a; "
            (expt 2 (integer-length len)))))

(for-each engine key-records)

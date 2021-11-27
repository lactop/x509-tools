### X.509 Tools

X.509 Tools help one to manage collections of PKI certificates.  X.509 Tools
allow at the moment
* to perform cleanups by removing expired and outdated certificates
* and to generate https configurations, which bind paths to certificate files
  with subjects of those certificates, for Nginx and lighttpd.

#### Dependencies

Tools are written in [GNU Guile](https://www.gnu.org/software/guile/) and use
[OpenSSL](https://www.openssl.org) binary to perform tasks. So the `guile` and
`openssl` executables must be on one of the `PATH`. Versions
* GNU Guile 2.0.14
* OpensSSL 1.0.1t

should be sufficeint.

#### certificates.scm

The `certificates.scm` program performs certificate directories cleanup and
generates https configurations for reverse proxying virtual domains listed in
the subjects of the certificates with the Nginx and lighttpd servers.

##### Installation

Clone the repository, copy the `bin/certificates.scm` file to the preferred
directory and make the file executable.
```
  $ git clone https://github.com/lactop/x509-tools
  $ sudo mkdir -p /opt/bin
  $ sudo cp x509-tools/bin/certificates.scm /opt/bin
  $ sudo chmod +x /opt/bin/certificates.scm
```

##### Terminology

The `certificate.scm` treats certificate as **expired**, if the certificate is
not valid after time when the `certificate.scm` was started.

The `сertificate.scm` treats certificate as **outdated** if for all subjects of
this certificate there are certificates which will be valid for the longer
period of time.

##### Operations

```
certificates.scm [-p path]
                 [-c nginx | lighttpd]
                 [-d expired | outdated | both]
                 [-q]
                 [-h]
```

- `-p` `--path` *path* appends *path* to processed directories. Only files with
  `.pem` extension are taken into account. **WARNING**: certificate in one
  directory may be outdated by certificates in another.
- `-c` `--configure` *server* requests virtual https hosts configuration for the
  *server*. Currently only `nginx` and `lighttpd` are supported. The option
  should be specified once. The resulting configuration is printed to the
  standard output.
- `-d` `--delete` *set* requests the deletion of `expired` or `outdated` *set*
  of certificates or `both` of them.
- `-q` `--quiet` makes the program perform silent.
- `-h` `--help` outputs short help message.

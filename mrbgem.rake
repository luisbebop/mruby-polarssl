MRuby::Gem::Specification.new('mruby-polarssl') do |spec|
  spec.license = 'GPL'
  spec.authors = 'luisbebop@gmail.com'

  polarssl_dirname = 'polarssl'
  polarssl_src = "#{spec.dir}/#{polarssl_dirname}"
  spec.cc.include_paths << "#{polarssl_src}/include"
  spec.cc.include_paths << "#{polarssl_src}/../../mruby-io/include"
  spec.cc.include_paths << "#{build.root}/src"
  spec.cc.flags << '-D_FILE_OFFSET_BITS=64 -Wall -W -Wdeclaration-after-statement'

  spec.objs += %W(
    #{polarssl_src}/library/aes.c
    #{polarssl_src}/library/aesni.c
    #{polarssl_src}/library/arc4.c
    #{polarssl_src}/library/asn1parse.c
    #{polarssl_src}/library/asn1write.c
    #{polarssl_src}/library/base64.c
    #{polarssl_src}/library/bignum.c
    #{polarssl_src}/library/blowfish.c
    #{polarssl_src}/library/camellia.c
    #{polarssl_src}/library/ccm.c
    #{polarssl_src}/library/certs.c
    #{polarssl_src}/library/cipher.c
    #{polarssl_src}/library/cipher_wrap.c
    #{polarssl_src}/library/ctr_drbg.c
    #{polarssl_src}/library/debug.c
    #{polarssl_src}/library/des.c
    #{polarssl_src}/library/dhm.c
    #{polarssl_src}/library/ecdh.c
    #{polarssl_src}/library/ecdsa.c
    #{polarssl_src}/library/ecp.c
    #{polarssl_src}/library/ecp_curves.c
    #{polarssl_src}/library/entropy.c
    #{polarssl_src}/library/entropy_poll.c
    #{polarssl_src}/library/error.c
    #{polarssl_src}/library/gcm.c
    #{polarssl_src}/library/havege.c
    #{polarssl_src}/library/hmac_drbg.c
    #{polarssl_src}/library/ripemd160.c
    #{polarssl_src}/library/md.c
    #{polarssl_src}/library/md2.c
    #{polarssl_src}/library/md4.c
    #{polarssl_src}/library/md5.c
    #{polarssl_src}/library/md_wrap.c
    #{polarssl_src}/library/memory_buffer_alloc.c
    #{polarssl_src}/library/net.c
    #{polarssl_src}/library/oid.c
    #{polarssl_src}/library/padlock.c
    #{polarssl_src}/library/pbkdf2.c
    #{polarssl_src}/library/pem.c
    #{polarssl_src}/library/pk.c
    #{polarssl_src}/library/pk_wrap.c
    #{polarssl_src}/library/pkcs11.c
    #{polarssl_src}/library/pkcs12.c
    #{polarssl_src}/library/pkcs5.c
    #{polarssl_src}/library/pkparse.c
    #{polarssl_src}/library/pkwrite.c
    #{polarssl_src}/library/rsa.c
    #{polarssl_src}/library/sha1.c
    #{polarssl_src}/library/sha256.c
    #{polarssl_src}/library/sha512.c
    #{polarssl_src}/library/ssl_cache.c
    #{polarssl_src}/library/ssl_ciphersuites.c
    #{polarssl_src}/library/ssl_cli.c
    #{polarssl_src}/library/ssl_srv.c
    #{polarssl_src}/library/ssl_tls.c
    #{polarssl_src}/library/threading.c
    #{polarssl_src}/library/timing.c
    #{polarssl_src}/library/version.c
    #{polarssl_src}/library/x509.c
    #{polarssl_src}/library/x509_create.c
    #{polarssl_src}/library/x509_crl.c
    #{polarssl_src}/library/x509_crt.c
    #{polarssl_src}/library/x509_csr.c
    #{polarssl_src}/library/x509write_crt.c
    #{polarssl_src}/library/x509write_csr.c
    #{polarssl_src}/library/xtea.c
  ).map { |f| f.relative_path_from(dir).pathmap("#{build_dir}/%X.o") }

  spec.add_dependency 'mruby-string-ext', core: 'mruby-string-ext'
  spec.add_dependency 'mruby-io'
  spec.add_dependency 'mruby-socket'
  spec.add_test_dependency 'mruby-mtest'
end

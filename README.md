mruby-polarssl
=========

## Description

Mbedtls (AKA PolarSSL) port for mruby, with this library your are able to use SSL/TLS and any other crypto functionality in the mruby runtime

## Features

* Set up encrypted SSL connections.

## Install
 - add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

    # ... (snip) ...

    conf.gem :git => 'https://github.com/luisbebop/mruby-polarssl.git'
end
```

## Test

```ruby
ruby run_test.rb test
```

## Usage
```ruby
socket = TCPSocket.new('polarssl.org', 443)

entropy = PolarSSL::Entropy.new
ctr_drbg = PolarSSL::CtrDrbg.new(entropy)

ssl = PolarSSL::SSL.new
ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
ssl.set_rng(ctr_drbg)
ssl.set_socket(socket)

ssl.handshake

ssl.write("GET / HTTP/1.0\r\nHost: polarssl.org\r\n\r\n")

response = ""
while chunk = ssl.read(1024)
  response << chunk
end

puts response

ssl.close_notify

socket.close

ssl.close
```

### Encrypting data

The `PolarSSL::Cipher` class lets you encrypt data with a wide range of
encryption standards DES-CBC, DES-ECB, DES3-CBC and DES3-ECB.

This sample encrypts a given plaintext with DES-ECB:

```ruby
cipher = PolarSSL::Cipher.new("DES-ECB")
cipher.encrypt
cipher.key = "0123456789ABCDEF"
cipher.update("1111111111111111")
# => "17668DFC7292532D"
```

## License

Under Apache 2.0 license, same as mbedtls license

```
mruby-polarssl - A mruby extension for using mbedtls (AKA PolarSSL).
Copyright (C) 20139  Luis Silva
```
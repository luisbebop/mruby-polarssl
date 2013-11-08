mruby-polarssl
=========

## Description

With PolarSSL for mruby, you can use SSL and cryptography functionality from PolarSSL in your mruby programs.

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
socket = TCPSocket.new('polarssl', 443)

entropy = PolarSSL::Entropy.new
ctr_drbg = PolarSSL::CtrDrbg.new(entropy)

ssl = PolarSSL::SSL.new
ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
ssl.set_rng(ctr_drbg)
ssl.set_socket(socket)

ssl.handshake

ssl.write("GET / HTTP/1.0\r\nHost: polarssl.org\r\n\r\n")

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
encryption standards like AES, Blowfish and DES.

This sample encrypts a given plaintext with AES128 in CTR mode:

```ruby
cipher = PolarSSL::Cipher.new("AES-128-CTR")

my_iv = SecureRandom.random_bytes(16)

cipher.reset(my_iv)
cipher.setkey("my16bytekey23456", 128, PolarSSL::Cipher::OPERATION_ENCRYPT)
cipher.update("some secret message I want to keep")
encrypted_data = cipher.finish

encoded_encrypted_data = Base64.encode64(encrypted_data)
encoded_iv = Base64.encode64(my_iv)
```

## License

*Please note*: PolarSSL itself is released as GPL or a Commercial License.
You will need to take this into account when using PolarSSL and this mruby extension in your
own software.

```
mruby-polarssl - A mruby extension for using PolarSSL.
Copyright (C) 2013  Luis Silva

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
```
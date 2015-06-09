# PolarSSL Test
if Object.const_defined?(:PolarSSL)
  assert("PolarSSL") do
    PolarSSL.class == Module
  end

  assert('PolarSSL::Entropy') do
    PolarSSL::Entropy.class == Class
  end

  assert('PolarSSL::Entropy#new') do
    entropy = PolarSSL::Entropy.new
  end

  assert('PolarSSL::Entropy#gather') do
    entropy = PolarSSL::Entropy.new
    entropy.gather() == true
  end

  assert('PolarSSL::CtrDrbg') do
    PolarSSL::CtrDrbg.class == Class
  end

  assert('PolarSSL::CtrDrbg#new err') do
    err = nil
    begin
      ctrdrbg = PolarSSL::CtrDrbg.new
    rescue Exception => e
      err = e
    end
    err.class == ArgumentError
  end

  assert('PolarSSL::CtrDrbg#new err 2') do
    err = nil
    begin
      ctrdrbg = PolarSSL::CtrDrbg.new "foo"
    rescue Exception => e
      err = e
    end
    err.class == TypeError
  end

  assert('PolarSSL::CtrDrbg#new') do
    entropy = PolarSSL::Entropy.new
    ctrdrbg = PolarSSL::CtrDrbg.new entropy
  end

  assert('PolarSSL::CtrDrbg#self_test') do
    PolarSSL::CtrDrbg.self_test
  end

  assert('PolarSSL::SSL') do
    PolarSSL::SSL.class == Class
  end

  assert('PolarSSL::SSL#new') do
    ssl = PolarSSL::SSL.new
  end

  assert('PolarSSL::SSL::SSL_IS_CLIENT') do
    PolarSSL::SSL.const_defined? :SSL_IS_CLIENT
    assert_equal(PolarSSL::SSL::SSL_IS_CLIENT, 0)
  end

  assert('PolarSSL::SSL::SSL_VERIFY_NONE') do
    PolarSSL::SSL.const_defined? :SSL_VERIFY_NONE
    assert_equal(PolarSSL::SSL::SSL_VERIFY_NONE, 0)
  end

  assert('PolarSSL::SSL::SSL_VERIFY_OPTIONAL') do
    PolarSSL::SSL.const_defined? :SSL_VERIFY_OPTIONAL
    assert_equal(PolarSSL::SSL::SSL_VERIFY_OPTIONAL, 1)
  end

  assert('PolarSSL::SSL::SSL_VERIFY_REQUIRED') do
    PolarSSL::SSL.const_defined? :SSL_VERIFY_REQUIRED
    assert_equal(PolarSSL::SSL::SSL_VERIFY_REQUIRED, 2)
  end

  assert('PolarSSL::SSL#set_endpoint') do
    ssl = PolarSSL::SSL.new
    ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
  end

  assert('PolarSSL::SSL#set_authmode') do
    ssl = PolarSSL::SSL.new
    ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
  end

  assert('PolarSSL::SSL#set_rng') do
    entropy = PolarSSL::Entropy.new
    ctr_drbg = PolarSSL::CtrDrbg.new(entropy)
    ssl = PolarSSL::SSL.new

    ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
    ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
    ssl.set_rng(ctr_drbg)
  end

  assert('PolarSSL::SSL#set_rng err') do
    err = nil
    begin
      ssl = PolarSSL::SSL.new
      ssl.set_rng "foo"
    rescue Exception => e
      err = e
    end
    #p "[BUG?expected Data?]#{e}"
    err.class == TypeError
  end

  assert('PolarSSL::SSL#set_socket') do
    socket = TCPSocket.new('polarssl.org', 443)
    entropy = PolarSSL::Entropy.new
    ctr_drbg = PolarSSL::CtrDrbg.new(entropy)
    ssl = PolarSSL::SSL.new
    ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
    ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
    ssl.set_rng(ctr_drbg)
    ssl.set_socket(socket)
  end

  assert('PolarSSL::SSL#handshake') do
    socket = TCPSocket.new('polarssl.org', 443)
    entropy = PolarSSL::Entropy.new
    ctr_drbg = PolarSSL::CtrDrbg.new(entropy)
    ssl = PolarSSL::SSL.new
    ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
    ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
    ssl.set_rng(ctr_drbg)
    ssl.set_socket(socket)
    ssl.handshake
  end

  assert('PolarSSL::SSL#handshake err') do
    @e = nil
    socket = TCPSocket.new('polarssl.org', 80)
    entropy = PolarSSL::Entropy.new
    ctr_drbg = PolarSSL::CtrDrbg.new(entropy)
    ssl = PolarSSL::SSL.new
    ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
    ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
    ssl.set_rng(ctr_drbg)
    ssl.set_socket(socket)
    begin
      ssl.handshake
    rescue => @e
    end
    @e.class == PolarSSL::SSL::Error
  end

  assert('PolarSSL::SSL#write') do
    socket = TCPSocket.new('polarssl.org', 443)
    entropy = PolarSSL::Entropy.new
    ctr_drbg = PolarSSL::CtrDrbg.new(entropy)
    ssl = PolarSSL::SSL.new
    ssl.set_endpoint(PolarSSL::SSL::SSL_IS_CLIENT)
    ssl.set_authmode(PolarSSL::SSL::SSL_VERIFY_NONE)
    ssl.set_rng(ctr_drbg)
    ssl.set_socket(socket)
    ssl.handshake
    ssl.write "foo"
  end

  assert('PolarSSL::SSL#read') do
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
    response.size > 0
    #debug
    #p "https response size: #{response.size}"
  end

  assert('PolarSSL::SSL#close_notify') do
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
    buf = ssl.read(4)
    #debug
    #p buf
    ssl.close_notify
  end

  assert('PolarSSL::SSL#close') do
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
    buf = ssl.read(4)
    #debug
    #p buf
    ssl.close_notify
    socket.close
    ssl.close
  end
end


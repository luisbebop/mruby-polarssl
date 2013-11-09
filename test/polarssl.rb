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
  end
  
  assert('PolarSSL::SSL::SSL_VERIFY_NONE') do
    PolarSSL::SSL.const_defined? :SSL_VERIFY_NONE
  end
  
  assert('PolarSSL::SSL::SSL_VERIFY_OPTIONAL') do
    PolarSSL::SSL.const_defined? :SSL_VERIFY_OPTIONAL
  end
  
  assert('PolarSSL::SSL::SSL_VERIFY_REQUIRED') do
    PolarSSL::SSL.const_defined? :SSL_VERIFY_REQUIRED
  end
  
end
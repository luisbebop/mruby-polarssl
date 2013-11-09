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
end
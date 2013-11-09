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
end
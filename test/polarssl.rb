# PolarSSL Test

if Object.const_defined?(:PolarSSL)
  assert("PolarSSL") do
    PolarSSL.class == Module
  end
end
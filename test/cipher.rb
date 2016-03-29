
class CipherTest < MTest::Unit::TestCase
  def test_cipher_encrypt_des_cbc
    cipher = PolarSSL::Cipher.new("DES-CBC")
    cipher.encrypt
    cipher.key = "0123456789ABCDEF"
    cipher.iv  = "fedcba9876543210"
    assert_equal "CCD173FFAB2039F4ACD8AEFDDFD8A1EB468E91157888BA68",
      cipher.update("37363534333231204E6F77206973207468652074696D6520")
  end

  def test_cipher_encrypt_des_ecb
    cipher = PolarSSL::Cipher.new("DES-ECB")
    cipher.encrypt
    cipher.key = "0123456789ABCDEF"
    assert_equal "17668DFC7292532D", cipher.update("1111111111111111")
  end

  def test_cipher_encrypt_3des_cbc
    cipher = PolarSSL::Cipher.new("DES3-CBC")
    cipher.encrypt
    cipher.key = "0123456789abcdeff1e0d3c2b5a49786fedcba9876543210"
    cipher.iv  = "fedcba9876543210"
    assert_equal "3FE301C962AC01D02213763C1CBD4CDC799657C064ECF5D4",
      cipher.update("37363534333231204E6F77206973207468652074696D6520")
  end

  def test_cipher_encrypt_3des_ecb
    cipher = PolarSSL::Cipher.new("DES3-ECB")
    cipher.encrypt
    cipher.key = "0000000000000000FFFFFFFFFFFFFFFF"
    assert_equal "9295B59BB384736E", cipher.update("0000000000000000")
  end

  def test_cipher_decrypt_des_cbc
    cipher = PolarSSL::Cipher.new("DES-CBC")
    cipher.decrypt
    cipher.key = "0123456789ABCDEF"
    cipher.iv  = "fedcba9876543210"
    assert_equal "37363534333231204E6F77206973207468652074696D6520",
      cipher.update("CCD173FFAB2039F4ACD8AEFDDFD8A1EB468E91157888BA68")
  end

  def test_cipher_decrypt_des_ecb
    cipher = PolarSSL::Cipher.new("DES-ECB")
    cipher.decrypt
    cipher.key = "0123456789ABCDEF"
    assert_equal "1111111111111111", cipher.update("17668DFC7292532D")
  end

  def test_cipher_decrypt_3des_cbc
    cipher = PolarSSL::Cipher.new("DES3-CBC")
    cipher.decrypt
    cipher.key = "0123456789abcdeff1e0d3c2b5a49786fedcba9876543210"
    cipher.iv  = "fedcba9876543210"
    assert_equal "37363534333231204E6F77206973207468652074696D6520",
      cipher.update("3FE301C962AC01D02213763C1CBD4CDC799657C064ECF5D4")
  end

  def test_cipher_decrypt_3des_ecb
    cipher = PolarSSL::Cipher.new("DES3-ECB")
    cipher.decrypt
    cipher.key = "0000000000000000FFFFFFFFFFFFFFFF"
    assert_equal "0000000000000000", cipher.update("9295B59BB384736E")
  end
end

if $ok_test
  MTest::Unit.new.mrbtest
else
  MTest::Unit.new.run
end

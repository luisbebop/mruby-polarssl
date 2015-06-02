
class EcdsaTest < MTest::Unit::TestCase
  def setup
    @e = nil
    @pem = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIFFDAmjPwMim1/VD/7ZUvzHPSObhfG9BZkwnke7bjwUgoAcGBSuBBAAK\noUQDQgAEJcd0GkIscqqrmLg0bYr0WHZ2EABICLFZtnG7JuVPk2DuVTYxs9dHXpsh\njEzhJ1U+ictJAvHbh+A2IC64lO5oFQ==\n-----END EC PRIVATE KEY-----\n"
  end

  def test_ctr_drbg_pers
    begin
      entropy = PolarSSL::Entropy.new
      ctrdrbg = PolarSSL::CtrDrbg.new(entropy, "ecdsa")
      assert_equal "ecdsa", ctrdrbg.pers
    rescue => @e
    end
    assert_nil @e
  end

  def test_class
    assert_equal Class, PolarSSL::PKey::EC.class
  end

  def test_not_raise_on_initialize
    begin
      PolarSSL::PKey::EC.new
    rescue => @e
    end
    assert_nil @e
  end

  def test_init_by_pem
    begin
      PolarSSL::PKey::EC.new(@pem)
    rescue => @e
    end
    assert_nil @e
  end

  def test_generate_key
    begin
      key = PolarSSL::PKey::EC.new
      assert key.generate_key
    rescue => @e
    end
    assert_nil @e
  end

  def test_generate_key_get_public_key
    begin
      key = PolarSSL::PKey::EC.new
      assert key.generate_key
      pubkey = key.public_key
    rescue => @e
    end
    assert_nil @e
    assert_instance_of String, pubkey
  end

  def test_ec_key_from_pem
    begin
      PolarSSL::PKey::EC.new(@pem)
    rescue => @e
    end
    assert_nil @e
  end

  # @key.public_key.to_bn.to_s(16)
  def test_public_key_bn_16_from_pem
    assert_equal "0325C7741A422C72AAAB98B8346D8AF458767610004808B159B671BB26E54F9360", PolarSSL::PKey::EC.new(@pem).public_key
  end

  # @key.private_key.to_int.to_s(16)
  def test_private_key_to_s_16_from_pem
    assert_equal "51430268CFC0C8A6D7F543FFB654BF31CF48E6E17C6F41664C2791EEDB8F0520", PolarSSL::PKey::EC.new(@pem).private_key
  end

  def test_private_key_to_s_16_from_pem
    begin
      key = PolarSSL::PKey::EC.new(@pem)
      @sig = key.sign("1234")
    rescue => @e
    end
    assert_nil @e
    assert_not_equal nil,  @sig
    assert_instance_of String, @sig
  end
end

if $ok_test
  MTest::Unit.new.mrbtest
else
  MTest::Unit.new.run
end



class EcdsaTest < MTest::Unit::TestCase
  def test_class
    assert_equal Class, PolarSSL::ECDSA.class
  end

  def test_not_raise_on_initialize
    exception = nil
    begin
      PolarSSL::ECDSA.new
    rescue => exception
    end
    assert_nil exception
  end
end

if $ok_test
  MTest::Unit.new.mrbtest
else
  MTest::Unit.new.run
end


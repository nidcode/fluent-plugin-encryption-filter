require 'helper'

class EncryptionFilterTest < Test::Unit::TestCase
  include Fluent

  def setup
    Fluent::Test.setup
  end

  CONFIG = %[
    passphrase 'password'
    field 'msg1'
    algorithm 'aes-256-cbc'
  ]

  def create_driver(conf = '')
    Test::FilterTestDriver.new(EncryptionFilter).configure(conf, true)
  end

  def test_configure
    assert_raise(Fluent::ConfigError) {
      d = create_driver('')
    }

    d = create_driver %[
      passphrase 'password'
      field 'msg1'
    ]

    assert_equal 'password', d.instance.passphrase
    assert_equal 'msg1', d.instance.field
  end

end

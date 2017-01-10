# -*- coding: utf-8 -*-
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

  def create_driver(conf = '', mode = '')
    case mode
      when 'enc'
      Test::FilterTestDriver.new(EncryptionFilter).configure(conf, true)
      when 'dec'
      Test::FilterTestDriver.new(DecryptionFilter).configure(conf, true)
    else
      raise "mode error #{mode}"
    end
  end

  def test_configure
    assert_raise(Fluent::ConfigError) {
      d = create_driver('', 'enc')
    }

    d = create_driver(CONFIG, 'enc')
    d2 = create_driver(CONFIG, 'dec')

    assert_equal 'aes-256-cbc', d.instance.algorithm
    assert_equal 'password', d.instance.passphrase
    assert_equal 'msg1', d.instance.field

    assert_equal 'aes-256-cbc', d2.instance.algorithm
    assert_equal 'password', d2.instance.passphrase
    assert_equal 'msg1', d2.instance.field
  end

  def filter(config, msgs, mode)
    d = create_driver(config, mode)
    d.run {
      msgs.each {|msg|
        d.filter(msg, @time) # Filterプラグインにメッセージを通す
      }
    }
    filtered = d.filtered_as_array # 結果を受け取る. [tag, time, record]の配列
    filtered.map {|m| m[2] } # record だけ返す
  end

  def test_filter
    # encryption test
    msg = {"plain" => "plain_text", "msg1" => "encrypt_text"}
    encrypted = filter(CONFIG, [msg], 'enc')
    assert_equal(msg['plain'], encrypted[0]['plain'])
    assert_not_equal(msg['msg1'], encrypted[0]['msg1'])

    # decryption test
    msg2 = {"plain" => "plain_text", "msg1" => encrypted[0]['msg1']}
    decrypted = filter(CONFIG, [msg2], 'dec')
    assert_equal(msg['plain'], decrypted[0]['plain'])
    assert_not_equal(encrypted[0]['msg1'], decrypted[0]['msg1'])
    assert_equal(msg['msg1'], decrypted[0]['msg1'])
  end
end

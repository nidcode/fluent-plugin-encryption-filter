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

  def create_driver(conf = '')
    Test::FilterTestDriver.new(EncryptionFilter).configure(conf, true)
  end

  def test_configure
    assert_raise(Fluent::ConfigError) {
      d = create_driver('')
    }

    d = create_driver(CONFIG)

    assert_equal 'aes-256-cbc', d.instance.algorithm
    assert_equal 'password', d.instance.passphrase
    assert_equal 'msg1', d.instance.field
  end

  def filter(config, msgs)
    d = create_driver(config)
    d.run {
      msgs.each {|msg|
        d.filter(msg, @time) # Filterプラグインにメッセージを通す
      }
    }
    filtered = d.filtered_as_array # 結果を受け取る. [tag, time, record]の配列
    filtered.map {|m| m[2] } # record だけ返す
  end

  def test_filter
    msg = {"plain" => "plain_text", "msg1" => "encrypt_text"}
    filtered = filter(CONFIG, [msg])
    assert_equal(msg['plain'], filtered[0]['plain'])
    #TODO encryption test
  end
end

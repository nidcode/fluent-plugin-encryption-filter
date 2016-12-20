require_relative '../helper'
require 'fluent/test/driver/filter'
require 'fluent/plugin/filter_encryption'

class EncryptionFilterTest < Test::Unit::TestCase
  include Fluent

  setup do
    Test.setup
    @time = Fluent::Engine.now
  end

  def create_driver(conf = '')
    Test::FilterTestDriver.new(EncryptionFilter).configure(conf, true)
  end

  def filter(config, msgs)
    d = create_driver(config)
    d.run {
      msgs.each {|msg|
        d.filter(msg, @time)
      }
    }
    filtered = d.filtered_as_array
    filtered.map {|m| m[2] }
  end

  sub_test_case 'configure' do
    test 'check default' do
      assert_nothing_raised { create_driver }
    end
  end

  sub_test_case 'filter' do
    test 'encryption' do
      msg = {"message" => "foo"}
      filtered = filter('', [msg])
      assert_equal([msg,msg],filtered)
    end
  end
end

require 'fluent/filter'
require 'digest/md5'
require 'encryptor'

module Fluent
  class EncryptionFilter < Filter
    Fluent::Plugin.register_filter('encryption', self)
    config_param :passphrase, :string, secret: true
    config_param :field, :string, default: 'ALL'
    def configure(conf)
      super
    end
    
    def start
      super
      @key = Digest::SHA256.hexdigest("#{@passphrase}")
      @iv = Digest::SHA256.hexdigest("#{@key}#{@passphrase}")
    end

    def shutdown
      super
    end

    def filter(tag, time, record)
      @salt = OpenSSL::Random.random_bytes(8)
      fields = @field.split(',')
      record.map {|k, v|
        if check_encfield(k, fields)
          encrypted_value = @salt + Encryptor.encrypt(value: v, key: @key, iv: @iv, salt: @salt)
          [k, "#{encrypted_value}"]
        else
          [k, v]
        end
      }.to_h
    end

    def check_encfield(field, enc_fld_list)
      if @field == 'ALL'
        return true
      else
        return enc_fld_list.include?(field)
      end
    end
  end if defined?(Filter) # Support only >= v0.12
end

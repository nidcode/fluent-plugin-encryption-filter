require 'fluent/filter'
require 'digest/md5'
require 'encryptor'
require 'base64'

module Fluent
  class DecryptionFilter < Filter
    Fluent::Plugin.register_filter('decryption', self)
    config_param :passphrase, :string, secret: true
    config_param :field, :string, default: 'ALL'
    config_param :algorithm, :string, default: 'aes-256-cbc'
    
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
      fields = @field.split(',')
      record.map {|k, v|
        if check_encfield(k, fields)
          uv = Base64.decode64(v)
          salt = uv[0,8]
          encrypted_text = uv[8, uv.size]
          [k, Encryptor.decrypt(algorithm: @algorithm, value: encrypted_text, key: @key, iv: @iv, salt: salt)]
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

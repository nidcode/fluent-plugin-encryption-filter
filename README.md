# Fluent::Plugin::Encryption::Filter

Fluentd filter plugin to encrypt/decrypt fluentd messages

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'fluent-plugin-encryption-filter'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install fluent-plugin-encryption-filter

## Configuration
### Encryption
```
<filter encrypt.**>
  @type encryption
  passphrase 'password'
  algorithm 'aes-256-cbc'
  field 'field1'
</filter>
```

### Decryption
```
<filter decrypt.**>
  @type decryption
  passphrase 'password'
  algorithm 'aes-256-cbc'
  field 'field1'
</filter>
```

### Parameters
passphrase: String
algorithm: String
field: String

## Development
To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nidcode/fluent-plugin-encryption-filter. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](contributor-covenant.org) code of conduct.


## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).


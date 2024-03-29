# Digest::Cmac

Copied from https://github.com/quadule/digest-cmac since it's not a gem.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'digest-cmac'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install digest-cmac

## Usage

A Ruby implementation of the CMAC / OMAC1 digest algorithm, based on RFC 4493:
http://tools.ietf.org/html/rfc4493

Here's an example using a test vector from the RFC:

# key is 128 bits
key = ["2b7e151628aed2a6abf7158809cf4f3c"].pack('H*')

cmac = Digest::CMAC.new(OpenSSL::Cipher::Cipher.new('aes-128-cbc'), key)
cmac.update(["6bc1bee22e409f96e93d7e117393172a"].pack('H*'))
digest = cmac.digest

# unpack it into hex
digest.unpack('H*')[0] # => '070a16b46b4d4144f79bdd9dd04a287c'

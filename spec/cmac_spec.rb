require 'spec_helper'
require 'openssl'

describe 'CMAC' do
  let(:cipher) { OpenSSL::Cipher::Cipher.new('aes-128-cbc') }
  let(:cmac) { Digest::CMAC.new(cipher, ['2b7e151628aed2a6abf7158809cf4f3c'].pack('H*')) }

  let(:l_subkey) { cmac.instance_variable_get('@l') }
  let(:lu_subkey) { cmac.instance_variable_get('@lu') }
  let(:lu2_subkey) { cmac.instance_variable_get('@lu2') }

  it 'subkey l' do
    expect('7df76b0c1ab899b33e42f047b91b546f').to eq(l_subkey.unpack('H*')[0])
  end

  it 'subkey lu' do
    expect('fbeed618357133667c85e08f7236a8de').to eq(lu_subkey.unpack('H*')[0])
  end

  it 'subkey lu2' do
    expect('f7ddac306ae266ccf90bc11ee46d513b').to eq(lu2_subkey.unpack('H*')[0])
  end

  it 'empty string' do
    cmac.update('')
    expect('bb1d6929e95937287fa37d129b756746').to eq(cmac.digest.unpack('H*')[0])
  end

  it '16 bytes' do
    cmac.update(['6bc1bee22e409f96e93d7e117393172a'].pack('H*'))
    expect('070a16b46b4d4144f79bdd9dd04a287c').to eq(cmac.digest.unpack('H*')[0])
  end

  it '32 bytes chunked' do
    cmac.update(['6bc1be'].pack('H*'))
    cmac.update(['e22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e'].pack('H*'))
    cmac.update(['51'].pack('H*'))
    expect('ce0cbf1738f4df6428b1d93bf12081c9').to eq(cmac.digest.unpack('H*')[0])
  end

  it '40 bytes' do
    cmac.update(['6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411'].pack('H*'))
    expect('dfa66747de9ae63030ca32611497c827').to eq(cmac.digest.unpack('H*')[0])
  end

  it '64 bytes' do
    cmac.update(['6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710'].pack('H*'))
    expect('51f0bebf7e3b9d92fc49741779363cfe').to eq(cmac.digest.unpack('H*')[0])
  end
end

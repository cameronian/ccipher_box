
require_relative '../lib/ccipher_box/mem_key'

RSpec.describe CcipherBox::MemKey do

  it 'perform data enc and dec on given key' do
  
    sk = SecureRandom.random_bytes(16)

    mk = CcipherBox::MemKey.new(sk)
    enc = mk.encrypt("testing 123")
    expect(enc).not_to be nil

    mk2 = CcipherBox::MemKey.new(sk)
    plain = mk2.decrypt(enc)
    expect(plain == "testing 123").to be true

  end

  it 'performs data enc and dec on given SymKey object' do
    
    sk = CcipherFactory::SymKeyGenerator.generate(:aes, 256)

    data = SecureRandom.random_bytes(128)
    mk = CcipherBox::MemKey.new(sk)
    enc = mk.encrypt(data)
    expect(enc).not_to be nil

    mk2 = CcipherBox::MemKey.new(sk)
    plain = mk2.decrypt(enc)
    expect(plain == data).to be true

  end

  it 'performs data enc and dec on given SymKey derive object' do
    
    sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    data = SecureRandom.random_bytes(128)
    mk = CcipherBox::MemKey.new(sk)
    enc = mk.encrypt(data)
    expect(enc).not_to be nil

    mk2 = CcipherBox::MemKey.new(sk)
    plain = mk2.decrypt(enc)
    expect(plain == data).to be true

  end

  it 'generates same key ID for same input key' do
  
    sk = SecureRandom.random_bytes(16)

    puts "SK 1 : #{sk.inspect}"
    mk = CcipherBox::MemKey.new(sk)
    expect(mk.keyID).not_to be nil

    puts "SK 2 : #{sk.inspect}"
    mk2 = CcipherBox::MemKey.new(sk)
    if mk2.keyID != mk.keyID
      puts "mk keyID : #{mk.keyID}"
      puts "mk2 keyID : #{mk2.keyID}"
    end
    expect(mk2.keyID == mk.keyID).to be true

  end


end

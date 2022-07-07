

RSpec.describe CcipherBox::SecureRing do

  before {
    @comp = Ccrypto::UtilFactory.instance(:comparator)
  }

  it 'initialize new ring, persist and load back from storage' do
  
    ring = CcipherBox::SecureRing.new
    expect(ring).not_to be nil

    ring.generate_key("opsKey1", { algo: :aes, keysize: 256 })
    expect(ring.is_key_registered?("opsKey1")).to be true

    bin = ring.encoded
    expect(bin.nil?).to be false
    expect(bin.length == 0).to be false

    rring = CcipherBox::SecureRing.from_encoded(bin)
    expect(rring.is_key_registered?("opsKey1")).to be true

  end

  it 'initialize, persist and load back from storage and perform encryption & decryption' do
  
    data = SecureRandom.random_bytes(1000)

    eng = CcipherBox::SecureRing.new
    expect(eng).not_to be nil

    eng.generate_key("opsKey1", { algo: :aes, keysize: 256 })
    expect(eng.is_key_registered?("opsKey1")).to be true

    eng.generate_key("opsKey2", { algo: :aes, keysize: 256 })
    expect(eng.is_key_registered?("opsKey2")).to be true

    enc = eng.new_encryption_engine("opsKey1")
    out = MemBuf.new
    enc.init(out)
    enc.update(data)
    enc.final

    bin = eng.encoded
    expect(bin.nil?).to be false
    expect(bin.length == 0).to be false

    reng = CcipherBox::SecureRing.from_encoded(bin)
    expect(reng.is_key_registered?("opsKey1")).to be true
    expect(reng.is_key_registered?("opsKey2")).to be true

    dec = reng.new_decryption_engine
    dout = MemBuf.new
    dec.init(dout)
    dec.update(out.bytes)
    dec.final

    expect(@comp.is_equals?(dout.bytes, data)).to be true

    reng.dispose_key("opsKey1")
    expect(reng.is_key_registered?("opsKey1")).to be false

    expect {
      dec2 = reng.new_decryption_engine
      dout2 = MemBuf.new
      dec2.init(dout2)
      dec2.update(out.bytes)
      dec2.final
    }.to raise_exception(CcipherBox::KeyNotRegistered)

  end

  it 'accepts encrypt with multiple registered key within same ring' do
  
    data = SecureRandom.random_bytes(1000)

    eng = CcipherBox::SecureRing.new
    expect(eng).not_to be nil

    eng.generate_key("opsKey1", { algo: :aes, keysize: 256 })
    expect(eng.is_key_registered?("opsKey1")).to be true

    eng.generate_key("opsKey2", { algo: :aes, keysize: 256 })
    expect(eng.is_key_registered?("opsKey2")).to be true

    enc = eng.new_encryption_engine("opsKey1","opsKey2")
    out = MemBuf.new
    enc.init(out)
    enc.update(data)
    enc.final

    bin = eng.encoded
    expect(bin.nil?).to be false
    expect(bin.length == 0).to be false

    reng = CcipherBox::SecureRing.from_encoded(bin)
    expect(reng.is_key_registered?("opsKey1")).to be true
    expect(reng.is_key_registered?("opsKey2")).to be true

    # decrypt with opsKey1
    dec = reng.new_decryption_engine
    dout = MemBuf.new
    dec.init(dout)
    dec.update(out.bytes)
    dec.final

    expect(@comp.is_equals?(dout.bytes, data)).to be true

    reng.dispose_key("opsKey1")
    expect(reng.is_key_registered?("opsKey1")).to be false

    # decrypt with opsKey2
    dec2 = reng.new_decryption_engine
    dout2 = MemBuf.new
    dec2.init(dout2)
    dec2.update(out.bytes)
    dec2.final

  end


end

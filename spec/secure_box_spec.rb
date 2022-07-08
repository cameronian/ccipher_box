

RSpec.describe CcipherBox::SecureBox do

  before {
    @comp = Ccrypto::UtilFactory.instance(:comparator)
  }

  it 'generates simple engine and protect with securebox' do
    
    data = SecureRandom.random_bytes(2000)

    ring = CcipherBox::SecureRing.new
    expect(ring).not_to be nil

    ring.name = "master ring"

    ring.generate_key("opsKey1", { algo: :aes, keysize: 256 })
    ring.generate_key("opsKey2", { algo: :aes, keysize: 256 })

    enc = ring.new_encryption_engine("opsKey1")
    out = MemBuf.new
    enc.init(out)
    enc.update(data)
    enc.final

    sb = CcipherBox::SecureBox.new
    sb.add_ring(ring)

    sbout = sb.to_storage do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    rsb = CcipherBox::SecureBox.load_storage(sbout) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    reng = rsb.rings.first[1]
    dec = reng.new_decryption_engine
    dout = MemBuf.new
    dec.init(dout) 
    dec.update(out.bytes)
    dec.final

    expect(@comp.is_equals?(dout.bytes, data)).to be true

    expect{
      rsb2 = CcipherBox::SecureBox.load_storage(sbout) do |ops|
        case ops
        when :password
          "p@ssw0rd123"
        end
      end
    }.to raise_exception(CcipherBox::SecureBoxDecryptionError)

  end

  it 'generates securebox with implicit ring management' do
    
    data = SecureRandom.random_bytes(2000)

    enc = subject.encryption_session("FirstRing/opsKey1", { algo: :aes, keysize: 256 })

    enc = subject.encryption_session("FirstRing/opsKey2", { algo: :aes, keysize: 256 })
    out = MemBuf.new
    enc.init(out)
    enc.update(data)
    enc.final

    # 
    # Persist the SecureBox
    #
    sbout = subject.to_storage do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    # 
    # load from storage
    #
    rsb = subject.class.load_storage(sbout) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    dout = rsb.decrypt(out.bytes)
    expect(@comp.is_equals?(dout, data)).to be true

    dec = rsb.decryption_session("FirstRing")
    dout2 = MemBuf.new
    dec.init(dout2)
    dec.update(out.bytes)
    dec.final
    expect(@comp.is_equals?(dout2.bytes, data)).to be true

    expect {
      rsb.decryption_session("NoneExistingRing")
    }.to raise_exception(CcipherBox::SecureRingNotExist)

    expect{
      rsb2 = subject.class.load_storage(sbout) do |ops|
        case ops
        when :password
          "p@ssw0rd123"
        end
      end
    }.to raise_exception(CcipherBox::SecureBoxDecryptionError)

  end

  it 'generates securebox with multiple rings' do
    
    data = SecureRandom.random_bytes(2000)

    extRing = CcipherBox::SecureRing.new({ name: "External" })
    extRing.generate_key("backup", { algo: :aes, keysize: 256 })

    subject.add_ring(extRing)

    ext2 = CcipherBox::SecureRing.new({ name: "Dinner" })
    ext2.generate_key("Hush", { algo: :aes, keysize: 256 })
    subject.add_ring(ext2)

    enc = subject.init_ring("FirstRing/opsKey1", { algo: :aes, keysize: 256 })
    enc = subject.init_ring("FirstRing/opsKey2", { algo: :aes, keysize: 256 })

    enc = subject.encryption_session("FirstRing/opsKey2", "External/backup", {}) # { auto_create_ring: false })
    out = MemBuf.new
    enc.init(out)
    enc.update(data)
    enc.final

    # 
    # Persist the SecureBox
    #
    sbout = subject.to_storage do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    # 
    # load from storage
    #
    rsb = subject.class.load_storage(sbout) do |ops|
      case ops
      when :password
        "p@ssw0rd"
      end
    end

    dout = rsb.decrypt(out.bytes)
    expect(@comp.is_equals?(dout, data)).to be true

    dec = rsb.decryption_session("FirstRing")
    dout2 = MemBuf.new
    dec.init(dout2)
    dec.update(out.bytes)
    dec.final
    expect(@comp.is_equals?(dout2.bytes, data)).to be true

    dec2 = rsb.decryption_session("External")
    dout3 = MemBuf.new
    dec2.init(dout3)
    dec2.update(out.bytes)
    dec2.final
    expect(@comp.is_equals?(dout3.bytes, data)).to be true

    expect {

      dec2 = rsb.decryption_session("Dinner")
      dout3 = MemBuf.new
      dec2.init(dout3)
      dec2.update(out.bytes)
      dec2.final

    }.to raise_exception(CcipherBox::KeyNotRegistered)

  end


end

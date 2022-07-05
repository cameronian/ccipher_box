

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

    reng = rsb.rings.first
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
    }.to raise_exception(CcipherFactory::SymKeyDecryptionError)

  end

end

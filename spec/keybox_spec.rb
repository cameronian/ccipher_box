

RSpec.describe CcipherBox::Keybox do

  it 'derive from random' do
    
    key = SecureRandom.random_bytes(16)

    CcipherFactory::KDF.supported_kdf_algo.each do |kdf|

      puts
      kb = CcipherBox::Keybox.new
      kb.baseMat = key
      kb.outBitLength = 256
      kb.kdf = kdf

      dkey = kb.dkey

      bin = kb.encoded

      box = CcipherBox::Keybox.from_encoded(bin)
      box.baseMat = key

      comp = Ccrypto::UtilFactory.instance(:comparator)
      expect(comp.is_equals?(dkey, box.dkey)).to be true

    end

  end

end

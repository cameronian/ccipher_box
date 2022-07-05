

module CcipherBox
  
  # 
  # SecureBox is a secure container protected by user password
  # which has multiple SecureRings (crypto configurations)
  #
  class SecureBox
    include TR::CondUtils

    attr_accessor :rings

    def initialize(rings = nil)
      @rings = rings || []
      @keyConfigs = []
    end

    def add_ring(ring)
      @rings << ring
    end

    def rings
      @rings.freeze
    end

    def to_storage(&block)
      
      raise CcipherBox::Error, "Block is required" if not block

      pass = block.call(:password)
      raise CcipherBox::Error, "Password is required" if is_empty?(pass)

      deriveLevel = block.call(:derive_level) || 2

      keyConfigs = []
      payload = pass
      (0..deriveLevel).each do |i|
        
        kb = Keybox.new
        kb.baseMat = payload
        kb.outBitLength = 256
        payload = kb.dkey 

        keyConfigs << kb.encoded
      end

      ringBin = []
      @rings.each do |e|
        ringBin << e.encoded
      end

      cboxes = BinStruct.instance.struct(:secure_rings)
      cboxes.secure_rings = ringBin

      sk = CcipherFactory::SymKeyGenerator.derive(:aes, payload.length*8)  do |ops|
        case ops
        when :password
          payload
        end
      end

      keyConfigs << sk.encoded

      enc = CcipherFactory::SymKeyCipher.att_encryptor
      intOut = MemBuf.new
      enc.output(intOut)
      enc.key = sk
      enc.att_encrypt_init
      enc.att_encrypt_update(cboxes.encoded)
      enc.att_encrypt_final

      st = BinStruct.instance.struct(:securebox) 
      st.keyConfigs = keyConfigs
      st.engines = intOut.bytes
      st.encoded

    end

    def self.load_storage(bin, &block)
      
      raise CcipherBox::Error, "Block is required" if not block

      pass = block.call(:password)
      raise CcipherBox::Error, "Password is required" if is_empty?(pass)

      st = BinStruct.instance.struct_from_bin(bin)
      payload = pass
      st.keyConfigs[0..-2].each do |kc|
        kb = Keybox.from_encoded(kc)
        kb.baseMat = payload
        payload = kb.dkey
      end

      sk = CcipherFactory::SymKey.from_encoded(st.keyConfigs[-1]) do |ops|
        case ops
        when :password
          payload
        end
      end

      dec = CcipherFactory::SymKeyCipher.att_decryptor
      intOut = MemBuf.new
      dec.output(intOut)
      dec.key = sk
      dec.att_decrypt_init
      dec.att_decrypt_update(st.engines)
      dec.att_decrypt_final

      cboxes = BinStruct.instance.struct_from_bin(intOut.bytes)
      rings = []
      cboxes.secure_rings.each do |cb|
        rings << CcipherBox::SecureRing.from_encoded(cb)
      end

      SecureBox.new(rings)

    end

  end
end

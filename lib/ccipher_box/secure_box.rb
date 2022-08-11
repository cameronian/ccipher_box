

module CcipherBox
 

  # 
  # SecureBox is a secure container protected by user password
  # which has multiple SecureRings (crypto configurations)
  #
  class SecureBox
    include TR::CondUtils

    attr_accessor :rings

    def initialize(rings = nil)
      @rings = {  }
      @keyConfigs = []
      if not_empty?(rings)
        rings.each do |r|
          @rings[r.name] = r
        end
      end
    end

    ##
    # SecureRing management
    #
    # Allow external created ring
    def add_ring(ring)
      @rings[ring.name] = ring
    end

    def remove_ring(ring_name)
      @rings.delete(ring_name)
    end

    def rings
      @rings.freeze
    end

    def init_ring(spec, opts = {  })
     
      ss = split_encryption_spec(spec)

      ring = find_ring(ss[0], opts)
      ring.generate_key(ss[1], opts) if not ring.is_key_registered?(ss[1])
      ring

    end

    # Implicit SecureRing management
    #
    # Encryption in chunk
    #
    def encryption_session(*specs, &block)

      opts = block.call(:options) if block
      opts = {  } if opts.nil?

      keys = []
      specs.each do |spec|
        ss = split_encryption_spec(spec)
        ringName = ss[0]
        keyName = ss[1]
        ring = find_ring(ringName, opts) 
        ring.generate_key(keyName, opts) if not ring.is_key_registered?(keyName)
        keys << ring.get_key(keyName)
      end

      #puts "Encryption key : #{keys}"
      EncryptionEngine.new(*keys)
    end

    # 
    # Decryption in chunk
    #
    def decryption_session(ringName)
      ring = find_ring(ringName, { auto_create_ring: false }) 
      ring.new_decryption_engine
    end

    # 
    # Single line encryption
    #
    def encrypt(data, *specs, &block)

      opts = block.call(:options) if block
      opts = {  } if opts.nil?

      keys = []
      specs.each do |spec|
        ss = split_encryption_spec(spec)
        ringName = ss[0]
        keyName = ss[1]
        ring = find_ring(ringName, opts) 
        if not ring.is_key_registered?(keyName)
          ring.generate_key(keyName, opts)
          block.call(:new_key_generated) if block
        end
        keys << ring.get_key(keyName)
      end

      eng = EncryptionEngine.new(*keys)
      intBuf = MemBuf.new
      eng.init(intBuf)
      eng.update(data)
      eng.final

      res = intBuf.bytes.clone
      intBuf.dispose

      res
      
    end

    # 
    # Single line decryption
    #
    def decrypt(bin, &block)

      raise CcipherBox::Error, "No SecureRing is laoded" if is_empty?(@rings)

      intBuf = false
      if block
        output = block.call(:output) 
      end

      if output.nil?
        intBuf = true
        output = MemBuf.new
      end
    
      res = nil
      lastEx = nil
      @rings.values.each do |v|
        begin
          dec = v.new_decryption_engine
          dec.init(output)
          dec.update(bin)
          dec.final

          res = output.bytes.clone
          output.dispose

          break
        rescue KeyNotRegistered => ex
          lastEx = ex
        end
      end

      if intBuf
        raise KeyNotRegistered, "Decryption failed. #{lastEx.nil? ? "" : "(#{lastEx.message})"}" if res.nil?
        res
      else
        nil
      end

    end

    ## end SecureRing management
    

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
      @rings.values.each do |e|
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

      begin
        
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

      rescue CcipherFactory::SymKeyDecryptionError => ex
        raise SecureBoxDecryptionError, ex
      end

    end

    private
    def find_ring(ringName, opts = {  })
      
      raise SecureBoxError, "Ring name cannot be empty" if is_empty?(ringName)

      if not @rings.keys.include?(ringName) 
        autoCreate = opts[:auto_create_ring]
        autoCreate = true if is_empty?(autoCreate)
        if autoCreate
          logger.debug "auto_create_ring is true. Creating ring '#{ringName}'."
          ring = SecureRing.new({ name: ringName })
          @rings[ringName] = ring
        else
          logger.debug "auto_create_ring is false"
          raise SecureRingNotExist, "Ring '#{ringName}' does not exist and auto create is not active."
        end
      end

      @rings[ringName]
      
    end

    def split_encryption_spec(spec)
      ss = spec.split("/")
      raise SecureBoxEncryptionSpecError, "Spec requires to in format ring_name/key_name format" if ss.length != 2
      ss
    end

    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :secbox
      end
      @logger
    end

  end
end

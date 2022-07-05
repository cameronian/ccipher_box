

module CcipherBox
  
  # 
  # Actual data encryption key that is encrypted in memory
  # This class represents a single encryption key
  #
  class MemKey
    include TR::CondUtils

    class MemKeyException < Exception; end

    attr_accessor :name

    def initialize(key, name = nil)
      @dataConv = Ccrypto::UtilFactory.instance(:data_conversion)
      @dataComp = Ccrypto::UtilFactory.instance(:comparator)
      self.key = key
      self.name = name

      @activateCount = 0
    end

    def key=(val)
      generateKeyID(val)
      @key = mem_seal(val)
    end

    def keyID
      @keyID
    end

    # keyID is stored as binary in the structure
    # but was used as Hex value at application level
    def self.to_KeyID(val)
      Ccrypto::UtilFactory.instance(:data_conversion).to_hex(val)
    end

    # 
    # Encrypt by this key is generally consider key wrap
    # therefore data is not expected to be very big.
    #
    # This is not really going to encrypt the actual data 
    # since there might have multiple key involved during
    # data protection
    #
    def encrypt(data, &block)

      if block
        algo = block.call(:symkey_algo)
        keysize = block.call(:symkey_length)
        mode = block.call(:symkey_mode)
        output = block.call(:output)
      end

      algo = :aes if is_empty?(algo)
      keysize = 256 if is_empty?(keysize)
      mode = :gcm if is_empty?(mode)
      output = :binary if is_empty?(output)

      key = mem_unseal(@key)
      case key
      when CcipherFactory::SymKey
        sk = key
      else
        sk = CcipherFactory::SymKeyGenerator.derive(algo, keysize) do |k|
          case k
          when :password
            key
          end
        end
      end

      @activateCount += 1
      # refresh the in-memory encryption
      if @activateCount > 5
        logger.debug "Seal refresh during encrypt ops"
        @key = mem_seal(@key) 
      end


      membuf = MemBuf.new
      enc = CcipherFactory::SymKeyCipher.att_encryptor
      enc.key = sk
      enc.mode = mode

      enc.output(membuf)
      enc.att_encrypt_init
      enc.att_encrypt_update(data)
      enc.att_encrypt_final

      encOut = membuf.bytes.clone
      membuf.dispose
      
      st = BinStruct.instance.struct(:cipher_envp)
      st.keyid = @dataConv.from_hex(self.keyID)
      sk.attach_mode
      st.keyConfig = sk.encoded
      st.cipher = encOut
      res = st.encoded

      case output
      when :hex
        @dataConv.to_hex(res)
      when :b64
        @dataConv.to_b64(res)
      else
        res
      end
      
    end

    def decrypt(bin, &block)
     
      st = BinStruct.instance.struct_from_bin(bin)
      st.keyid = @dataConv.to_hex(st.keyid)

      raise MemKeyException, "Given data to decrypt is not cipher envelope" if CBTag.value_constant(st.oid) != :cipher_envp
      raise MemKeyException, "Give cipher envelope is not meant for this key. Current key ID '#{self.keyID}' and key ID inside envelope '#{st.keyid}'" if not @dataComp.is_equals?(self.keyID, st.keyid)

      case @key
      when CcipherFactory::SymKey
        sk = @key
      else
        sk = CcipherFactory::SymKey.from_encoded(st.keyConfig) do |k|
          case k
          when :password
            mem_unseal(@key)
          end
        end
      end

      @activateCount += 1
      # refresh the in-memory protection
      if @activateCount > 5
        logger.debug "Seal refresh during decrypt ops"
        @key = mem_seal(@key) 
      end

      membuf = MemBuf.new
      dec = CcipherFactory::SymKeyCipher.att_decryptor
      dec.key = sk

      dec.output(membuf)
      dec.att_decrypt_init
      dec.att_decrypt_update(st.cipher)
      dec.att_decrypt_final

      plain = membuf.bytes.clone
      membuf.dispose

      if block
        output = block.call(:output)
      end
      output = :binary if is_empty?(output)
      
      case output
      when :hex
        @dataConv.to_hex(plain)
      when :b64
        @dataConv.to_b64(plain)
      else
        plain
      end

    end

    #def derive(algo = :script)
    #  kb = Keybox.new(algo)
    #  kb.baseMat = mem_unseal(@key)
    #  kb
    #end

    def encoded
      st = BinStruct.instance.struct(:mem_key)
      st.value = mem_unseal(@key)
      st.encoded
    end

    private
    # Encrypt the actual key resides in memory
    def mem_seal(key)

      supported = CcipherFactory::SymKeyGenerator.supported_symkey
      symAlgo = supported.keys
      # randomly select which algo to start for in memory protection
      startIndx = rand(0..symAlgo.length-1)
      loopCnt = 0

      logger.debug "Total supported symkey algo : #{symAlgo.length}"
      
      indx = startIndx
      
      case key
      when CcipherFactory::SoftSymKey
        logger.debug "Given key to seal is Soft SymKey"
        payload = key.key.key
      when CcipherFactory::DerivedSymKey
        logger.debug "Given key to seal is Derived SymKey"
        payload = key.key
      else
        logger.debug "Given key to seal is native key"
        payload = key
      end

      loop do
       
        algo = symAlgo[indx]
        ks = supported[algo][:keysize][-1] 
        mode = supported[algo][:mode][-1]

        logger.debug "Utilizing symkey at index : #{indx} - #{algo}/#{ks}/#{mode}"
        sk = CcipherFactory::SymKeyGenerator.generate(algo, ks)

        #logger.debug "Generated key #{loopCnt} : #{sk.inspect}"

        enc = CcipherFactory::SymKeyCipher.att_encryptor
        enc.key = sk
        enc.mode = mode
        
        membuf = MemBuf.new
        enc.output(membuf)

        enc.att_encrypt_init
        enc.att_encrypt_update(payload)
        enc.att_encrypt_final

        sk.attach_mode
        encRes = membuf.bytes.clone
        membuf.dispose

        #logger.debug "Encrypted #{loopCnt} : #{encRes.inspect}"

        st = BinStruct.instance.struct(:mem_key_layer)
        st.material = sk.encoded
        st.payload = encRes
        payload = st.encoded

        indx = ((indx+1) % symAlgo.length)

        loopCnt += 1
        break if loopCnt >= symAlgo.length

      end

      kkey = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |k|
        case k
        when :password
          case key
          when CcipherFactory::SoftSymKey
            # SymKey -> Ccrypto::SecretKey -> raw key
            key.key.key
          when CcipherFactory::DerivedSymKey
            key.key
          else
            key
          end
        end
      end

      st = BinStruct.instance.struct(:mem_key_envp)
      
      kcv = CcipherFactory::KCV.new
      kcv.key = kkey

      st.kcv = kcv.encoded
      st.kcvconfig = kkey.encoded
      st.layer = payload
      st.encoded

    end

    # Decrypt the in-memory protected key for operational
    def mem_unseal(env)

      begin

        sti = BinStruct.instance.struct_from_bin(env)

        payload = sti.layer

        loop do

          st = BinStruct.instance.struct_from_bin(payload)

          break if st.nil?

          key = CcipherFactory::SymKey.from_encoded(st.material)
          #logger.debug "Unseal found : #{key.inspect}"

          encData = st.payload

          dec = CcipherFactory::SymKeyCipher.att_decryptor
          
          membuf = MemBuf.new
          dec.output(membuf)

          dec.key = key
          dec.att_decrypt_init
          dec.att_decrypt_update(encData)
          dec.att_decrypt_final

          payload = membuf.bytes.clone
          membuf.dispose

          #logger.debug "Decrypted payload : #{payload.inspect}"

        end
      rescue Binenc::BinencDecodingError => ex
        #STDERR.puts ex.message
      end

      #begin
      #  dkey = CcipherFactory::SymKey.from_encoded(payload)
      #rescue Binenc::BinencDecodingError => ex
        payload
      #end

    end

    def generateKeyID(key)
      
      if @keyID.nil? 

        if key.is_a?(CcipherFactory::SymKey)
          sk = key
        else
          sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |k|
            case k
            when :password
              key
            when :kdf
              :scrypt
            when :kdf_scrypt_cost
              65536
            when :kdf_scrypt_parallel
              1
            when :kdf_scrypt_blocksize
              8
            when :kdf_scrypt_salt
              @dataConv.from_hex("FEDCBA0123456789")
            when :kdf_scrypt_digestAlgo
              :sha3_256
            end
          end
        end

        kcv = CcipherFactory::KCV.new
        kcv.key = sk
        kcv.nonce = "8"*32
        kcvBin = kcv.encoded do |k|
          case k
          when :kcv_cipher_iv
            # given key (sk) is AES key with GCM mode (default if mode not given)
            # therefore the IV size has to be 12
            # Other algo this must be adjusted accordingly
            "1A2B3C4D5E6F"
          end
        end

        @keyID = @dataConv.to_hex(kcvBin)
      end

      @keyID

    end


    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :mem_key
      end
      @logger
    end

  end
end

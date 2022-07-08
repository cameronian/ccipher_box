
require 'tempfile'

module CcipherBox
  # 
  # Meant to encrypt large data
  #
  class EncryptionEngine
    include TR::CondUtils
   
    def initialize(*args)
      @keys = args
    end

    def init(output)
      raise CcipherBox::Error, "Output is mandatory" if output.nil?

      @output = output
      @baseMat = SecureRandom.random_bytes(256/8)
      @sk = CcipherFactory::SymKeyGenerator.derive(:aes, 256) do |ops|
        case ops
        when :password
          @baseMat
        end
      end

      @intOut = Tempfile.new

      @cipher = CcipherFactory::SymKeyCipher.encryptor
      @cipher.output(@intOut)
      @cipher.key = @sk
      @cipher.encrypt_init
    end

    def update(data)
      @cipher.encrypt_update(data) 
    end

    def final(&block)
      header = @cipher.encrypt_final

      st = BinStruct.instance.struct(:ccipherbox_cipher)
      st.keyConfig = @sk.encoded
     
      encBaseMat = []
      @keys.each do |k|
        #logger.debug "Encrypt with key #{k.name}"
        encBaseMat << k.encrypt(@baseMat)
      end
      st.baseMaterial = encBaseMat
      
      st.cipherConfig = header
      aheader = st.encoded

      @output.write(aheader)

      @intOut.rewind
      while not @intOut.eof?
        @output.write(@intOut.read)
      end

      @intOut.close
      @intOut.delete

      aheader
    end

    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :enc_eng
      end
      @logger
    end

  end
end

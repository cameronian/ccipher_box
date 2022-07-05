
require 'tempfile'

module CcipherBox
  class EncryptionEngine
    include TR::CondUtils
   
    def initialize(vault, keyID)
      @vault = vault
      @keyID = keyID
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
      st.baseMaterial = @vault.encrypt(@keyID, @baseMat, &block)
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

  end
end

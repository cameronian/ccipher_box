

module CcipherBox
  class DecryptionEngine
    include TR::CondUtils

    def initialize(vault)
      @vault = vault
    end

    def init(output)
       
      raise CcipherBox::Error, "Output is mandatory" if output.nil?

      @output = output
      @intOut = MemBuf.new

    end

    def update(data)
     
      if @dec.nil?
        @intOut.write(data)

        BinStruct.instance.find_struct(@intOut) do |meta, data|

          st = BinStruct.instance.struct_from_bin(meta)

          st.baseMaterial.each do |ebm|

            baseMat = @vault.decrypt(ebm)

            sk = CcipherFactory::SymKey.from_encoded(st.keyConfig) do |ops|
              case ops
              when :password
                baseMat
              end
            end

            @dec = CcipherFactory::SymKeyCipher.decryptor
            @dec.output(@output)
            @dec.key = sk
            @dec.decrypt_init

            @dec.decrypt_update_meta(st.cipherConfig)

            @dec.decrypt_update_cipher(data) if not_empty?(data)

            break
          end

        end

      else
        @dec.decrypt_update_cipher(data)
      end

    end

    def final
      @dec.decrypt_final 
    end

  end
end

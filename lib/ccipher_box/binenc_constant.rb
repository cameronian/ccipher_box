

if not defined?(CBTag)

  CBTag = Binenc::BinTag.new

  CBTag.load do

    # hierarchy
    define_constant(:root, '2.8.8.0') do
      define_constant(:mem_key_layer, "#.10")
      define_constant(:mem_key_envp, "#.11")

      define_constant(:cipher_envp, "#.20")

      define_constant(:keybox, "#.30") 

      define_constant(:secure_ring, "#.50") 
      define_constant(:secure_rings, "#.51") 

      define_constant(:ccipherbox, "#.80") do
        define_constant(:keyConfig, "#.1") 
        define_constant(:keyConfig_from_base, "#.2") 

        define_constant(:ccipherbox_cipher, "#.10") 
        define_constant(:ccipherboxes, "#.20") 
      end

      define_constant(:securebox, "#.90") 
    end

    # constant
    #define_constant(:sha1,         0x0101)

  end


end


require_relative 'encryption_engine'
require_relative 'decryption_engine'

require_relative 'enc_key_config'

module CcipherBox

  # 
  # SecureRing that carries a unique seed for data encryption and decryption
  # Typically SecureRing contains one key vault for data protection
  #
  # Different between SecureRing and MemVault is the encrypt/decrypt
  # function of MemVault only for limited data however for SecureRing
  # the data size is limited only by the algorithm limitation
  #
  class SecureRing
    include TR::CondUtils

    attr_accessor :name
    def initialize(opts = {  })

      @name = opts[:name] || "Genesis"

      @vault = MemVault.new(@name)

      # seed for data encryption key derivation
      @encSeed = opts[:encSeed] || SecureRandom.random_bytes(64)

      # keep link between encryption key config with a name
      @encKeyConfig = EncKeyConfig.new
      if not_empty?(opts[:encKeyConfig])
        conf = opts[:encKeyConfig].keyConfigs
        conf.each do |name, kc|
          regenerate_key(name, kc)
        end
      end
    end

    # generate new operation key for data encryption and decryption
    def generate_key(name, opts = {  })
      algo = opts[:algo] || :aes
      keysize = opts[:keysize] || 256

      sk = CcipherFactory::SymKeyGenerator.derive(algo, keysize) do |ops|
        case ops
        when :password
          @encSeed
        end
      end

      @vault.register(name, sk)
      @encKeyConfig.register_config(name, sk.encoded)
    end

    def dispose_key(name)
      @vault.deregister(name)
      self
    end

    def is_key_registered?(name)
      @vault.is_registered?(name)
    end

    def registered_keys
      @vault.keys.freeze
    end

    def get_key(name)
      @vault.get_key(name)
    end

    def new_encryption_engine(*keyNames)
      names = []
      keyNames.each do |name|
        raise KeyNotRegistered, "Key with name '#{name}' not registered" if not is_key_registered?(name)
        names << @vault.get_key(name)
      end
      EncryptionEngine.new(*names)
    end

    def new_decryption_engine
      DecryptionEngine.new(@vault)
    end

    def encoded
      st = BinStruct.instance.struct(:secure_ring)
      st.name = @name
      st.cipherSeed = @encSeed
      st.keyConfigs = @encKeyConfig.encoded
      st.encoded
    end

    def self.from_encoded(bin)
      st = BinStruct.instance.struct_from_bin(bin)
      encKeyConfig = EncKeyConfig.from_encoded(st.keyConfigs)
      SecureRing.new({ encSeed: st.cipherSeed, encKeyConfig: encKeyConfig, name: st.name })
    end

    private
    # regenerate key based on config loaded from external
    def regenerate_key(name, config)
      
      sk = CcipherFactory::SymKey.from_encoded(config[:config]) do |ops|
        case ops
        when :password
          if @encKeyConfig.is_derived_key?(config)
          else
            @encSeed
          end
        end
      end

      @vault.register(name, sk)

    end

    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :secure_ring
      end
      @logger
    end


  end
  
end

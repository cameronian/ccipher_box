
require_relative 'bin_struct'

require_relative 'mem_key'

module CcipherBox

  # Collection of crypto keys in a vault to be used by application.
  # Application can register a key that tie with a name here 
  # and later use the name to encrypt a data
  # This only store keys that will be kept in memory
  # Not meant to be persistance
  class MemVault
    include TR::CondUtils

    class MemVaultException < Exception; end

    def initialize(ring)
      @ring = ring
    end

    def register(name, key)
      @dataConv = Ccrypto::UtilFactory.instance(:data_conversion)
      vault[name] = MemKey.new(@ring, key, name)
      self
    end

    def deregister(name)
      vault.delete(name)
      self
    end

    def is_registered?(name)
      vault.keys.include?(name)
    end

    def encrypt(name, data, &block)
      key = vault[name]  
      key.encrypt(data, &block)
    end

    def decrypt(cipher)
      keyID = BinStruct.instance.struct_fields_from_bin(cipher, 2)[0]  
      keyID = MemKey.to_KeyID(keyID)

      foundKey = nil
      vault.values.each do |k|
        if k.keyID == keyID
          foundKey = k
          break
        end
      end

      if not_empty?(foundKey)
        logger.debug "Found decryption key with label #{vault.invert[foundKey]}"
        foundKey.decrypt(cipher)
      else
        raise KeyNotRegistered, "Encryption key for this cipher not registered (KeyID : #{keyID})"
      end

    end

    def derive(name)
      vault[name].derive
    end

    private
    # internal structure to bind the application given name
    # to a key.
    # This allow application to select which key to be used for
    # data protection
    def vault
      if @vault.nil?
        @vault = {  }
      end
      @vault
    end

    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :mem_vault
      end
      @logger
    end


  end
end



module CcipherBox

  # link between data encryption key name with their
  # respective key configs
  # In a specific configurations, there might be many
  # data encryption key and the key config to derive
  # the data encryption key from a base key is kept
  # here for later rebuild the same key again
  # Only used inside SecureRing
  class EncKeyConfig
    include TR::CondUtils

    def initialize
      @keyConfigs = {  }
    end

    def register_config(name, keyConfig)
      @keyConfigs[name] = { config: keyConfig }  
    end

    def register_derive_config(name, keyConfig, baseName, baseKeyConfig)
      @keyConfigs[name] = { config: keyConfig, base: baseName, baseConfig: baseKeyConfig } 
    end

    def keyConfigs
      @keyConfigs.freeze
    end

    def is_derived_key?(hash)
      not_empty?(hash[:base])
    end

    def encoded

      configs = []
      @keyConfigs.each do |name, val|

        if not_empty?(val[:base])
          st = BinStruct.instance.struct(:keyConfig_from_base)
          st.name = name
          st.keyConfig = val[:config]
          st.baseName = val[:base]
          st.baseKeyConfig = val[:baseConfig]
        else
          st = BinStruct.instance.struct(:keyConfig)
          st.name = name
          st.keyConfig = val[:config]
        end

        configs << st.encoded

      end

      configs

    end

    def self.from_encoded(seq)
     
      ekc = EncKeyConfig.new
      seq.each do |sst|
        st = BinStruct.instance.struct_from_bin(sst)
        case st.oid
        when CBTag.constant_value(:keyConfig)
          ekc.register_config(st.name, st.keyConfig)
        when CBTag.constant_value(:keyConfig_from_base)
          ekc.register_config(st.name, st.keyConfig, st.baseName, st.baseKeyConfig)
        end
      end

      ekc

    end

  end
end

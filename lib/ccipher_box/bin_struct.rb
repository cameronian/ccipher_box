
require 'singleton'
require_relative 'binenc_constant'

module CcipherBox
  class BinStruct
    include Singleton

    def struct(key, ver = "1.0")
      st = structure(ver)[key] 
      st.clone if not st.nil?
    end

    def struct_from_bin(bin)
      type, ver = struct_fields_from_bin(bin, 0, 1)
      c = CBTag.value_constant(type) 
      st = struct(c, translate_version(ver))
      st.from_bin(bin) if not st.nil?
    end

    def struct_fields_from_bin(bin, *args)
      Binenc::EngineFactory.instance(:bin_struct).value_from_bin_struct(bin, *args)
    end

    def find_struct(buf, &block)

      cpos = buf.pos

      begin

        #len = find_asn1_length(buf.string)
        len = Ccrypto::ASN1.engine.asn1_length(buf.bytes)
        #logger.debug "Found meta length : #{len}" if not logger.nil?
        raise InsufficientData if len == 0

        buf.rewind
        meta = buf.read(len)

        if block
          block.call(meta, buf.read(cpos-len))
        else
          meta
        end

        #rescue OpenSSL::ASN1::ASN1Error => ex
      rescue Ccrypto::ASN1EngineException => ex
        logger.error ex
        buf.seek(cpos)
        raise InsufficientData
      end
      
    end

    private
    def logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :binstruct
      end
      @logger
    end

    def structure(ver = "1.0")
      
      if @struct.nil?
        @struct = {  }

        @struct["1.0"] = {

          keybox: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:keybox)
            int :version, 0x0100
            bin :kdfConfig
          end,


          mem_key_layer: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:mem_key_layer)
            int :version, 0x0100
            bin :material
            bin :payload
          end,

          mem_key_envp: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:mem_key_envp)
            int :version, 0x0100
            bin :kcv
            bin :kcvconfig
            bin :layer
          end,

          ccipherbox_keywrap: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:ccipherbox_keywrap)
            int :version, 0x0100
            bin :keyid
            bin :keyConfig
            bin :cipher
          end,

          keyConfig: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:keyConfig)
            int :version, 0x0100
            str :name
            bin :keyConfig
          end,

          keyConfig_from_base: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:keyConfig_from_base)
            int :version, 0x0100
            str :name
            str :baseName
            bin :baseKeyConfig
            bin :keyConfig
          end,

          secure_ring: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:secure_ring)
            int :version, 0x0100
            str :name
            bin :cipherSeed
            seq :keyConfigs
          end,

          secure_rings: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:secure_rings)
            int :version, 0x0100
            seq :secure_rings
          end,



          ccipherbox_cipher: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:ccipherbox_cipher)
            int :version, 0x0100
            bin :keyConfig
            bin :baseMaterial
            bin :cipherConfig
          end,

          securebox: Binenc::EngineFactory.instance(:bin_struct).define do
            oid :oid, CBTag.constant_value(:securebox)
            int :version, 0x0100
            # ccipherboxes struct
            bin :engines 
            seq :keyConfigs
          end,


        }
      end

      @struct[ver]

    end

    def translate_version(ver)
      case ver.to_i
      when 0x0100
        "1.0"
      else
        raise Exception, "Version #{ver} is unknown"
      end
    end


  end
end

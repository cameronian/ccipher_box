
require 'ccipher_factory'

module CcipherBox

  # Abstraction of deriving a key from a given base key (baseMat)
  # and the Key Derivation Function (KDF).
  # With the two inputs, a derive key would be provided via dkey() API
  class Keybox
    include TR::CondUtils

    attr_accessor :outBitLength, :kdf, :baseMat

    def initialize(kdfEngine = nil)
      raise KeyboxException, "Instance of KDF engine (CcipherFactory::KDF::KDFEngine) required" if not_empty?(kdfEngine) and not kdfEngine.is_a?(CcipherFactory::KDF::KDFEngine)

      @kdfEng = kdfEngine
      if not @kdfEng.nil?
        @kdfOut = MemBuf.new
        @kdfEng.output(@kdfOut)
      end
    end

    def self.from_encoded(bin)
      
      raise KeyboxException, "Given binary is empty" if is_empty?(bin)

      st = BinStruct.instance.struct_from_bin(bin)
      kdfEng = CcipherFactory::KDF.from_encoded(st.kdfConfig)
      Keybox.new(kdfEng)

    end

    def baseMat=(val)

      case val
      when CcipherFactory::SymKey
        # taking the key value only will still can get
        # derived key correctly even if the key type and size
        # has changed. For example change from Blowfish to AES
        # will not resulted in a different value
        #
        # Decided to take only the raw key value to allow 
        # flexibility at upper application to change from a 
        # symmetric algo to another, since the objective of this
        # class is just to get a derived raw key, not SymKey object
        @baseMat = val.key

        # taking the encoded value however from symkey
        # will make the base key sensitive to meta data changes,
        # from key type, size, KDF config changes all will affect
        # final result
        #@baseMat = val.encoded
      #when String
      # test for String will means need a mechanism to test for Java::byte[]
      # which is not yet there
      #  @baseMat = val
      else
        @baseMat = val
        #raise KeyboxException, "Unsupported base material type '#{val}'"
      end

      @dkeyVal = nil
    end

    def dkey

      if @dkeyVal.nil?

        raise KeyboxException, "BaseMat not given" if is_empty?(@baseMat)

        kdfEng.derive_update(@baseMat)

        @kdfConfig = kdfEng.derive_final

        @dkeyVal = @kdfOut.bytes.clone
        @kdfOut.dispose

      end

      @dkeyVal

    end

    def encoded
      st = BinStruct.instance.struct(:keybox)
      st.kdfConfig = @kdfConfig
      st.encoded
    end

    private
    def kdfEng

      if @kdfEng.nil? 

        raise KeyboxException, "OutBitLength is not given" if is_empty?(@outBitLength)

        if @kdf.nil?

          # random KDF
          rEng = [:scrypt, :hkdf, :pbkdf2].sample
          logger.debug "Random KDF : #{rEng}"
          @kdfEng = CcipherFactory::KDF.instance(rEng)
          @kdfEng.outByteLength = @outBitLength/8

          @kdfOut = MemBuf.new
          @kdfEng.output(@kdfOut)
          @kdfEng.derive_init

        else

          case @kdf
          when :scrypt, :hkdf, :pbkdf2
            logger.debug "Given KDF : #{@kdf}"
            @kdfEng = CcipherFactory::KDF.instance(@kdf)
            @kdfEng.outByteLength = @outBitLength/8
          else
            raise KeyboxException, "Unknown KDF engine '#{@kdf}' requested"
          end

          @kdfOut = MemBuf.new
          @kdfEng.output(@kdfOut)
          @kdfEng.derive_init

        end # @kdf.nil?

      end # kdfEng.nil?

      @kdfEng

    end

    def self.logger
      if @logger.nil?
        @logger = TeLogger::Tlogger.new
        @logger.tag = :keybox
      end
      @logger
    end

    def logger
      self.class.logger
    end

  end
  
end

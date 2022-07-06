# frozen_string_literal: true

require_relative "ccipher_box/version"

require_relative 'ccipher_box/keybox'
require_relative 'ccipher_box/mem_vault'

require_relative 'ccipher_box/secure_box'
require_relative 'ccipher_box/secure_ring'

module CcipherBox
  class Error < StandardError; end

  class KeyboxException < StandardError; end
  class KeyboxRegisterException < StandardError; end
  class KeyNotRegistered < StandardError; end

  class InsufficientData < StandardError; end


  class SecureBoxError < StandardError; end
  class SecureBoxDecryptionError < StandardError; end
  class SecureRingNotExist < StandardError; end

  # Your code goes here...


end

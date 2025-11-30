# frozen_string_literal: true

require 'ffi'

module PolkadotSignatureVerifier
  extend FFI::Library

  # Load the library from the plugin's lib directory
  lib_path = File.expand_path('../../lib/verifier/libpolkadot_sig_verifier.so', __FILE__)

  unless File.exist?(lib_path)
    raise LoadError, "Could not find polkadot signature verifier library at: #{lib_path}"
  end

  ffi_lib lib_path

  # Attach the verification function
  # Returns 1 for valid, 0 for invalid
  attach_function :verify_polkadot_signature, [:string, :string, :string], :uint8
  attach_function :get_version, [], :string

  # Ruby-friendly wrapper
  # @param address [String] SS58-encoded Polkadot address
  # @param signature [String] Hex-encoded signature (with or without 0x prefix)
  # @param message [String] The original message that was signed
  # @return [Boolean] true if signature is valid, false otherwise
  def self.verify(address:, signature:, message:)
    result = verify_polkadot_signature(address, signature, message)
    result == 1
  rescue => e
    log_error("Verification failed: #{e.message}")
    false
  end

  # Check if the library loaded correctly
  def self.test_connection
    version = get_version
    log_info("Library v#{version} loaded successfully")
    true
  rescue => e
    log_error("Failed to connect to library: #{e.message}")
    false
  end

  private

  def self.log_info(message)
    Rails.logger.info("[PolkadotSignatureVerifier] #{message}") if defined?(Rails) && Rails.logger
  end

  def self.log_error(message)
    Rails.logger.error("[PolkadotSignatureVerifier] #{message}") if defined?(Rails) && Rails.logger
  end
end

# frozen_string_literal: true

require_relative "lightspark_crypto/version"
require_relative "lightspark_crypto/lightspark_crypto"

module LightsparkCrypto
  # Network constants — mirrors Go's BitcoinNetwork consts.
  module Network
    BITCOIN = 1
    TESTNET = 2
    REGTEST = 3
  end

  # The native extension registers each function under an underscore-prefixed
  # name (e.g. `_sign_ecdsa`). Aliases below expose the unprefixed names.
  # Methods that need optional/default arguments stay as wrappers because magnus
  # singleton methods have fixed arity.
  class << self
    alias get_mnemonic_seed_phrase _get_mnemonic_seed_phrase
    alias mnemonic_to_seed _mnemonic_to_seed
    alias derive_public_key _derive_public_key
    alias derive_private_key _derive_private_key
    alias ecdh _ecdh
    alias sign_invoice _sign_invoice
    alias sign_invoice_hash _sign_invoice_hash
    alias get_per_commitment_point _get_per_commitment_point
    alias release_per_commitment_secret _release_per_commitment_secret
    alias generate_preimage_nonce _generate_preimage_nonce
    alias generate_preimage _generate_preimage
    alias generate_preimage_hash _generate_preimage_hash
    alias sign_ecdsa _sign_ecdsa
    alias verify_ecdsa _verify_ecdsa
    alias encrypt_ecies _encrypt_ecies
    alias decrypt_ecies _decrypt_ecies
    alias generate_multisig_address _generate_multisig_address
    alias generate_keypair _generate_keypair
    alias sign_transactions _sign_transactions

    def derive_key_and_sign(seed_bytes, network, message, derivation_path, is_raw, add_tweak = nil, mul_tweak = nil)
      _derive_key_and_sign(seed_bytes, network, message, derivation_path, is_raw, add_tweak, mul_tweak)
    end

    def derive_and_tweak_pubkey(pubkey, derivation_path, add_tweak = nil, mul_tweak = nil)
      _derive_and_tweak_pubkey(pubkey, derivation_path, add_tweak, mul_tweak)
    end
  end
end

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

  class << self
    def get_mnemonic_seed_phrase(entropy) = _get_mnemonic_seed_phrase(entropy)

    def mnemonic_to_seed(mnemonic) = _mnemonic_to_seed(mnemonic)

    def derive_public_key(seed_bytes, network, derivation_path) =
      _derive_public_key(seed_bytes, network, derivation_path)

    def derive_private_key(seed_bytes, network, derivation_path) =
      _derive_private_key(seed_bytes, network, derivation_path)

    def ecdh(seed_bytes, network, other_pub_key) =
      _ecdh(seed_bytes, network, other_pub_key)

    def derive_key_and_sign(seed_bytes, network, message, derivation_path, is_raw, add_tweak = nil, mul_tweak = nil)
      _derive_key_and_sign(seed_bytes, network, message, derivation_path, is_raw, add_tweak, mul_tweak)
    end

    def sign_invoice(seed_bytes, network, unsigned_invoice) =
      _sign_invoice(seed_bytes, network, unsigned_invoice)

    def sign_invoice_hash(seed_bytes, network, unsigned_invoice_bytes) =
      _sign_invoice_hash(seed_bytes, network, unsigned_invoice_bytes)

    def get_per_commitment_point(seed_bytes, network, derivation_path, per_commitment_point_idx)
      _get_per_commitment_point(seed_bytes, network, derivation_path, per_commitment_point_idx)
    end

    def release_per_commitment_secret(seed_bytes, network, derivation_path, per_commitment_point_idx)
      _release_per_commitment_secret(seed_bytes, network, derivation_path, per_commitment_point_idx)
    end

    def generate_preimage_nonce(seed_bytes) = _generate_preimage_nonce(seed_bytes)

    def generate_preimage(seed_bytes, nonce) = _generate_preimage(seed_bytes, nonce)

    def generate_preimage_hash(seed_bytes, nonce) = _generate_preimage_hash(seed_bytes, nonce)

    def sign_ecdsa(msg, private_key_bytes) = _sign_ecdsa(msg, private_key_bytes)

    def verify_ecdsa(msg, signature_bytes, public_key_bytes) =
      _verify_ecdsa(msg, signature_bytes, public_key_bytes)

    def encrypt_ecies(msg, public_key_bytes) = _encrypt_ecies(msg, public_key_bytes)

    def decrypt_ecies(cipher_text, private_key_bytes) =
      _decrypt_ecies(cipher_text, private_key_bytes)

    def generate_multisig_address(network, pk1, pk2) =
      _generate_multisig_address(network, pk1, pk2)

    def derive_and_tweak_pubkey(pubkey, derivation_path, add_tweak = nil, mul_tweak = nil)
      _derive_and_tweak_pubkey(pubkey, derivation_path, add_tweak, mul_tweak)
    end

    def generate_keypair = _generate_keypair

    def sign_transactions(master_seed, data, network) =
      _sign_transactions(master_seed, data, network)
  end
end

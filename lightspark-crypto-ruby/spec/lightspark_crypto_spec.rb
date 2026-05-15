# frozen_string_literal: true

require "base64"
require "digest"
require "spec_helper"

RSpec.describe LightsparkCrypto do
  describe ".get_mnemonic_seed_phrase" do
    it "derives the correct mnemonic from entropy" do
      entropy = Base64.strict_decode64("geVgqn+RALV+fPe1fvra9SNotfA/e2BprRqu2ub/6wg=")

      mnemonic = described_class.get_mnemonic_seed_phrase(entropy)

      expect(mnemonic).to eq(%w[
        limit climb clever you avoid follow wheat page rely water repeat tumble
        custom foot science urge gather estate effort frozen purpose lend promote anchor
      ])
    end
  end

  describe ".derive_public_key" do
    it "derives the correct xpub" do
      seed = ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2" \
              "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"].pack("H*")

      pub_key = described_class.derive_public_key(seed, LightsparkCrypto::Network::BITCOIN, "m/0/2147483647'/1")

      expect(pub_key).to eq(
        "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQ" \
        "coNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
      )
    end
  end

  describe ".derive_key_and_sign" do
    it "signs a message and produces the expected signature" do
      message = Digest::SHA256.digest("Hello Crypto World")
      seed    = ["fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2" \
                 "9f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"].pack("H*")

      signature = described_class.derive_key_and_sign(
        seed, LightsparkCrypto::Network::BITCOIN, message, "m/0/2147483647'/1", false
      )

      expect(Base64.strict_encode64(signature)).to eq(
        "fagpGOb9o/E8g62yL6jV5wtpTVzJ7R4rh0Xt2Uw4fPVd1Q+2ZJbkSrRBRj0bvk1" \
        "qTSiCvoiCfD5CMEHZL4fAlA=="
      )
    end
  end

  describe ".sign_transactions" do
    it "signs transactions without raising" do
      data = <<~JSON
        {"commitment_tx":"0200000000010187748372b3dfb3d47c2bb0a02848a327c77f5c982d036626c6de0a958af56069000000000025cee5800236ad03000000000016001415f586897037ded59858ccb1d24d4fbe7602692e90d00300000000002200204a30a8d4aba2d9d2e245052fc3566e1e18c49c1f364351481bfdd3e4d3a60da00400473044022066dbda605a766bc8143e15825c878b3b9444637b04678da42fe8f0c317c41fc70220482bb1a741497b14650c1e07ec4a00803855ff0f6a1434c88ae068f51567e94201004752210315496a93245ab6a7373b4e7297a30e2a20feefc50c59484dce93b6685e3ec0302103e65fcacf66816c0cb7d85726944463efe1466184a01d99949aed8a8b0676009a52aee1158720","sweep_tx":"020000000001016d0d0c47799e62541fc4bb51461b4bed8a5ed978ebe4f52d4c168a5b950d6f5401000000009000000001fbb80300000000001600146b0009af85b18052eb83afbdc9c45521c552588f0300004d632102a299258a6ac6b9be6b7ee879a87aca8a30e05d15e915b7af722f09d44c5014a867029000b2752103c74ec665bd1547f4a3dccee02c104677c7e880c6b0bdaec0cea195680d3cb62768ac00000000","htlc_tx":[],"serialized_htlc_sweep_tx":[],"channel_point":"6960f58a950adec62666032d985c7fc727a34828a0b02b7cd4b3dfb372837487:0","sweep_tx_add_tweak":"201d490866cdcc50199497d98b699f4ae367b23e801ffe405f3f983deef42f56","htlc_tx_add_tweak":"146d304968ba398899c7147fb641a6e20d4134b2c78abf4a2eb67e094fd730c1","funding_private_key_derivation_path":"m/3/599143572/0","delayed_payment_base_key_derivation_path":"m/3/599143572/3","htlc_base_key_derivation_path":"m/3/599143572/4","channel_capacity":500000,"nonces":[],"commitment_number":1}
      JSON

      result = described_class.sign_transactions(
        "f520e5271623fe21c76b0212f855c97a", data.strip, LightsparkCrypto::Network::REGTEST
      )

      expect(result).to be_a(LightsparkCrypto::FundsRecoveryResponse)
      expect(result.commitment_tx).not_to be_empty
      expect(result.sweep_tx).not_to be_empty
    end
  end

  describe ".sign_ecdsa and .verify_ecdsa" do
    it "signs and verifies a message round-trip" do
      keypair = described_class.generate_keypair
      message = Digest::SHA256.digest("test message")

      signature = described_class.sign_ecdsa(message, keypair.private_key)
      verified  = described_class.verify_ecdsa(message, signature, keypair.public_key)

      expect(verified).to be true
    end
  end

  describe ".encrypt_ecies and .decrypt_ecies" do
    it "encrypts and decrypts a message round-trip" do
      keypair   = described_class.generate_keypair
      plaintext = "hello lightning"

      ciphertext = described_class.encrypt_ecies(plaintext, keypair.public_key)
      decrypted  = described_class.decrypt_ecies(ciphertext, keypair.private_key)

      expect(decrypted).to eq(plaintext)
    end
  end

  describe ".mnemonic_to_seed" do
    it "converts mnemonic words back to seed bytes" do
      entropy  = Base64.strict_decode64("geVgqn+RALV+fPe1fvra9SNotfA/e2BprRqu2ub/6wg=")
      mnemonic = described_class.get_mnemonic_seed_phrase(entropy)
      seed     = described_class.mnemonic_to_seed(mnemonic)

      expect(seed).to be_a(String)
      expect(seed.bytesize).to eq(64)
    end
  end

  describe ".generate_preimage / .generate_preimage_hash" do
    it "generates a preimage and its hash" do
      seed  = described_class.mnemonic_to_seed(%w[abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about])
      nonce = described_class.generate_preimage_nonce(seed)

      expect(nonce).to be_a(String)
      expect(nonce.bytesize).to be > 0

      preimage      = described_class.generate_preimage(seed, nonce)
      preimage_hash = described_class.generate_preimage_hash(seed, nonce)

      expect(preimage).to be_a(String)
      expect(preimage_hash).to be_a(String)
      expect(Digest::SHA256.digest(preimage)).to eq(preimage_hash)
    end
  end
end

# lightspark-crypto-ruby

Ruby bindings for the [Lightspark crypto library](https://github.com/lightsparkdev/lightspark-crypto-uniffi), built with [magnus](https://github.com/matsadler/magnus).

Provides key derivation, signing, ECIES encryption/decryption, Lightning invoice signing, and funds recovery operations. Mirrors the Go bindings (`lightspark-crypto-go`) and bypasses UDL — the native extension talks to the underlying Rust crate directly.

## Installation

Add to your Gemfile:

```ruby
gem "lightspark_crypto"
```

## Usage

```ruby
require "lightspark_crypto"
require "digest"

entropy  = Random.bytes(32)
mnemonic = LightsparkCrypto.get_mnemonic_seed_phrase(entropy)
seed     = LightsparkCrypto.mnemonic_to_seed(mnemonic)

network = LightsparkCrypto::Network::BITCOIN

pub_key  = LightsparkCrypto.derive_public_key(seed, network, "m/0/2147483647'/1")
priv_key = LightsparkCrypto.derive_private_key(seed, network, "m/0/2147483647'/1")

keypair   = LightsparkCrypto.generate_keypair
message   = Digest::SHA256.digest("hello world")
signature = LightsparkCrypto.sign_ecdsa(message, keypair.private_key)
valid     = LightsparkCrypto.verify_ecdsa(message, signature, keypair.public_key)

sig = LightsparkCrypto.derive_key_and_sign(
  seed, network, message, "m/0/2147483647'/1", false
)

ciphertext = LightsparkCrypto.encrypt_ecies("secret", keypair.public_key)
plaintext  = LightsparkCrypto.decrypt_ecies(ciphertext, keypair.private_key)

signed = LightsparkCrypto.sign_invoice(seed, network, "lnbc...")
signed.recovery_id  # => Integer
signed.signature    # => binary String

nonce         = LightsparkCrypto.generate_preimage_nonce(seed)
preimage      = LightsparkCrypto.generate_preimage(seed, nonce)
preimage_hash = LightsparkCrypto.generate_preimage_hash(seed, nonce)

response = LightsparkCrypto.sign_transactions(master_seed_hex, json_data, network)
response.commitment_tx   # => String
response.sweep_tx        # => String
response.htlc_inbound_tx # => Array<LightsparkCrypto::Pair>
```

## Building from source

Requirements: Rust toolchain, Ruby >= 3.1

```bash
cd lightspark-crypto-ruby
bundle install
bundle exec rake compile
bundle exec rspec
```

For macOS arm64:

```bash
./scripts/generate-macos-arm64.sh
```

## Network

| Constant | Value |
|---|---|
| `LightsparkCrypto::Network::BITCOIN` | Mainnet |
| `LightsparkCrypto::Network::TESTNET` | Testnet |
| `LightsparkCrypto::Network::REGTEST` | Regtest |

## License

Apache-2.0

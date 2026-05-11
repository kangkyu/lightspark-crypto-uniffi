use lightspark_crypto::crypto::{self, KeyPair as InnerKeyPair};
use lightspark_crypto::funds_recovery_kit::{
    sign_transactions as inner_sign_transactions, StringTuple,
};
use lightspark_crypto::signer::{LightsparkSigner, Mnemonic, Network, Seed};
use magnus::{
    exception, function, method, prelude::*, Error, Module, RArray, RString, Ruby,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn to_ruby_err(e: impl std::fmt::Display) -> Error {
    Error::new(exception::runtime_error(), e.to_string())
}

fn to_network(n: i64) -> Result<Network, Error> {
    match n {
        1 => Ok(Network::Bitcoin),
        2 => Ok(Network::Testnet),
        3 => Ok(Network::Regtest),
        other => Err(Error::new(
            exception::arg_error(),
            format!("unknown network: {}", other),
        )),
    }
}

fn rs_to_vec(s: &RString) -> Vec<u8> {
    unsafe { s.as_slice() }.to_vec()
}

fn opt_rs_to_vec(s: Option<RString>) -> Option<Vec<u8>> {
    s.map(|v| rs_to_vec(&v))
}

fn bytes(ruby: &Ruby, b: &[u8]) -> RString {
    ruby.str_from_slice(b)
}

fn get_signer(seed_bytes: Vec<u8>, network: Network) -> Result<LightsparkSigner, Error> {
    let seed = Seed::new(seed_bytes);
    LightsparkSigner::new(&seed, network).map_err(to_ruby_err)
}

// ── KeyPair ───────────────────────────────────────────────────────────────────

#[magnus::wrap(class = "LightsparkCrypto::KeyPair", free_immediately, size)]
#[derive(Clone)]
struct RubyKeyPair(InnerKeyPair);

impl RubyKeyPair {
    fn public_key(ruby: &Ruby, rb_self: &Self) -> RString {
        bytes(ruby, &rb_self.0.get_public_key())
    }

    fn private_key(ruby: &Ruby, rb_self: &Self) -> RString {
        bytes(ruby, &rb_self.0.get_private_key())
    }
}

// ── SignedInvoice ─────────────────────────────────────────────────────────────

#[magnus::wrap(class = "LightsparkCrypto::SignedInvoice", free_immediately, size)]
#[derive(Clone)]
struct RubySignedInvoice {
    recovery_id: i32,
    signature: Vec<u8>,
}

impl RubySignedInvoice {
    fn recovery_id(&self) -> i32 {
        self.recovery_id
    }

    fn signature(ruby: &Ruby, rb_self: &Self) -> RString {
        bytes(ruby, &rb_self.signature)
    }
}

// ── Pair (StringTuple) ────────────────────────────────────────────────────────

#[magnus::wrap(class = "LightsparkCrypto::Pair", free_immediately, size)]
#[derive(Clone)]
struct RubyPair {
    first: String,
    second: String,
}

impl RubyPair {
    fn first(&self) -> String {
        self.first.clone()
    }

    fn second(&self) -> String {
        self.second.clone()
    }
}

fn to_ruby_pair(t: StringTuple) -> RubyPair {
    RubyPair {
        first: t.first,
        second: t.second,
    }
}

// ── FundsRecoveryResponse ─────────────────────────────────────────────────────

#[magnus::wrap(
    class = "LightsparkCrypto::FundsRecoveryResponse",
    free_immediately,
    size
)]
struct RubyFundsRecoveryResponse {
    commitment_tx: String,
    sweep_tx: String,
    htlc_inbound_tx: Vec<RubyPair>,
    htlc_outbound_tx: Vec<RubyPair>,
    counterparty_sweep_tx: String,
    counterparty_htlc_inbound_tx: Vec<String>,
    counterparty_htlc_outbound_tx: Vec<String>,
}

impl RubyFundsRecoveryResponse {
    fn commitment_tx(&self) -> String {
        self.commitment_tx.clone()
    }

    fn sweep_tx(&self) -> String {
        self.sweep_tx.clone()
    }

    fn counterparty_sweep_tx(&self) -> String {
        self.counterparty_sweep_tx.clone()
    }

    fn counterparty_htlc_inbound_tx(&self) -> Vec<String> {
        self.counterparty_htlc_inbound_tx.clone()
    }

    fn counterparty_htlc_outbound_tx(&self) -> Vec<String> {
        self.counterparty_htlc_outbound_tx.clone()
    }

    fn htlc_inbound_tx(ruby: &Ruby, rb_self: &Self) -> RArray {
        ruby.ary_from_iter(rb_self.htlc_inbound_tx.iter().cloned())
    }

    fn htlc_outbound_tx(ruby: &Ruby, rb_self: &Self) -> RArray {
        ruby.ary_from_iter(rb_self.htlc_outbound_tx.iter().cloned())
    }
}

// ── Free crypto functions ─────────────────────────────────────────────────────

fn sign_ecdsa(ruby: &Ruby, msg: RString, private_key_bytes: RString) -> Result<RString, Error> {
    let out = crypto::sign_ecdsa(rs_to_vec(&msg), rs_to_vec(&private_key_bytes))
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn verify_ecdsa(
    msg: RString,
    signature_bytes: RString,
    public_key_bytes: RString,
) -> Result<bool, Error> {
    crypto::verify_ecdsa(
        rs_to_vec(&msg),
        rs_to_vec(&signature_bytes),
        rs_to_vec(&public_key_bytes),
    )
    .map_err(to_ruby_err)
}

fn encrypt_ecies(ruby: &Ruby, msg: RString, public_key_bytes: RString) -> Result<RString, Error> {
    let out = crypto::encrypt_ecies(rs_to_vec(&msg), rs_to_vec(&public_key_bytes))
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn decrypt_ecies(
    ruby: &Ruby,
    cipher_text: RString,
    private_key_bytes: RString,
) -> Result<RString, Error> {
    let out = crypto::decrypt_ecies(rs_to_vec(&cipher_text), rs_to_vec(&private_key_bytes))
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn generate_multisig_address(
    network: i64,
    pk1: RString,
    pk2: RString,
) -> Result<String, Error> {
    crypto::generate_multisig_address(to_network(network)?, rs_to_vec(&pk1), rs_to_vec(&pk2))
        .map_err(to_ruby_err)
}

fn generate_keypair() -> Result<RubyKeyPair, Error> {
    crypto::generate_keypair()
        .map(|arc| RubyKeyPair((*arc).clone()))
        .map_err(to_ruby_err)
}

fn derive_and_tweak_pubkey(
    ruby: &Ruby,
    pubkey: String,
    derivation_path: String,
    add_tweak: Option<RString>,
    mul_tweak: Option<RString>,
) -> Result<RString, Error> {
    let out = crypto::derive_and_tweak_pubkey(
        pubkey,
        derivation_path,
        opt_rs_to_vec(add_tweak),
        opt_rs_to_vec(mul_tweak),
    )
    .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

// ── Signer-backed functions ───────────────────────────────────────────────────

fn get_mnemonic_seed_phrase(entropy: RString) -> Result<Vec<String>, Error> {
    let mnemonic = Mnemonic::from_entropy(rs_to_vec(&entropy)).map_err(to_ruby_err)?;
    Ok(mnemonic
        .as_string()
        .split_whitespace()
        .map(str::to_owned)
        .collect())
}

fn mnemonic_to_seed(ruby: &Ruby, mnemonic: Vec<String>) -> Result<RString, Error> {
    let phrase = mnemonic.join(" ");
    let mnemonic_obj = Mnemonic::from_phrase(phrase).map_err(to_ruby_err)?;
    let seed = Seed::from_mnemonic(&mnemonic_obj);
    Ok(bytes(ruby, &seed.as_bytes()))
}

fn derive_public_key(
    seed_bytes: RString,
    network: i64,
    derivation_path: String,
) -> Result<String, Error> {
    get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .derive_public_key(derivation_path)
        .map_err(to_ruby_err)
}

fn derive_private_key(
    seed_bytes: RString,
    network: i64,
    derivation_path: String,
) -> Result<String, Error> {
    get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .derive_private_key(derivation_path)
        .map_err(to_ruby_err)
}

fn ecdh(
    ruby: &Ruby,
    seed_bytes: RString,
    network: i64,
    other_pub_key: RString,
) -> Result<RString, Error> {
    let out = get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .ecdh(rs_to_vec(&other_pub_key))
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn derive_key_and_sign(
    ruby: &Ruby,
    seed_bytes: RString,
    network: i64,
    message: RString,
    derivation_path: String,
    is_raw: bool,
    add_tweak: Option<RString>,
    mul_tweak: Option<RString>,
) -> Result<RString, Error> {
    let out = get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .derive_key_and_sign(
            rs_to_vec(&message),
            derivation_path,
            is_raw,
            opt_rs_to_vec(add_tweak),
            opt_rs_to_vec(mul_tweak),
        )
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn sign_invoice(
    seed_bytes: RString,
    network: i64,
    unsigned_invoice: String,
) -> Result<RubySignedInvoice, Error> {
    let sig = get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .sign_invoice(unsigned_invoice)
        .map_err(to_ruby_err)?;
    Ok(RubySignedInvoice {
        recovery_id: sig.get_recovery_id(),
        signature: sig.get_signature(),
    })
}

fn sign_invoice_hash(
    seed_bytes: RString,
    network: i64,
    unsigned_invoice: RString,
) -> Result<RubySignedInvoice, Error> {
    let sig = get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .sign_invoice_hash(rs_to_vec(&unsigned_invoice))
        .map_err(to_ruby_err)?;
    Ok(RubySignedInvoice {
        recovery_id: sig.get_recovery_id(),
        signature: sig.get_signature(),
    })
}

fn get_per_commitment_point(
    ruby: &Ruby,
    seed_bytes: RString,
    network: i64,
    derivation_path: String,
    per_commitment_point_idx: u64,
) -> Result<RString, Error> {
    let out = get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .get_per_commitment_point(derivation_path, per_commitment_point_idx)
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn release_per_commitment_secret(
    ruby: &Ruby,
    seed_bytes: RString,
    network: i64,
    derivation_path: String,
    per_commitment_point_idx: u64,
) -> Result<RString, Error> {
    let out = get_signer(rs_to_vec(&seed_bytes), to_network(network)?)?
        .release_per_commitment_secret(derivation_path, per_commitment_point_idx)
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn generate_preimage_nonce(ruby: &Ruby, seed_bytes: RString) -> Result<RString, Error> {
    let signer = get_signer(rs_to_vec(&seed_bytes), Network::Bitcoin)?;
    Ok(bytes(ruby, &signer.generate_preimage_nonce()))
}

fn generate_preimage(ruby: &Ruby, seed_bytes: RString, nonce: RString) -> Result<RString, Error> {
    let out = get_signer(rs_to_vec(&seed_bytes), Network::Bitcoin)?
        .generate_preimage(rs_to_vec(&nonce))
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn generate_preimage_hash(
    ruby: &Ruby,
    seed_bytes: RString,
    nonce: RString,
) -> Result<RString, Error> {
    let out = get_signer(rs_to_vec(&seed_bytes), Network::Bitcoin)?
        .generate_preimage_hash(rs_to_vec(&nonce))
        .map_err(to_ruby_err)?;
    Ok(bytes(ruby, &out))
}

fn sign_transactions(
    master_seed: String,
    data: String,
    network: i64,
) -> Result<RubyFundsRecoveryResponse, Error> {
    let resp = inner_sign_transactions(master_seed, data, to_network(network)?)
        .map_err(to_ruby_err)?;
    Ok(RubyFundsRecoveryResponse {
        commitment_tx: resp.commitment_tx,
        sweep_tx: resp.sweep_tx,
        htlc_inbound_tx: resp.htlc_inbound_tx.into_iter().map(to_ruby_pair).collect(),
        htlc_outbound_tx: resp.htlc_outbound_tx.into_iter().map(to_ruby_pair).collect(),
        counterparty_sweep_tx: resp.counterparty_sweep_tx,
        counterparty_htlc_inbound_tx: resp.counterparty_htlc_inbound_tx,
        counterparty_htlc_outbound_tx: resp.counterparty_htlc_outbound_tx,
    })
}

// ── Init ─────────────────────────────────────────────────────────────────────

#[magnus::init]
fn init(ruby: &Ruby) -> Result<(), Error> {
    let module = ruby.define_module("LightsparkCrypto")?;

    let keypair_class = module.define_class("KeyPair", ruby.class_object())?;
    keypair_class.define_method("public_key", method!(RubyKeyPair::public_key, 0))?;
    keypair_class.define_method("private_key", method!(RubyKeyPair::private_key, 0))?;

    let signed_invoice_class = module.define_class("SignedInvoice", ruby.class_object())?;
    signed_invoice_class.define_method("recovery_id", method!(RubySignedInvoice::recovery_id, 0))?;
    signed_invoice_class.define_method("signature", method!(RubySignedInvoice::signature, 0))?;

    let pair_class = module.define_class("Pair", ruby.class_object())?;
    pair_class.define_method("first", method!(RubyPair::first, 0))?;
    pair_class.define_method("second", method!(RubyPair::second, 0))?;

    let response_class = module.define_class("FundsRecoveryResponse", ruby.class_object())?;
    response_class.define_method(
        "commitment_tx",
        method!(RubyFundsRecoveryResponse::commitment_tx, 0),
    )?;
    response_class.define_method(
        "sweep_tx",
        method!(RubyFundsRecoveryResponse::sweep_tx, 0),
    )?;
    response_class.define_method(
        "htlc_inbound_tx",
        method!(RubyFundsRecoveryResponse::htlc_inbound_tx, 0),
    )?;
    response_class.define_method(
        "htlc_outbound_tx",
        method!(RubyFundsRecoveryResponse::htlc_outbound_tx, 0),
    )?;
    response_class.define_method(
        "counterparty_sweep_tx",
        method!(RubyFundsRecoveryResponse::counterparty_sweep_tx, 0),
    )?;
    response_class.define_method(
        "counterparty_htlc_inbound_tx",
        method!(RubyFundsRecoveryResponse::counterparty_htlc_inbound_tx, 0),
    )?;
    response_class.define_method(
        "counterparty_htlc_outbound_tx",
        method!(RubyFundsRecoveryResponse::counterparty_htlc_outbound_tx, 0),
    )?;

    module.define_singleton_method("_sign_ecdsa", function!(sign_ecdsa, 2))?;
    module.define_singleton_method("_verify_ecdsa", function!(verify_ecdsa, 3))?;
    module.define_singleton_method("_encrypt_ecies", function!(encrypt_ecies, 2))?;
    module.define_singleton_method("_decrypt_ecies", function!(decrypt_ecies, 2))?;
    module.define_singleton_method(
        "_generate_multisig_address",
        function!(generate_multisig_address, 3),
    )?;
    module.define_singleton_method("_generate_keypair", function!(generate_keypair, 0))?;
    module.define_singleton_method(
        "_derive_and_tweak_pubkey",
        function!(derive_and_tweak_pubkey, 4),
    )?;
    module.define_singleton_method(
        "_get_mnemonic_seed_phrase",
        function!(get_mnemonic_seed_phrase, 1),
    )?;
    module.define_singleton_method("_mnemonic_to_seed", function!(mnemonic_to_seed, 1))?;
    module.define_singleton_method("_derive_public_key", function!(derive_public_key, 3))?;
    module.define_singleton_method("_derive_private_key", function!(derive_private_key, 3))?;
    module.define_singleton_method("_ecdh", function!(ecdh, 3))?;
    module.define_singleton_method("_derive_key_and_sign", function!(derive_key_and_sign, 7))?;
    module.define_singleton_method("_sign_invoice", function!(sign_invoice, 3))?;
    module.define_singleton_method("_sign_invoice_hash", function!(sign_invoice_hash, 3))?;
    module.define_singleton_method(
        "_get_per_commitment_point",
        function!(get_per_commitment_point, 4),
    )?;
    module.define_singleton_method(
        "_release_per_commitment_secret",
        function!(release_per_commitment_secret, 4),
    )?;
    module.define_singleton_method(
        "_generate_preimage_nonce",
        function!(generate_preimage_nonce, 1),
    )?;
    module.define_singleton_method("_generate_preimage", function!(generate_preimage, 2))?;
    module.define_singleton_method(
        "_generate_preimage_hash",
        function!(generate_preimage_hash, 2),
    )?;
    module.define_singleton_method("_sign_transactions", function!(sign_transactions, 3))?;

    Ok(())
}

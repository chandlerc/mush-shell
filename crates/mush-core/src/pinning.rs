// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Ephemeral-key pinning for the QUIC handshake: one of the custom
//! security-relevant surfaces the design doc's "Security analysis"
//! enumerates, and kept deliberately small and heavily documented. The
//! model:
//!
//! - Each side generates an ephemeral Ed25519 keypair per session
//!   ([`SessionIdentity`]) and presents it in the TLS 1.3 handshake as an
//!   RFC 7250 raw public key: the "certificate" is the bare
//!   SubjectPublicKeyInfo DER, no X.509 anywhere.
//! - The SHA-256 hash of that SPKI DER ([`KeyPin`]) is exchanged over the
//!   mutually authenticated SSH bootstrap channel.
//! - The verifiers here check exactly one thing beyond rustls's own
//!   signature verification: that the presented SPKI hashes to the pinned
//!   value. There are no roots, no names, no validity windows, and no
//!   TLS 1.2 paths.
//!
//! Everything else -- handshake, AEAD, key schedule, key updates -- is
//! stock rustls and quinn.

use std::sync::Arc;

use aws_lc_rs::digest;
use aws_lc_rs::signature::Ed25519KeyPair;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{
  HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::crypto::{
  CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs as provider,
  verify_tls13_signature_with_raw_key,
};
use rustls::pki_types::{
  CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
  UnixTime,
};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::version::TLS13;
use rustls::{
  CertificateError, DigitallySignedStruct, DistinguishedName,
  Error as TlsError, SignatureScheme,
};
use subtle::ConstantTimeEq as _;

use crate::bootstrap::InvalidValue;
use crate::transport::TransportOptions;

/// The ALPN protocol identifier for the Mush tunnel.
pub const ALPN: &[u8] = b"mush/1";

/// Errors from identity generation and crypto config construction.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
  /// The crypto provider failed to generate or load a key.
  #[error("session key generation failed")]
  KeyGeneration,
  /// rustls rejected the configuration.
  #[error("TLS configuration rejected: {0}")]
  Tls(#[from] rustls::Error),
  /// The rustls config could not be converted for QUIC use. Cannot
  /// happen with the provider used here (`crypto_provider`).
  #[error("QUIC-incompatible TLS configuration: {0}")]
  NoInitialCipherSuite(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

/// SHA-256 hash of a peer's SubjectPublicKeyInfo DER: the value carried
/// over the bootstrap channel and pinned by the handshake verifiers.
///
/// Equality is constant-time (via `subtle`). The pins are public values,
/// so this is depth rather than a requirement, but it costs nothing.
///
/// The wire encoding ([`std::fmt::Display`] / [`std::str::FromStr`]) is
/// canonical unpadded standard base64 (43 characters); parsing rejects
/// any other form, including padded input.
#[derive(Clone, Copy)]
pub struct KeyPin([u8; 32]);

impl KeyPin {
  /// Pins `spki_der`, the DER encoding of a SubjectPublicKeyInfo.
  pub fn from_spki_der(spki_der: &[u8]) -> Self {
    let hash = digest::digest(&digest::SHA256, spki_der);
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(hash.as_ref());
    Self(bytes)
  }

  /// Wraps an already-computed hash.
  pub fn from_bytes(bytes: [u8; 32]) -> Self {
    Self(bytes)
  }

  /// The raw hash bytes.
  pub fn as_bytes(&self) -> &[u8; 32] {
    &self.0
  }
}

impl PartialEq for KeyPin {
  fn eq(&self, other: &Self) -> bool {
    self.0.ct_eq(&other.0).into()
  }
}

impl Eq for KeyPin {}

impl std::fmt::Display for KeyPin {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&STANDARD_NO_PAD.encode(self.0))
  }
}

impl std::fmt::Debug for KeyPin {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "KeyPin({self})")
  }
}

impl std::str::FromStr for KeyPin {
  type Err = InvalidValue;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let decoded = STANDARD_NO_PAD.decode(s).map_err(|_| InvalidValue)?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| InvalidValue)?;
    Ok(Self(bytes))
  }
}

/// An ephemeral per-session identity: an Ed25519 keypair presented in the
/// handshake as an RFC 7250 raw public key.
///
/// Ed25519 is used because the default rustls provider (aws-lc-rs)
/// supports it on the raw-public-key path end to end (keygen via
/// `Ed25519KeyPair::generate_pkcs8`, signing via `any_eddsa_type`,
/// verification via `verify_tls13_signature_with_raw_key`), and a single
/// fixed algorithm keeps the verifiers' accepted-scheme list to exactly
/// one entry. No fallback to ECDSA is needed.
pub struct SessionIdentity {
  certified_key: Arc<CertifiedKey>,
  spki_der: SubjectPublicKeyInfoDer<'static>,
  pin: KeyPin,
}

impl SessionIdentity {
  /// Generates a fresh Ed25519 keypair. The key exists only in this
  /// process's memory and is never written anywhere.
  pub fn generate() -> Result<Self, CryptoError> {
    let pkcs8 =
      Ed25519KeyPair::generate_pkcs8(&aws_lc_rs::rand::SystemRandom::new())
        .map_err(|_| CryptoError::KeyGeneration)?;
    let signing_key = provider::sign::any_eddsa_type(
      &PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()),
    )
    .map_err(|_| CryptoError::KeyGeneration)?;
    let spki_der = signing_key
      .public_key()
      .ok_or(CryptoError::KeyGeneration)?
      .into_owned();
    let pin = KeyPin::from_spki_der(spki_der.as_ref());
    // Per the raw-public-key resolvers' contract, the single "certificate"
    // is the SPKI DER itself.
    let certified_key = Arc::new(CertifiedKey::new(
      vec![CertificateDer::from(spki_der.as_ref().to_vec())],
      signing_key,
    ));
    Ok(Self {
      certified_key,
      spki_der,
      pin,
    })
  }

  /// The DER-encoded SubjectPublicKeyInfo presented in the handshake.
  pub fn spki_der(&self) -> &[u8] {
    self.spki_der.as_ref()
  }

  /// The pin of this identity: what the peer must have received over the
  /// bootstrap channel for the handshake to succeed.
  pub fn pin(&self) -> KeyPin {
    self.pin
  }
}

impl std::fmt::Debug for SessionIdentity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.debug_struct("SessionIdentity")
      .field("pin", &self.pin)
      .finish()
  }
}

/// The one signature scheme either verifier advertises or accepts; see
/// [`SessionIdentity`] for why there is exactly one.
const SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;

/// Refuses a signature under any scheme but the one advertised: the
/// verifier hands the provider's whole verification table to
/// `verify_tls13_signature_with_raw_key`, which would otherwise accept
/// any scheme in it. A peer that signed under a scheme this side never
/// offered is misbehaving whatever the signature says, and the SPKI is
/// pinned to an Ed25519 key regardless, so this is depth: the refusal
/// belongs to this crate's own table rather than to webpki's
/// key-algorithm match two layers down.
fn verify_pinned_scheme(scheme: SignatureScheme) -> Result<(), TlsError> {
  match scheme == SIGNATURE_SCHEME {
    true => Ok(()),
    false => Err(TlsError::PeerMisbehaved(
      rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
    )),
  }
}

/// The whole of Mush's trust decision: the peer is whoever presents the
/// pinned SPKI, having proved possession of it under the one signature
/// scheme this side advertises.
///
/// rustls asks a client and a server that same question through two
/// unrelated traits. Each verifier below is this plus the bookkeeping
/// its own trait asks for, so the decision is reviewed once rather than
/// diffed between two copies that must be shown to agree.
#[derive(Debug)]
struct Pinned {
  pinned: KeyPin,
  algorithms: WebPkiSupportedAlgorithms,
}

impl Pinned {
  /// Checks a presented raw-public-key "certificate" against the pin.
  /// With `requires_raw_public_keys()` in force, rustls hands the
  /// verifier the peer's SPKI DER directly as the end-entity
  /// certificate, so the entire check is one hash comparison.
  fn verify_spki(
    &self,
    end_entity: &CertificateDer<'_>,
  ) -> Result<(), TlsError> {
    if KeyPin::from_spki_der(end_entity.as_ref()) == self.pinned {
      return Ok(());
    }
    Err(TlsError::InvalidCertificate(
      CertificateError::ApplicationVerificationFailure,
    ))
  }

  /// Proof of possession of the pinned key: the advertised scheme
  /// (`verify_pinned_scheme`), then rustls's raw-public-key check.
  fn verify_tls13(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    verify_pinned_scheme(dss.scheme)?;
    verify_tls13_signature_with_raw_key(
      message,
      &SubjectPublicKeyInfoDer::from(cert.as_ref()),
      dss,
      &self.algorithms,
    )
  }

  /// QUIC is TLS 1.3 only; nothing may downgrade to a 1.2 handshake.
  fn refuse_tls12() -> Result<HandshakeSignatureValid, TlsError> {
    Err(TlsError::PeerIncompatible(
      rustls::PeerIncompatible::Tls12NotOffered,
    ))
  }
}

/// Client-side verifier: accepts exactly the server whose SPKI hash was
/// pinned from the bootstrap `MUSH CONNECT` line.
///
/// Server names, OCSP, intermediates, and validity time are deliberately
/// ignored: the pin is the entire trust decision, and there is no PKI.
#[derive(Debug)]
struct PinnedServerVerifier(Pinned);

impl ServerCertVerifier for PinnedServerVerifier {
  fn verify_server_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
    _server_name: &ServerName<'_>,
    _ocsp_response: &[u8],
    _now: UnixTime,
  ) -> Result<ServerCertVerified, TlsError> {
    self.0.verify_spki(end_entity)?;
    Ok(ServerCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &CertificateDer<'_>,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    Pinned::refuse_tls12()
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    self.0.verify_tls13(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    vec![SIGNATURE_SCHEME]
  }

  fn requires_raw_public_keys(&self) -> bool {
    true
  }
}

/// Server-side verifier: requires client auth and accepts exactly the
/// client whose SPKI hash arrived in the bootstrap `MUSH HELLO` line.
///
/// Anyone else -- port scanners included -- fails the handshake and
/// learns nothing beyond "a QUIC endpoint exists".
#[derive(Debug)]
struct PinnedClientVerifier(Pinned);

impl ClientCertVerifier for PinnedClientVerifier {
  fn root_hint_subjects(&self) -> &[DistinguishedName] {
    &[]
  }

  fn verify_client_cert(
    &self,
    end_entity: &CertificateDer<'_>,
    _intermediates: &[CertificateDer<'_>],
    _now: UnixTime,
  ) -> Result<ClientCertVerified, TlsError> {
    self.0.verify_spki(end_entity)?;
    Ok(ClientCertVerified::assertion())
  }

  fn verify_tls12_signature(
    &self,
    _message: &[u8],
    _cert: &CertificateDer<'_>,
    _dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    Pinned::refuse_tls12()
  }

  fn verify_tls13_signature(
    &self,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
  ) -> Result<HandshakeSignatureValid, TlsError> {
    self.0.verify_tls13(message, cert, dss)
  }

  fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
    vec![SIGNATURE_SCHEME]
  }

  fn offer_client_auth(&self) -> bool {
    true
  }

  fn client_auth_mandatory(&self) -> bool {
    true
  }

  fn requires_raw_public_keys(&self) -> bool {
    true
  }
}

/// The crypto provider all Mush TLS configs use: rustls's default
/// (aws-lc-rs), which includes TLS13_AES_128_GCM_SHA256 as quinn requires
/// for Initial packet protection.
fn crypto_provider() -> Arc<CryptoProvider> {
  Arc::new(provider::default_provider())
}

/// Builds the complete client-side quinn config: present `identity` as a
/// raw public key, require the server to present the key pinned as
/// `pinned_server`, TLS 1.3 only, ALPN [`ALPN`], with `transport`'s
/// client-side policy applied.
///
/// The transport policy is part of the constructor on purpose; see
/// [`crate::transport`] for what a config assembled without
/// [`TransportOptions::client_transport`] silently loses.
pub fn client_config(
  identity: &SessionIdentity,
  pinned_server: KeyPin,
  transport: &TransportOptions,
) -> Result<quinn::ClientConfig, CryptoError> {
  let provider = crypto_provider();
  let algorithms = provider.signature_verification_algorithms;
  let mut tls = rustls::ClientConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(PinnedServerVerifier(Pinned {
      pinned: pinned_server,
      algorithms,
    })))
    .with_client_cert_resolver(Arc::new(
      AlwaysResolvesClientRawPublicKeys::new(identity.certified_key.clone()),
    ));
  tls.alpn_protocols = vec![ALPN.to_vec()];
  let quic = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
  let mut config = quinn::ClientConfig::new(Arc::new(quic));
  config.transport_config(transport.client_transport());
  Ok(config)
}

/// Builds the complete server-side quinn config: present `identity` as a
/// raw public key and require a client presenting the key pinned as
/// `pinned_client`, TLS 1.3 only, ALPN [`ALPN`], with `transport`'s
/// server-side policy applied (see [`client_config`] for why the two are
/// coupled).
///
/// Client address migration is left at quinn's default (enabled), which
/// the design depends on for roaming.
pub fn server_config(
  identity: &SessionIdentity,
  pinned_client: KeyPin,
  transport: &TransportOptions,
) -> Result<quinn::ServerConfig, CryptoError> {
  let provider = crypto_provider();
  let algorithms = provider.signature_verification_algorithms;
  let mut tls = rustls::ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&[&TLS13])?
    .with_client_cert_verifier(Arc::new(PinnedClientVerifier(Pinned {
      pinned: pinned_client,
      algorithms,
    })))
    .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(
      identity.certified_key.clone(),
    )));
  tls.alpn_protocols = vec![ALPN.to_vec()];
  let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
  let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
  config.transport_config(transport.server_transport());
  Ok(config)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn pin_round_trips_through_base64() {
    let pin = KeyPin::from_spki_der(b"example spki");
    let encoded = pin.to_string();
    assert_eq!(encoded.len(), 43);
    let parsed: KeyPin = encoded.parse().unwrap();
    assert_eq!(parsed, pin);
  }

  #[test]
  fn pin_parse_rejects_bad_input() {
    assert_eq!("not base64!".parse::<KeyPin>(), Err(InvalidValue));
    // Wrong decoded length.
    let short = STANDARD_NO_PAD.encode([0u8; 16]);
    assert_eq!(short.parse::<KeyPin>(), Err(InvalidValue));
    // Padded base64 is non-canonical and rejected.
    let padded = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
    assert!(padded.contains('='));
    assert_eq!(padded.parse::<KeyPin>(), Err(InvalidValue));
  }

  #[test]
  fn distinct_identities_have_distinct_pins() {
    let a = SessionIdentity::generate().unwrap();
    let b = SessionIdentity::generate().unwrap();
    assert_ne!(a.pin(), b.pin());
    assert_eq!(a.pin(), KeyPin::from_spki_der(a.spki_der()));
  }

  /// The advertised scheme list is the accepted one: a signature under
  /// anything else is refused here rather than deeper down.
  #[test]
  fn only_the_advertised_signature_scheme_is_accepted() {
    assert!(verify_pinned_scheme(SIGNATURE_SCHEME).is_ok());
    for scheme in [
      SignatureScheme::ECDSA_NISTP256_SHA256,
      SignatureScheme::RSA_PSS_SHA256,
      SignatureScheme::ED448,
    ] {
      assert!(verify_pinned_scheme(scheme).is_err(), "accepted {scheme:?}");
    }
  }
}

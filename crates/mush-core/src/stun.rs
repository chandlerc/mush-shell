// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! The traversal probe wire format: STUN binding requests and success
//! responses (RFC 8489), encoded and decoded by the `stun-types` crate.
//!
//! The design's reuse rule picks the existing STUN format rather than
//! inventing a probe format ("Reuse versus build"), and picks a codec
//! rather than an ICE stack: ssh already gives Mush reliable, private,
//! mutually authenticated signaling, so none of ICE's negotiation
//! machinery is wanted -- only the one message pair the jump helper and
//! its peers need.
//!
//! One probe drives all three of the helper's services (see
//! [`crate::helper`]): it is the reflection query, the registration that
//! makes an address relayable, and the packet whose NAT mapping the
//! punch rendezvous is built on. The session it belongs to travels in
//! the STUN `USERNAME` attribute as `<nonce>:<role>`, the shape ICE uses
//! for its ufrag pair. That label is a flow label and never a
//! credential: [`SessionNonce`] grants nothing and the probes carrying
//! it are visible to anyone on the path.
//!
//! # Why the probes are signed
//!
//! A label cannot prove who sent a datagram, and the helper acts on
//! exactly that: a labeled probe makes it register the source address
//! the probe arrived from and relay to it afterwards. UDP source
//! addresses are forgeable, so a label alone would make the helper an
//! arbitrary-destination forwarder for anyone who has seen one probe go
//! past. Every labeled probe therefore carries RFC 8489
//! `MESSAGE-INTEGRITY-SHA256` under short-term credentials, keyed with
//! the session's [`SessionSecret`]: distributed over the two ssh
//! channels the client already holds, so it never crosses a network in
//! the clear and needs no key exchange. The helper signs its responses
//! with the same key, so a reflexive address is one the real helper
//! reported rather than one an off-path answer claimed.
//!
//! # Why the label says where a probe was going
//!
//! A signature says who wrote a message, not who it was for, and a
//! session's probes go to two places that treat them very differently
//! ([`Aim`]). A peer's addresses come from signaling, so they can
//! include one a lying helper named, and probes fan out to all of them
//! across networks nobody chose. Without saying which was meant, a probe
//! captured on the way to a candidate that was never the peer would be a
//! registration the helper honors.
//!
//! So the label carries the [`Aim`] too, inside what the integrity
//! attribute covers, and each service acts only on its own: the helper
//! registers [`Aim::Helper`] probes ([`crate::helper`]), the destination
//! answers [`Aim::Peer`] probes ([`crate::upgrade`]), and a probe from
//! the other context is refused before any state is touched. What
//! remains is a replay within one context, which the helper bounds by
//! refusing to *move* a registration on a transaction it already acted
//! on, so a captured probe cannot outlive its round.
//!
//! Nothing here is inside the security boundary: signing authorizes the
//! helper to act, and every path it helps propose still has to survive
//! the pinned QUIC handshake. The `--stun <server>` opt-in has no
//! credentials to share and nothing to authorize, so those probes are
//! unlabeled and unsigned.
//!
//! Demultiplexing follows RFC 7983, with the guard RFC 7983 alone does
//! not give: see [`is_stun`], which every socket carrying both classes
//! sorts on.
//!
//! This is another parser fed by unauthenticated network input, so it
//! carries the [`crate::bootstrap`] parser's discipline: never panic,
//! bound what is examined, and answer nothing that is not understood.

use std::net::SocketAddr;

use stun_types::attribute::{
  MessageIntegritySha256, Username, XorMappedAddress,
};
use stun_types::message::{
  BINDING, IntegrityAlgorithm, Message, MessageClass,
  MessageIntegrityCredentials, MessageType, MessageWriteVec,
  ShortTermCredentials, TransactionId,
};
use stun_types::prelude::*;

use crate::bootstrap::{InvalidValue, SessionNonce, SessionSecret};
use crate::wire::str_enum;

/// The integrity algorithm the probes are signed with: RFC 8489's
/// `MESSAGE-INTEGRITY-SHA256`, the one it defines for new deployments.
/// Both ends of every probe are Mush, so nothing here interops with the
/// RFC 5389-era SHA-1 attribute, in either direction (see [`signed`]).
const INTEGRITY: IntegrityAlgorithm = IntegrityAlgorithm::Sha256;

/// The length of a full `MESSAGE-INTEGRITY-SHA256` tag. RFC 8489 allows
/// truncation down to 16 bytes and the attribute's parser accepts one;
/// nothing here has a reason to send a shorter tag than the algorithm
/// produces.
const INTEGRITY_TAG_BYTES: usize = 32;

/// The short-term credentials a session's probes are signed with. The
/// username is the probe label the message already carries; RFC 8489
/// short-term credentials key on the password alone.
fn credentials(secret: &SessionSecret) -> MessageIntegrityCredentials {
  ShortTermCredentials::new(secret.expose()).into()
}

/// Whether `message` carries a full `MESSAGE-INTEGRITY-SHA256` that
/// verifies under this session's secret.
///
/// Which algorithm a message is checked with is this side's decision
/// rather than the sender's, which takes saying so in code: the codec
/// picks one from the attributes a message happens to carry, so a probe
/// bearing only the RFC 5389-era SHA-1 `MESSAGE-INTEGRITY` would be
/// verified with HMAC-SHA1 over the same secret and accepted. Forging
/// either still needs the secret, so this is defense in depth rather
/// than the fix for a vulnerability.
fn signed(message: &Message<'_>, secret: &SessionSecret) -> bool {
  let Ok(tag) = message.attribute::<MessageIntegritySha256>() else {
    return false;
  };
  tag.hmac().len() == INTEGRITY_TAG_BYTES
    && matches!(
      message.validate_integrity(&credentials(secret)),
      Ok(IntegrityAlgorithm::Sha256)
    )
}

/// The longest datagram this module will parse as STUN.
///
/// A probe runs to about a hundred bytes; anything this much longer
/// claiming to be one is not worth walking the attributes of. Relay
/// payload never reaches the STUN parser (see the module docs on
/// demultiplexing).
pub const MAX_PROBE_BYTES: usize = 512;

/// Which of a session's two peers a probe comes from.
///
/// The helper keeps one slot per role, so a peer whose address changes
/// moves its own slot rather than competing for the other's, and a
/// client that rebinds its socket cannot lock the destination out of
/// the session it shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRole {
  /// The Mush client: the side that generates the nonce and drives
  /// signaling.
  Client,
  /// The destination running `mush server bootstrap`.
  Destination,
}

impl PeerRole {
  /// The other side of the same session: where this peer's relayed
  /// datagrams go.
  pub fn peer(self) -> Self {
    match self {
      Self::Client => Self::Destination,
      Self::Destination => Self::Client,
    }
  }
}

str_enum! {
  PeerRole => InvalidValue {
    Client => "client",
    Destination => "destination",
  }
}

/// Which of a session's two probe contexts a probe belongs to: the one
/// service that acts on it, named inside what the signature covers, so
/// that a probe sent at a candidate address is never a registration the
/// helper honors (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Aim {
  /// The jump helper, which registers the address the probe arrived
  /// from and relays to it afterwards.
  Helper,
  /// The session's other peer, which answers the probe and acts on
  /// nothing else in it.
  Peer,
}

str_enum! {
  Aim => InvalidValue {
    Helper => "helper",
    Peer => "peer",
  }
}

/// The session, side, and destination a probe claims, as carried in
/// `USERNAME`.
///
/// Wire form: `<nonce>:<role>:<aim>`, e.g.
/// `Wm9uY2VXb25jZVpvbmNlWg:client:helper`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProbeLabel {
  /// The session's nonce, as delivered to the helper over ssh.
  pub nonce: SessionNonce,
  /// Which peer of that session sent the probe.
  pub role: PeerRole,
  /// Which service the probe was sent to.
  pub aim: Aim,
}

impl ProbeLabel {
  /// The label for a probe `role` sends to the jump helper.
  pub fn to_helper(nonce: SessionNonce, role: PeerRole) -> Self {
    Self {
      nonce,
      role,
      aim: Aim::Helper,
    }
  }

  /// The label for a probe `role` sends to the session's other peer.
  pub fn to_peer(nonce: SessionNonce, role: PeerRole) -> Self {
    Self {
      nonce,
      role,
      aim: Aim::Peer,
    }
  }
}

impl std::fmt::Display for ProbeLabel {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "{}:{}:{}", self.nonce, self.role, self.aim)
  }
}

impl std::str::FromStr for ProbeLabel {
  type Err = InvalidValue;

  fn from_str(s: &str) -> Result<Self, Self::Err> {
    let (nonce, rest) = s.split_once(':').ok_or(InvalidValue)?;
    let (role, aim) = rest.split_once(':').ok_or(InvalidValue)?;
    Ok(Self {
      nonce: nonce.parse().map_err(|_| InvalidValue)?,
      role: role.parse()?,
      aim: aim.parse()?,
    })
  }
}

/// What a datagram arriving at a traversal socket is (RFC 7983
/// demultiplexing; see the module docs).
#[derive(Debug)]
pub enum Datagram<'a> {
  /// A STUN binding request: a reflection query and a registration.
  Binding(BindingRequest<'a>),
  /// STUN, but not a binding request: a response to something this
  /// service never sent, an unknown method, or a malformed message.
  /// Never answered.
  OtherStun,
  /// Not STUN at all, which on a helper socket means relay payload.
  Payload,
}

/// STUN's magic cookie, at bytes 4..8 of every message (RFC 8489
/// section 5).
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// The shortest STUN message: the 20-byte header alone.
const MIN_MESSAGE_BYTES: usize = 20;

/// Whether a datagram is STUN rather than session traffic.
///
/// The traversal socket sorts every arriving datagram with this
/// ([`crate::traversal`]), so it is a byte test and not a parse: it runs
/// on the session's receive path, where it must be cheap and a datagram
/// it misfiles is a packet the session loses.
///
/// RFC 7983 separates the two classes on the first byte's two high bits,
/// which are zero for STUN and hold QUIC's fixed bit. That bit alone is
/// not enough: RFC 9287 lets a QUIC endpoint clear it at random on any
/// packet whose peer offered to accept that, which quinn does by
/// default. So Mush's endpoints decline the offer ([`crate::transport`])
/// *and* this test requires the magic cookie, the field RFC 8489
/// prescribes for exactly this question. Either guard alone would do;
/// together, a session packet cannot be taken for a probe by accident or
/// by a peer that greases anyway.
pub fn is_stun(datagram: &[u8]) -> bool {
  datagram.len() >= MIN_MESSAGE_BYTES
    && datagram[0] >> 6 == 0
    && datagram[4..8] == MAGIC_COOKIE
}

/// Sorts one received datagram.
pub fn classify(datagram: &[u8]) -> Datagram<'_> {
  if !is_stun(datagram) {
    return Datagram::Payload;
  }
  if datagram.len() > MAX_PROBE_BYTES {
    return Datagram::OtherStun;
  }
  match Message::from_bytes(datagram) {
    Ok(message)
      if message.has_class(MessageClass::Request)
        && message.has_method(BINDING) =>
    {
      Datagram::Binding(BindingRequest {
        request_bytes: datagram.len(),
        message,
      })
    }
    // A malformed STUN-shaped datagram is not relay payload either:
    // the first byte already said it is not QUIC.
    Ok(_) | Err(_) => Datagram::OtherStun,
  }
}

/// A parsed STUN binding request, and the answer it may be given.
#[derive(Debug)]
pub struct BindingRequest<'a> {
  message: Message<'a>,
  request_bytes: usize,
}

impl BindingRequest<'_> {
  /// The session and role the request claims, or `None` when it carries
  /// no `USERNAME` or one that is not a label. An unlabeled request
  /// belongs to no session, so the helper has nothing to check it
  /// against.
  ///
  /// A claim and nothing more: what proves the sender holds the
  /// session's secret is [`authentic`](Self::authentic).
  pub fn label(&self) -> Option<ProbeLabel> {
    self
      .message
      .attribute::<Username>()
      .ok()?
      .username()
      .parse()
      .ok()
  }

  /// The request's STUN transaction id.
  ///
  /// A peer generates a fresh one per round and retransmits the same one
  /// on loss, so a service that acts on the address a probe arrives from
  /// can tell a retransmission from a replay of one it already acted on
  /// ([`crate::helper`]).
  pub fn transaction_id(&self) -> u128 {
    self.message.transaction_id().into()
  }

  /// Whether the request carries a valid `MESSAGE-INTEGRITY-SHA256`
  /// over `secret`.
  ///
  /// This is what stands between the helper and a forged source
  /// address: the message the HMAC covers is the one that names the
  /// session, so only a peer holding the secret can make the helper
  /// register an address or relay to it.
  pub fn authentic(&self, secret: &SessionSecret) -> bool {
    signed(&self.message, secret)
  }

  /// The success response reporting `observed` as the request's source
  /// address, signed with the session's secret.
  ///
  /// Refused when the response would be larger than the request, so the
  /// service can never be pointed at a spoofed source address as an
  /// amplifier. A real probe carries a label and an integrity attribute
  /// and is comfortably larger than any response; the guard covers the
  /// minimal hand-made requests an attacker would reach for instead.
  pub fn reflect(
    &self,
    observed: SocketAddr,
    secret: &SessionSecret,
  ) -> Result<Vec<u8>, AmplificationRefused> {
    let mut response =
      Message::builder_success(&self.message, MessageWriteVec::new());
    let addr = XorMappedAddress::new(observed, self.message.transaction_id());
    // The only errors are attribute-ordering ones (integrity and
    // fingerprint), which this message has none of, and integrity is
    // added last for exactly that reason.
    let _ = response.add_attribute(&addr);
    let _ = response.add_message_integrity(&credentials(secret), INTEGRITY);
    let response = response.finish();
    if response.len() > self.request_bytes {
      return Err(AmplificationRefused {
        request: self.request_bytes,
        response: response.len(),
      });
    }
    Ok(response)
  }
}

/// A reflection that would have answered more bytes than it was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
  "reflecting {response} bytes at a {request}-byte request would amplify"
)]
pub struct AmplificationRefused {
  /// Bytes in the request.
  pub request: usize,
  /// Bytes the response would have carried.
  pub response: usize,
}

/// One binding transaction from a probing peer's side: the request to
/// send, and the matching of the response that comes back.
///
/// Peers probe from the same socket their QUIC endpoint uses (design
/// doc, "Path establishment"), so the mapping a probe opens is the
/// mapping the session gets. Keep the transaction until the reflexive
/// address is in hand; retransmit its [`request`](Self::request) bytes
/// as needed, since a repeat of the same transaction is what STUN
/// expects of a lost probe.
#[derive(Debug, Clone)]
pub struct BindingTransaction {
  request: Vec<u8>,
  transaction: TransactionId,
  secret: Option<SessionSecret>,
}

impl BindingTransaction {
  /// Builds a binding request labeled for `label`'s session, role, and
  /// aim, and signed with the session's secret.
  pub fn new(label: ProbeLabel, secret: &SessionSecret) -> Self {
    Self::build(Some((label, *secret)), TransactionId::generate())
  }

  /// Builds a binding request with no session label and no signature,
  /// for a reflector that is not the jump helper: the `--stun <server>`
  /// opt-in of the design's "Degrading without the helper".
  pub fn unlabeled() -> Self {
    Self::build(None, TransactionId::generate())
  }

  /// [`new`](Self::new) over a transaction id the caller chose.
  ///
  /// Behind the `fuzzing` feature, and only because a target that
  /// generates a random id is not a function of its input: crash
  /// minimization, deduplication, and artifact replay all assume the same
  /// bytes drive the same run, and the integrity attribute covers the
  /// header, so a harness cannot splice an id in afterwards. A session
  /// probes with an id nobody can guess, which is what stops an off-path
  /// answer ([`reflexive`](Self::reflexive)), so nothing that ships
  /// chooses one.
  #[cfg(feature = "fuzzing")]
  pub fn seeded(label: ProbeLabel, secret: &SessionSecret, id: u128) -> Self {
    Self::build(Some((label, *secret)), TransactionId::from(id))
  }

  /// [`unlabeled`](Self::unlabeled) over a transaction id the caller
  /// chose; see [`seeded`](Self::seeded).
  #[cfg(feature = "fuzzing")]
  pub fn unlabeled_seeded(id: u128) -> Self {
    Self::build(None, TransactionId::from(id))
  }

  fn build(
    session: Option<(ProbeLabel, SessionSecret)>,
    transaction: TransactionId,
  ) -> Self {
    let mut request = Message::builder(
      MessageType::from_class_method(MessageClass::Request, BINDING),
      transaction,
      MessageWriteVec::new(),
    );
    // The label is a fixed 22-character nonce plus a short role, far
    // inside the attribute's bound, and integrity is added after it,
    // which is the only ordering rule either call has.
    if let Some((label, secret)) = &session {
      if let Ok(username) = Username::new(&label.to_string()) {
        let _ = request.add_attribute(&username);
      }
      let _ = request.add_message_integrity(&credentials(secret), INTEGRITY);
    }
    Self {
      request: request.finish(),
      transaction,
      secret: session.map(|(_, secret)| secret),
    }
  }

  /// The request bytes to send at a reflector.
  pub fn request(&self) -> &[u8] {
    &self.request
  }

  /// The reflexive address `datagram` reports, if it is this
  /// transaction's success response.
  ///
  /// The transaction id must match, which is STUN's own guard against
  /// an off-path attacker answering a probe it never saw, and a signed
  /// transaction additionally requires the answer to be signed with the
  /// same secret: a reflexive address becomes a candidate both peers
  /// then aim traffic at, so it has to come from the helper the session
  /// actually shares a secret with.
  pub fn reflexive(&self, datagram: &[u8]) -> Option<SocketAddr> {
    if datagram.len() > MAX_PROBE_BYTES {
      return None;
    }
    let message = Message::from_bytes(datagram).ok()?;
    if message.transaction_id() != self.transaction
      || !message.has_class(MessageClass::Success)
      || !message.has_method(BINDING)
    {
      return None;
    }
    if let Some(secret) = &self.secret
      && !signed(&message, secret)
    {
      return None;
    }
    let addr = message.attribute::<XorMappedAddress>().ok()?;
    Some(addr.addr(self.transaction))
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn nonce(seed: u8) -> SessionNonce {
    SessionNonce::from_bytes([seed; 16])
  }

  fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
  }

  fn label(seed: u8, role: PeerRole) -> ProbeLabel {
    ProbeLabel::to_helper(nonce(seed), role)
  }

  fn labels(seed: u8) -> Vec<ProbeLabel> {
    let mut labels = Vec::new();
    for role in [PeerRole::Client, PeerRole::Destination] {
      labels.push(ProbeLabel::to_helper(nonce(seed), role));
      labels.push(ProbeLabel::to_peer(nonce(seed), role));
    }
    labels
  }

  fn secret(seed: u8) -> SessionSecret {
    SessionSecret::from_bytes([seed; 16])
  }

  fn binding(datagram: &[u8]) -> BindingRequest<'_> {
    match classify(datagram) {
      Datagram::Binding(request) => request,
      other => panic!("not a binding request: {other:?}"),
    }
  }

  #[test]
  fn labels_round_trip_and_reject_the_unknown() {
    for label in labels(0x2a) {
      assert_eq!(label.to_string().parse::<ProbeLabel>().unwrap(), label);
      assert_eq!(label.role.peer().peer(), label.role);
    }
    // The aim is part of the label and not a default: a probe that does
    // not say where it was going is not a label at all, so nothing can
    // be replayed into the context it omits.
    for bad in [
      "",
      ":",
      "client",
      &nonce(1).to_string(),
      &format!("{}:", nonce(1)),
      &format!("{}:server", nonce(1)),
      &format!("{}:Client", nonce(1)),
      &format!("not-a-nonce:{}", PeerRole::Client),
      &format!("{}:{}", nonce(1), PeerRole::Client),
      &format!("{}:{}:", nonce(1), PeerRole::Client),
      &format!("{}:{}:Helper", nonce(1), PeerRole::Client),
      &format!("{}:{}:extra", nonce(1), PeerRole::Client),
      &format!("{}:{}:peer:peer", nonce(1), PeerRole::Client),
    ] {
      assert_eq!(bad.parse::<ProbeLabel>(), Err(InvalidValue), "{bad}");
    }
  }

  /// The aim is inside what the signature covers, so a probe sent at a
  /// peer cannot be turned into one the helper would register: editing
  /// the label breaks the integrity attribute, and leaving it alone
  /// leaves it saying where it was really going.
  #[test]
  fn a_probes_aim_cannot_be_edited() {
    let to_peer = ProbeLabel::to_peer(nonce(3), PeerRole::Client);
    let probe = BindingTransaction::new(to_peer, &secret(1));
    let request = binding(probe.request());
    assert_eq!(request.label(), Some(to_peer));
    assert!(request.authentic(&secret(1)));

    // The one byte that tells the two contexts apart.
    let mut edited = probe.request().to_vec();
    let at = edited
      .windows(4)
      .position(|window| window == b"peer")
      .expect("the label is in the request");
    edited[at..at + 4].copy_from_slice(b"help");
    assert!(!binding(&edited).authentic(&secret(1)));
  }

  #[test]
  fn a_probe_round_trips_through_reflection() {
    for observed in ["192.0.2.9:41234", "[2001:db8::9]:41234"] {
      let observed = addr(observed);
      let transaction =
        BindingTransaction::new(label(3, PeerRole::Client), &secret(1));
      let request = binding(transaction.request());
      assert_eq!(request.label(), Some(label(3, PeerRole::Client)));
      assert!(request.authentic(&secret(1)));
      let response = request.reflect(observed, &secret(1)).unwrap();
      assert_eq!(transaction.reflexive(&response), Some(observed));
    }
  }

  /// The transaction id is what stops an off-path answer being taken
  /// for the reflector's: a response to another transaction reports
  /// nothing, whatever address it claims.
  #[test]
  fn a_response_to_another_transaction_is_ignored() {
    let ours = BindingTransaction::new(label(3, PeerRole::Client), &secret(1));
    let theirs =
      BindingTransaction::new(label(3, PeerRole::Client), &secret(1));
    let response = binding(theirs.request())
      .reflect(addr("198.51.100.1:5000"), &secret(1))
      .unwrap();
    assert_eq!(theirs.reflexive(&response), Some(addr("198.51.100.1:5000")));
    assert_eq!(ours.reflexive(&response), None);
    // Nor is a request ever mistaken for a response.
    assert_eq!(ours.reflexive(ours.request()), None);
  }

  /// A probe the sender could not sign proves nothing, whatever session
  /// its label claims.
  #[test]
  fn a_probe_signed_with_another_secret_is_not_authentic() {
    let probe = BindingTransaction::new(label(3, PeerRole::Client), &secret(1));
    let request = binding(probe.request());
    assert_eq!(request.label(), Some(label(3, PeerRole::Client)));
    assert!(request.authentic(&secret(1)));
    assert!(!request.authentic(&secret(2)));
    // A hand-made probe carrying the label and no signature at all.
    let mut bare = Message::builder_request(BINDING, MessageWriteVec::new());
    let username = Username::new(&label(3, PeerRole::Client).to_string());
    bare.add_attribute(&username.unwrap()).unwrap();
    let bare = bare.finish();
    assert_eq!(binding(&bare).label(), Some(label(3, PeerRole::Client)));
    assert!(!binding(&bare).authentic(&secret(1)));
    // And one whose body was edited after signing.
    let mut tampered = probe.request().to_vec();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert!(!binding(&tampered).authentic(&secret(1)));
  }

  /// A probe whose integrity attribute is not the full-length SHA-256
  /// tag this side chose is not authentic: the codec reads the
  /// algorithm off the message, so RFC 5389's SHA-1 `MESSAGE-INTEGRITY`
  /// would otherwise be accepted, and a truncation to the 16 bytes the
  /// attribute parser allows still verifies as SHA-256. Both still need
  /// the secret, so what this refuses is a downgrade, not a forgery.
  #[test]
  fn a_probe_signed_the_old_way_is_not_authentic() {
    let label = label(3, PeerRole::Client);
    let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    message
      .add_attribute(&Username::new(&label.to_string()).unwrap())
      .unwrap();
    message
      .add_message_integrity(&credentials(&secret(1)), IntegrityAlgorithm::Sha1)
      .unwrap();
    let sha1 = message.finish();
    // The codec accepts it; this crate does not.
    assert!(matches!(
      Message::from_bytes(&sha1)
        .unwrap()
        .validate_integrity(&credentials(&secret(1))),
      Ok(IntegrityAlgorithm::Sha1)
    ));
    assert_eq!(binding(&sha1).label(), Some(label));
    assert!(!binding(&sha1).authentic(&secret(1)));

    let truncated = truncated_probe(label, &secret(1), 16);
    assert!(matches!(
      Message::from_bytes(&truncated)
        .unwrap()
        .validate_integrity(&credentials(&secret(1))),
      Ok(IntegrityAlgorithm::Sha256)
    ));
    assert!(!binding(&truncated).authentic(&secret(1)));
    // The same construction at full length is the ordinary probe, so
    // the test is measuring the truncation and nothing else.
    let full = truncated_probe(label, &secret(1), 32);
    assert!(binding(&full).authentic(&secret(1)));
    assert!(!binding(&full).authentic(&secret(2)));
  }

  /// A binding request carrying a `MESSAGE-INTEGRITY-SHA256` truncated
  /// to `tag` bytes, signed correctly for the length it claims (RFC
  /// 8489 section 14.6 computes the HMAC over a length field that
  /// includes the attribute).
  fn truncated_probe(
    label: ProbeLabel,
    secret: &SessionSecret,
    tag: usize,
  ) -> Vec<u8> {
    let mut message = Message::builder_request(BINDING, MessageWriteVec::new());
    message
      .add_attribute(&Username::new(&label.to_string()).unwrap())
      .unwrap();
    let mut bytes = message.finish();
    let offset = bytes.len();
    let length = u16::try_from(offset + 4 + tag - 20).unwrap();
    let mut header = [0u8; 4];
    header[..2].copy_from_slice(&bytes[..2]);
    header[2..].copy_from_slice(&length.to_be_bytes());
    let key = credentials(secret).make_key(INTEGRITY);
    let hmac =
      MessageIntegritySha256::compute(&[&header, &bytes[4..offset]], &key)
        .unwrap();
    bytes[2..4].copy_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&0x001cu16.to_be_bytes());
    bytes.extend_from_slice(&u16::try_from(tag).unwrap().to_be_bytes());
    bytes.extend_from_slice(&hmac[..tag]);
    bytes
  }

  /// The answer side takes the same rule: a reflection signed the old
  /// way adds no reflexive candidate.
  #[test]
  fn a_reflection_signed_the_old_way_is_not_believed() {
    let ours = BindingTransaction::new(label(3, PeerRole::Client), &secret(1));
    let request = binding(ours.request());
    let mut response =
      Message::builder_success(&request.message, MessageWriteVec::new());
    response
      .add_attribute(&XorMappedAddress::new(
        addr("203.0.113.9:41000"),
        request.message.transaction_id(),
      ))
      .unwrap();
    response
      .add_message_integrity(&credentials(&secret(1)), IntegrityAlgorithm::Sha1)
      .unwrap();
    assert_eq!(ours.reflexive(&response.finish()), None);
  }

  /// A reflection answer is believed only from the helper the session
  /// shares its secret with: a matching transaction id alone must not be
  /// enough to add a candidate both peers then aim traffic at.
  #[test]
  fn a_reflection_signed_with_another_secret_is_not_believed() {
    let ours = BindingTransaction::new(label(3, PeerRole::Client), &secret(1));
    let forged = binding(ours.request())
      .reflect(addr("203.0.113.9:41000"), &secret(2))
      .unwrap();
    assert_eq!(ours.reflexive(&forged), None);
    let honest = binding(ours.request())
      .reflect(addr("203.0.113.9:41000"), &secret(1))
      .unwrap();
    assert_eq!(ours.reflexive(&honest), Some(addr("203.0.113.9:41000")));
    // An unsigned transaction has no secret to check against, which is
    // the `--stun` opt-in: a third-party server shares nothing to sign
    // with, so the transaction id is the only guard there.
    let plain = BindingTransaction::unlabeled();
    let answer =
      unsigned_reflection(plain.request(), addr("203.0.113.9:41000"));
    assert_eq!(plain.reflexive(&answer), Some(addr("203.0.113.9:41000")));
    // A signed transaction refuses the same unsigned answer.
    let answer = unsigned_reflection(ours.request(), addr("203.0.113.9:41000"));
    assert_eq!(ours.reflexive(&answer), None);
  }

  /// A plain RFC 8489 success response with no integrity attribute:
  /// what a third-party STUN server answers.
  fn unsigned_reflection(request: &[u8], observed: SocketAddr) -> Vec<u8> {
    let message = Message::from_bytes(request).unwrap();
    let mut response =
      Message::builder_success(&message, MessageWriteVec::new());
    let addr = XorMappedAddress::new(observed, message.transaction_id());
    response.add_attribute(&addr).unwrap();
    response.finish()
  }

  /// The demultiplexing rule, in both directions: no QUIC packet may be
  /// read as a probe and no probe as payload.
  #[test]
  fn datagrams_demultiplex_by_class() {
    let probe =
      BindingTransaction::new(label(7, PeerRole::Destination), &secret(1));
    assert!(matches!(classify(probe.request()), Datagram::Binding(_)));
    // Long header (0xc0..) and short header (0x40..), the only two
    // shapes a QUIC packet has.
    for first in [0xc3u8, 0x40, 0x5f, 0xff] {
      let mut packet = probe.request().to_vec();
      packet[0] = first;
      assert!(matches!(classify(&packet), Datagram::Payload), "{first:#x}");
    }
    assert!(matches!(classify(&[]), Datagram::Payload));
  }

  /// A greased QUIC packet (RFC 9287: the fixed bit cleared at random)
  /// looks exactly like STUN to the first-byte test alone. Reading one
  /// as a probe would take it off the session's receive path, which is
  /// packet loss the session cannot see -- so the cookie has to be what
  /// decides.
  #[test]
  fn a_greased_quic_packet_is_never_a_probe() {
    // A short-header packet whose fixed bit is cleared, with a
    // connection id and payload that are otherwise arbitrary bytes.
    let mut packet = vec![0x01u8];
    packet.extend((0..64u8).map(|byte| byte.wrapping_mul(7)));
    assert!(!is_stun(&packet));
    assert!(matches!(classify(&packet), Datagram::Payload));
    // Even one carrying the cookie's bytes somewhere other than the
    // header field they belong in.
    let mut packet = vec![0x01u8, 0, 0, 0, 0, 0, 0, 0];
    packet.extend(MAGIC_COOKIE);
    packet.extend([0u8; 32]);
    assert!(matches!(classify(&packet), Datagram::Payload));
  }

  /// A STUN-shaped datagram that is not a binding request is never
  /// answered, and never treated as payload either.
  #[test]
  fn only_binding_requests_are_answered() {
    let probe = BindingTransaction::new(label(7, PeerRole::Client), &secret(1));
    let response = binding(probe.request())
      .reflect(addr("192.0.2.1:1000"), &secret(1))
      .unwrap();
    assert!(matches!(classify(&response), Datagram::OtherStun));
    // Overlong STUN-shaped input is not walked, and truncated or
    // cookie-less input is not STUN at all.
    let mut overlong = vec![0u8; MAX_PROBE_BYTES + 1];
    overlong[4..8].copy_from_slice(&MAGIC_COOKIE);
    assert!(matches!(classify(&overlong), Datagram::OtherStun));
    for datagram in [&probe.request()[..12], &[0u8; 20][..]] {
      assert!(matches!(classify(datagram), Datagram::Payload));
    }
    // A truncated probe that still carries the cookie is STUN, and the
    // codec is what refuses it.
    assert!(matches!(
      classify(&probe.request()[..20]),
      Datagram::OtherStun
    ));
  }

  /// A binding request with no label belongs to no session.
  #[test]
  fn an_unlabeled_request_has_no_session() {
    let bare =
      Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    assert_eq!(binding(&bare).label(), None);
    let mut junk = Message::builder_request(BINDING, MessageWriteVec::new());
    junk
      .add_attribute(&Username::new("nobody").unwrap())
      .unwrap();
    let junk = junk.finish();
    assert_eq!(binding(&junk).label(), None);
  }

  /// The amplification bound: a response is never larger than the
  /// request that asked for it, so the bare 20-byte request an attacker
  /// would spoof is refused.
  #[test]
  fn reflection_never_answers_more_than_it_was_asked() {
    let probe = BindingTransaction::new(label(9, PeerRole::Client), &secret(1));
    for observed in ["192.0.2.9:1", "[2001:db8::9]:1"] {
      let observed = addr(observed);
      let reply = binding(probe.request())
        .reflect(observed, &secret(1))
        .unwrap();
      assert!(
        reply.len() <= probe.request().len(),
        "{} > {}",
        reply.len(),
        probe.request().len()
      );
    }
    let bare =
      Message::builder_request(BINDING, MessageWriteVec::new()).finish();
    assert_eq!(bare.len(), 20);
    // Neither a v4 nor a v6 response fits inside 20 bytes.
    assert!(
      binding(&bare)
        .reflect(addr("192.0.2.9:1"), &secret(1))
        .is_err()
    );
    assert_eq!(
      binding(&bare).reflect(addr("[2001:db8::9]:1"), &secret(1)),
      Err(AmplificationRefused {
        request: 20,
        response: 80,
      })
    );
  }
}

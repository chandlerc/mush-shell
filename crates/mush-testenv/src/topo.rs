// Part of the Mush project, under the Apache License v2.0 with LLVM
// Exceptions. See /LICENSE for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

//! Topology presets matching the shapes in `docs/design.md`.
//!
//! Every preset builds a fresh throwaway [`Lab`]; dropping the returned
//! struct tears the whole topology down. Construction is cheap (tens of
//! milliseconds), so each test builds its own.

use std::net::Ipv4Addr;

use anyhow::{Context, Result};
use patchbay::{Device, Firewall, Lab, Nat, Router, RouterBuilder};

use crate::util::{
  current_netns_inode, loosen_rp_filter, restrict_inbound_tcp, sweep_netns,
};

/// The netns identities of every node, captured at build time for
/// [`NetnsSweep`].
fn collect_netns(devices: &[&Device], routers: &[&Router]) -> Result<Vec<u64>> {
  let mut inodes = Vec::with_capacity(devices.len() + routers.len());
  for dev in devices {
    inodes.push(dev.run_sync(current_netns_inode)?);
  }
  for router in routers {
    inodes.push(router.run_sync(current_netns_inode)?);
  }
  Ok(inodes)
}

/// NAT/firewall models the harness can build, named after the design
/// doc's grades.
///
/// The middle tier between `PortRestricted` and `Symmetric` -- a
/// port-preserving symmetric NAT -- cannot be expressed with nftables and
/// is deliberately absent; the deterministic simulator (`mush-netsim`)
/// covers that model. See `docs/testing.md`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatMode {
  /// Full cone (RFC 4787 EIM + EIF), port-preserving. With the presets'
  /// one-device-per-edge layout this also models cloud-style 1:1
  /// port-preserving NAT, which is exact until a source-port collision --
  /// impossible with a single device behind the router.
  FullCone,
  /// Port-restricted cone (EIM + APDF): the standard home-router shape.
  PortRestricted,
  /// Symmetric (EDM): a fresh random mapping per destination.
  Symmetric,
  /// No translation; a stateful firewall drops unsolicited inbound. The
  /// device keeps a publicly routed address.
  FirewallOnly,
}

impl NatMode {
  fn apply(self, builder: RouterBuilder) -> RouterBuilder {
    match self {
      NatMode::FullCone => builder.nat(Nat::Open),
      NatMode::PortRestricted => builder.nat(Nat::Moderate),
      NatMode::Symmetric => builder.nat(Nat::Strict),
      NatMode::FirewallOnly => builder.firewall(Firewall::BlockInbound),
    }
  }

  /// Whether traffic from behind this edge appears with the router's WAN
  /// address (true) or the device's own address (false).
  fn translates(self) -> bool {
    !matches!(self, NatMode::FirewallOnly)
  }
}

/// The namespace identities a topology records at build time, SIGKILLing
/// whatever still lives in them on drop ([`sweep_netns`]): kill-on-drop
/// and `PR_SET_PDEATHSIG` reach only a direct child, so this is what
/// reaps an ssh session's remote tree (see `docs/testing.md`).
///
/// Every topology declares it as its FIRST field, which is what makes the
/// sweep run while the `Lab` beneath it still holds those namespaces
/// open: [`crate::procs_in_netns`] matches on `/proc/<pid>/ns/net`
/// inodes, and a torn-down namespace has no processes left to find. Only
/// [`Topology`] also reads it, to hand those inodes to a leak check; the
/// other two hold it purely for this `Drop`.
struct NetnsSweep(Vec<u64>);

impl Drop for NetnsSweep {
  fn drop(&mut self) {
    sweep_netns(&self.0);
  }
}

/// A client/dest pair with configurable edges, plus public vantage points.
///
/// The client and dest each sit behind their own edge router: a plain
/// public router when the corresponding mode is `None`, otherwise the
/// requested NAT/firewall. Two additional plain routers (`vantage_a`,
/// `vantage_b`) provide distinct public reflector addresses for mapping
/// observation, and `third_party` is a public router no preset or helper
/// ever contacts, reserved as the source of unsolicited traffic for
/// filtering checks.
pub struct Topology {
  netns: NetnsSweep,
  pub lab: Lab,
  pub client: Device,
  pub dest: Device,
  pub client_net: Router,
  pub dest_net: Router,
  pub vantage_a: Router,
  pub vantage_b: Router,
  pub third_party: Router,
  pub client_mode: Option<NatMode>,
  pub dest_mode: Option<NatMode>,
}

impl Topology {
  /// The netns identities of every node, for leak checks against
  /// `/proc/<pid>/ns/net` (see [`crate::procs_in_netns`]).
  pub fn netns_inodes(&self) -> &[u64] {
    &self.netns.0
  }

  /// The source address the public internet observes for the client's
  /// traffic: the edge router's WAN address under NAT, the client's own
  /// address otherwise.
  pub fn client_public_ip(&self) -> Result<Ipv4Addr> {
    match self.client_mode {
      Some(m) if m.translates() => {
        self.client_net.uplink_ip().context("client edge WAN ip")
      }
      _ => self.client.ip().context("client ip"),
    }
  }

  /// The client's own interface address.
  pub fn client_ip(&self) -> Result<Ipv4Addr> {
    self.client.ip().context("client ip")
  }

  /// The dest's own interface address. Reachable from the client only
  /// when the dest side does not translate (public or firewall-only).
  pub fn dest_ip(&self) -> Result<Ipv4Addr> {
    self.dest.ip().context("dest ip")
  }

  /// Gives the dest a second address on the same interface and subnet
  /// as its first, and returns it.
  ///
  /// A multi-homed destination, in a shape where routing is identical:
  /// same link, same gateway, same return path, so the only difference
  /// between the two addresses is which one a packet is sent to. A
  /// server bound to the unspecified address answers on both, and
  /// enumerating its interfaces hints both.
  pub async fn add_dest_alias(&self) -> Result<Ipv4Addr> {
    let cidr = self
      .dest_net
      .downstream_cidr()
      .context("dest net downstream cidr")?;
    // Devices are numbered up from the bottom of the subnet, so the top
    // host is free.
    let alias = cidr
      .hosts()
      .next_back()
      .context("dest net subnet has no host addresses")?;
    self
      .dest
      .iface("eth0")
      .context("dest eth0")?
      .add_ip(alias, cidr.prefix_len())
      .await?;
    Ok(alias)
  }
}

async fn build_pair(
  client_mode: Option<NatMode>,
  dest_mode: Option<NatMode>,
) -> Result<Topology> {
  let lab = Lab::new().await?;
  let mut client_net = lab.add_router("client-net");
  if let Some(m) = client_mode {
    client_net = m.apply(client_net);
  }
  let client_net = client_net.build().await?;
  let mut dest_net = lab.add_router("dest-net");
  if let Some(m) = dest_mode {
    dest_net = m.apply(dest_net);
  }
  let dest_net = dest_net.build().await?;
  let vantage_a = lab.add_router("vantage-a").build().await?;
  let vantage_b = lab.add_router("vantage-b").build().await?;
  let third_party = lab.add_router("third-party").build().await?;
  let client = lab
    .add_device("client")
    .iface("eth0", client_net.id())
    .build()
    .await?;
  let dest = lab
    .add_device("dest")
    .iface("eth0", dest_net.id())
    .build()
    .await?;
  let netns_inodes = collect_netns(
    &[&client, &dest],
    &[&client_net, &dest_net, &vantage_a, &vantage_b, &third_party],
  )?;
  Ok(Topology {
    lab,
    client,
    dest,
    client_net,
    dest_net,
    vantage_a,
    vantage_b,
    third_party,
    client_mode,
    dest_mode,
    netns: NetnsSweep(netns_inodes),
  })
}

/// Client and dest both on public routers; no NAT or filtering anywhere.
pub async fn direct() -> Result<Topology> {
  build_pair(None, None).await
}

/// Client behind the given edge; dest public.
pub async fn client_nat(mode: NatMode) -> Result<Topology> {
  build_pair(Some(mode), None).await
}

/// Client and dest each behind their own edge.
pub async fn nat_both(
  client_mode: NatMode,
  dest_mode: NatMode,
) -> Result<Topology> {
  build_pair(Some(client_mode), Some(dest_mode)).await
}

/// The design doc's jump topology: the dest's ssh is reachable from the
/// jump host, not from the client.
///
/// The client sits behind a port-restricted home NAT. The jump host is
/// dual-homed: a public interface on the internet core and a second
/// interface on the dest's LAN, so the jump reaches the dest over the LAN
/// no matter what edge shields it. The edge is the `dest_mode` passed to
/// [`jump_chain`]: `FirewallOnly` is the classic DMZ (public addresses,
/// unsolicited inbound dropped), while the NAT grades put the dest behind
/// NAT with the jump inside -- `Symmetric` being the relay-of-last-resort
/// case of the design doc's fallback order. [`jump_policy`] builds the
/// fourth shape, where no edge shields the dest at all and the jump
/// exists purely for ssh policy.
pub struct JumpTopo {
  _netns: NetnsSweep,
  pub lab: Lab,
  pub client: Device,
  pub jump: Device,
  pub dest: Device,
  /// The client's NAT.
  pub home: Router,
  /// Public core the jump's public interface attaches to.
  pub net: Router,
  /// The dest's edge, built from `dest_mode`.
  pub dmz: Router,
  /// The client's second uplink, present only under [`jump_roaming`].
  pub home_b: Option<Router>,
  /// An extra bastion in front of [`jump`](Self::jump) on the public
  /// core, present only under [`jump_chain_two_hops`]: the first hop of
  /// `-J a,b`, with no interface on the dest's LAN and so no way to reach it.
  pub first_hop: Option<Device>,
  /// The edge model shielding the dest; `None` under [`jump_policy`],
  /// where the dest sits on a plain public router and only its own ssh
  /// policy keeps the client out.
  pub dest_mode: Option<NatMode>,
  /// The edge the client sits behind.
  pub client_mode: NatMode,
}

impl JumpTopo {
  /// The jump host's public address: what the client dials.
  pub fn jump_public_ip(&self) -> Result<Ipv4Addr> {
    self
      .jump
      .iface("eth0")
      .context("jump eth0")?
      .ip()
      .context("jump eth0 ip")
  }

  /// The first bastion of a two-hop chain; see
  /// [`first_hop`](Self::first_hop).
  pub fn first_hop_ip(&self) -> Result<Ipv4Addr> {
    self
      .first_hop
      .as_ref()
      .context(
        "this topology has one bastion; build it with \
                jump_chain_two_hops",
      )?
      .iface("eth0")
      .context("first hop eth0")?
      .ip()
      .context("first hop eth0 ip")
  }

  /// The jump host's address on the DMZ LAN.
  pub fn jump_dmz_ip(&self) -> Result<Ipv4Addr> {
    self
      .jump
      .iface("eth1")
      .context("jump eth1")?
      .ip()
      .context("jump eth1 ip")
  }

  /// The dest's address, reachable only from inside its LAN (i.e. from
  /// the jump). Private under the NAT grades.
  pub fn dest_ip(&self) -> Result<Ipv4Addr> {
    self.dest.ip().context("dest ip")
  }

  /// Routes the client's traffic through the given uplink, as a laptop
  /// moving from wifi to a phone does. Only under [`jump_roaming`],
  /// which is the topology that has a second one.
  pub async fn use_uplink(&self, uplink: Uplink) -> Result<()> {
    anyhow::ensure!(
      self.home_b.is_some(),
      "this topology has one uplink; build it with jump_roaming"
    );
    self.client.set_default_route(uplink.iface()).await
  }

  /// The WAN address the network observes when the client egresses
  /// through the given uplink.
  pub fn wan_ip(&self, uplink: Uplink) -> Result<Ipv4Addr> {
    let router = match uplink {
      Uplink::A => &self.home,
      Uplink::B => self
        .home_b
        .as_ref()
        .context("this topology has one uplink")?,
    };
    router.uplink_ip().context("uplink WAN ip")
  }

  /// The source address the public internet -- and so the jump --
  /// observes for the client's traffic.
  pub fn client_public_ip(&self) -> Result<Ipv4Addr> {
    self.home.uplink_ip().context("home NAT WAN ip")
  }
}

/// Builds the jump topology with the dest behind the given edge and the
/// client behind a port-restricted home NAT. See [`JumpTopo`].
pub async fn jump_chain(dest_mode: NatMode) -> Result<JumpTopo> {
  jump_chain_with(NatMode::PortRestricted, dest_mode).await
}

/// [`jump_chain`] with the client's own edge chosen too.
///
/// The client's grade decides what its reflexive address is worth: a
/// port-preserving edge (`FullCone` in the presets' one-device layout)
/// makes the address the jump observes usable for the destination's
/// reverse punch, which is the design's degradation path when no helper
/// is available.
pub async fn jump_chain_with(
  client_mode: NatMode,
  dest_mode: NatMode,
) -> Result<JumpTopo> {
  build_jump(Shape {
    client_mode,
    dest_mode: Some(dest_mode),
    ..Shape::default()
  })
  .await
}

/// [`jump_chain_with`] with a second bastion in front of the jump, for
/// the design's chained `-J a,b` (design doc, "Bootstrap through the
/// jump").
///
/// The extra hop sits on the public core with no interface on the dest's
/// LAN, so it can carry the ssh chain and nothing else: what reaches the
/// destination is still the last hop, which is where the helper runs.
pub async fn jump_chain_two_hops(
  client_mode: NatMode,
  dest_mode: NatMode,
) -> Result<JumpTopo> {
  build_jump(Shape {
    client_mode,
    dest_mode: Some(dest_mode),
    first_hop: true,
    ..Shape::default()
  })
  .await
}

/// The "jump for ssh policy, UDP wide open" shape (design doc, "Path
/// establishment": *jump required for ssh policy but UDP actually
/// reachable*): the dest sits on a plain public router and drops
/// inbound TCP from everyone but the jump.
///
/// This is the topology Mush's direct candidates exist for. The
/// bootstrap has to traverse the jump exactly as `ssh -J` would, while
/// the QUIC session goes straight to the destination, so a session here
/// proves the two halves are independent.
pub async fn jump_policy() -> Result<JumpTopo> {
  let topo = build_jump(Shape::default()).await?;
  restrict_inbound_tcp(&topo.dest, topo.jump_dmz_ip()?)?;
  Ok(topo)
}

/// [`jump_chain_with`] with a second uplink under the client, so a
/// session established through the bastion can then be made to move.
///
/// The escalation [`RoamingTopo`] offers, on the topology the punched
/// and relayed paths run on: a relayed session's registration with the
/// helper is tied to the mapping it was made from, and an uplink switch
/// is what takes that mapping away.
pub async fn jump_roaming(
  client_mode: NatMode,
  dest_mode: NatMode,
) -> Result<JumpTopo> {
  build_jump(Shape {
    client_mode,
    dest_mode: Some(dest_mode),
    second_uplink: true,
    ..Shape::default()
  })
  .await
}

/// Which of the jump topology's variations to build.
#[derive(Clone, Copy)]
struct Shape {
  client_mode: NatMode,
  /// The dest's edge; `None` puts it on a plain public router.
  dest_mode: Option<NatMode>,
  second_uplink: bool,
  first_hop: bool,
}

impl Default for Shape {
  fn default() -> Self {
    Self {
      client_mode: NatMode::PortRestricted,
      dest_mode: None,
      second_uplink: false,
      first_hop: false,
    }
  }
}

async fn build_jump(shape: Shape) -> Result<JumpTopo> {
  let Shape {
    client_mode,
    dest_mode,
    second_uplink,
    first_hop,
  } = shape;
  let lab = Lab::new().await?;
  let home = client_mode.apply(lab.add_router("home")).build().await?;
  let home_b = match second_uplink {
    true => Some(client_mode.apply(lab.add_router("home-b")).build().await?),
    false => None,
  };
  let net = lab.add_router("net").build().await?;
  let mut dmz = lab.add_router("dmz");
  if let Some(mode) = dest_mode {
    dmz = mode.apply(dmz);
  }
  let dmz = dmz.build().await?;
  let first_hop = match first_hop {
    true => Some(
      lab
        .add_device("hop")
        .iface("eth0", net.id())
        .build()
        .await?,
    ),
    false => None,
  };
  let mut client = lab.add_device("client").iface("eth0", home.id());
  if let Some(home_b) = &home_b {
    client = client.iface("eth1", home_b.id()).default_via("eth0");
  }
  let client = client.build().await?;
  if home_b.is_some() {
    loosen_rp_filter(&client, &["eth0", "eth1"])?;
  }
  let jump = lab
    .add_device("jump")
    .iface("eth0", net.id())
    .iface("eth1", dmz.id())
    .default_via("eth0")
    .build()
    .await?;
  let dest = lab
    .add_device("dest")
    .iface("eth0", dmz.id())
    .build()
    .await?;

  // The jump forwards asymmetrically (in on the public interface, out on
  // the DMZ interface), which strict reverse-path filtering drops.
  loosen_rp_filter(&jump, &["eth0", "eth1"])?;

  let mut routers: Vec<&Router> = vec![&home, &net, &dmz];
  if let Some(home_b) = &home_b {
    routers.push(home_b);
  }
  let mut devices: Vec<&Device> = vec![&client, &jump, &dest];
  if let Some(first_hop) = &first_hop {
    devices.push(first_hop);
  }
  let netns_inodes = collect_netns(&devices, &routers)?;
  Ok(JumpTopo {
    lab,
    client,
    jump,
    dest,
    home,
    home_b,
    first_hop,
    net,
    dmz,
    dest_mode,
    client_mode,
    _netns: NetnsSweep(netns_inodes),
  })
}

/// One of a dual-homed client's two uplinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uplink {
  A,
  B,
}

impl Uplink {
  /// The client interface wired to this uplink. Both dual-homed presets
  /// ([`roaming`] and [`jump_roaming`]) number the client's interfaces
  /// in uplink order.
  fn iface(self) -> &'static str {
    match self {
      Uplink::A => "eth0",
      Uplink::B => "eth1",
    }
  }
}

/// A roaming client: dual-homed behind two independent port-restricted
/// NATs, with a public dest to observe the switch from.
///
/// Models the client-side path events Mush must survive: a route flip
/// to the other uplink ([`use_uplink`](Self::use_uplink)), and an uplink
/// dying outright, as on suspend or wifi loss
/// ([`fail_uplink`](Self::fail_uplink)). A mid-session NAT rebind that
/// keeps the address but invalidates every mapping is
/// `Router::flush_nat_state` on either uplink, which needs the
/// `conntrack` binary (see [`crate::conntrack_available`]).
pub struct RoamingTopo {
  _netns: NetnsSweep,
  pub lab: Lab,
  pub client: Device,
  pub dest: Device,
  pub uplink_a: Router,
  pub uplink_b: Router,
  pub dest_net: Router,
}

impl RoamingTopo {
  /// Routes the client's default route through the given uplink. Takes
  /// effect immediately for new flows.
  pub async fn use_uplink(&self, uplink: Uplink) -> Result<()> {
    self.client.set_default_route(uplink.iface()).await
  }

  /// Takes the given uplink's link down, as when wifi drops or a laptop
  /// suspends: the old path dies rather than merely going unused. Linux
  /// removes the routes over the interface, so traffic routed through it
  /// fails immediately.
  pub async fn fail_uplink(&self, uplink: Uplink) -> Result<()> {
    self
      .client
      .iface(uplink.iface())
      .context("uplink iface")?
      .link_down()
      .await
  }

  /// Brings a failed uplink back up; the default route over it is
  /// restored when it is the client's default-route interface.
  pub async fn restore_uplink(&self, uplink: Uplink) -> Result<()> {
    self
      .client
      .iface(uplink.iface())
      .context("uplink iface")?
      .link_up()
      .await
  }

  /// The WAN address the network observes when the client egresses
  /// through the given uplink.
  pub fn wan_ip(&self, uplink: Uplink) -> Result<Ipv4Addr> {
    let router = match uplink {
      Uplink::A => &self.uplink_a,
      Uplink::B => &self.uplink_b,
    };
    router.uplink_ip().context("uplink WAN ip")
  }

  /// The dest's public address.
  pub fn dest_ip(&self) -> Result<Ipv4Addr> {
    self.dest.ip().context("dest ip")
  }
}

/// Builds the roaming topology with uplink A active. See [`RoamingTopo`].
pub async fn roaming() -> Result<RoamingTopo> {
  let lab = Lab::new().await?;
  let uplink_a = lab
    .add_router("uplink-a")
    .nat(Nat::Moderate)
    .build()
    .await?;
  let uplink_b = lab
    .add_router("uplink-b")
    .nat(Nat::Moderate)
    .build()
    .await?;
  let dest_net = lab.add_router("dest-net").build().await?;
  let client = lab
    .add_device("client")
    .iface("eth0", uplink_a.id())
    .iface("eth1", uplink_b.id())
    .default_via("eth0")
    .build()
    .await?;
  let dest = lab
    .add_device("dest")
    .iface("eth0", dest_net.id())
    .build()
    .await?;

  loosen_rp_filter(&client, &["eth0", "eth1"])?;

  let netns_inodes =
    collect_netns(&[&client, &dest], &[&uplink_a, &uplink_b, &dest_net])?;
  Ok(RoamingTopo {
    lab,
    client,
    dest,
    uplink_a,
    uplink_b,
    dest_net,
    _netns: NetnsSweep(netns_inodes),
  })
}

//! MCP wrappers for the rustre-net crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::hex_encode;

pub struct NetIpChecksumTool;

pub struct NetIsPrivateAddrTool;

pub struct NetParseEthernetExtTool;

pub struct NetParseIcmpEchoTool;

pub struct NetParseIpv6FullTool;

pub struct NetParseEthernetV2Tool;
impl NetParseEthernetV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_ethernet_v2".to_string(), description: "Parse an Ethernet II frame from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseEthernetV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_ethernet(&bytes) { Ok(f) => Ok(ToolResult::text(json!({"ethertype":f.ethertype,"src":rustre_net::EthernetFrame::mac_to_string(&f.src_mac),"dst":rustre_net::EthernetFrame::mac_to_string(&f.dst_mac),"payload_len":f.payload.len(),"source":"rustre_net::parse_ethernet"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetParseIpv4V2Tool;
impl NetParseIpv4V2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_ipv4_v2".to_string(), description: "Parse an IPv4 packet from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseIpv4V2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_ipv4(&bytes) { Ok(p) => Ok(ToolResult::text(json!({"src":p.src.to_string(),"dst":p.dst.to_string(),"protocol":p.protocol,"ttl":p.ttl,"payload_len":p.payload.len(),"source":"rustre_net::parse_ipv4"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetParseIpv6V2Tool;
impl NetParseIpv6V2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_ipv6_v2".to_string(), description: "Parse an IPv6 packet from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseIpv6V2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_ipv6(&bytes) { Ok(p) => Ok(ToolResult::text(json!({"src":p.src.to_string(),"dst":p.dst.to_string(),"protocol":p.protocol,"ttl":p.ttl,"payload_len":p.payload.len(),"source":"rustre_net::parse_ipv6"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetParseTcpV2Tool;
impl NetParseTcpV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_tcp_v2".to_string(), description: "Parse a TCP segment from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseTcpV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_tcp(&bytes) { Ok(s) => Ok(ToolResult::text(json!({"src_port":s.src_port,"dst_port":s.dst_port,"seq":s.seq,"ack":s.ack,"flags":s.flags.to_string(),"window":s.window,"payload_len":s.payload.len(),"source":"rustre_net::parse_tcp"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetParseUdpV2Tool;
impl NetParseUdpV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_udp_v2".to_string(), description: "Parse a UDP datagram from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseUdpV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_udp(&bytes) { Ok(u) => Ok(ToolResult::text(json!({"src_port":u.src_port,"dst_port":u.dst_port,"payload_len":u.payload.len(),"source":"rustre_net::parse_udp"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetParseIcmpV2Tool;
impl NetParseIcmpV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_icmp_v2".to_string(), description: "Parse an ICMP message from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseIcmpV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_icmp(&bytes) { Ok(i) => Ok(ToolResult::text(json!({"type":i.icmp_type,"code":i.code,"checksum":i.checksum,"payload_len":i.payload.len(),"source":"rustre_net::parse_icmp"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetParseArpV2Tool;
impl NetParseArpV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_parse_arp_v2".to_string(), description: "Parse an ARP packet from hex bytes.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetParseArpV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::parse_arp(&bytes) { Ok(a) => Ok(ToolResult::text(json!({"op":a.op.to_string(),"sha":a.sha_str(),"ptype":a.ptype,"hlen":a.hlen,"plen":a.plen,"source":"rustre_net::parse_arp"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetDetectProtocolV2Tool;
impl NetDetectProtocolV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_detect_protocol_v2".to_string(), description: "Detect application protocol from ports and payload.".to_string(), input_schema: json!({"type":"object","properties":{"src_port":{"type":"integer"},"dst_port":{"type":"integer"},"data":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetDetectProtocolV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sp = args.get("src_port").and_then(Value::as_u64).unwrap_or(0) as u16; let dp = args.get("dst_port").and_then(Value::as_u64).unwrap_or(0) as u16; let bytes = crate::args_to_bytes_named(&args, "data").unwrap_or_default(); let name = rustre_net::detect_protocol(sp, dp, &bytes); Ok(ToolResult::text(json!({"protocol":name,"source":"rustre_net::detect_protocol"}).to_string())) } }

pub struct NetDecodeChunkedV2Tool;
impl NetDecodeChunkedV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_decode_chunked_v2".to_string(), description: "Decode HTTP chunked transfer encoding.".to_string(), input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetDecodeChunkedV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bytes = crate::args_to_bytes_named(&args, "data")?; match rustre_net::decode_chunked(&bytes) { Ok(d) => Ok(ToolResult::text(json!({"decoded_len":d.len(),"decoded_hex":hex_encode(&d),"source":"rustre_net::decode_chunked"}).to_string())), Err(e) => Err(McpError::InvalidParams(e.to_string())) } } }

pub struct NetIcmpTypeNameV2Tool;
impl NetIcmpTypeNameV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_icmp_type_name_v2".to_string(), description: "Return the name for an ICMP type code.".to_string(), input_schema: json!({"type":"object","properties":{"icmp_type":{"type":"integer"}},"required":["icmp_type"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetIcmpTypeNameV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("icmp_type").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'icmp_type'".into()))? as u8; Ok(ToolResult::text(json!({"name":rustre_net::icmp_type_name(t),"source":"rustre_net::icmp_type_name"}).to_string())) } }

pub struct NetIsMulticastAddrV2Tool;
impl NetIsMulticastAddrV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "net_is_multicast_addr_v2".to_string(), description: "Return true if IP address is multicast.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"string"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for NetIsMulticastAddrV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("addr").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let addr: std::net::IpAddr = s.parse().map_err(|e: std::net::AddrParseError| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"is_multicast":rustre_net::is_multicast_addr(addr),"is_private":rustre_net::is_private_addr(addr),"is_broadcast":rustre_net::is_broadcast_addr(addr),"source":"rustre_net::is_multicast_addr"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NetIpChecksumTool::definition(), Box::new(NetIpChecksumTool)),
        (NetIsPrivateAddrTool::definition(), Box::new(NetIsPrivateAddrTool)),
        (NetParseEthernetExtTool::definition(), Box::new(NetParseEthernetExtTool)),
        (NetParseIcmpEchoTool::definition(), Box::new(NetParseIcmpEchoTool)),
        (NetParseIpv6FullTool::definition(), Box::new(NetParseIpv6FullTool)),
        (NetParseEthernetV2Tool::definition(), Box::new(NetParseEthernetV2Tool)),
        (NetParseIpv4V2Tool::definition(), Box::new(NetParseIpv4V2Tool)),
        (NetParseIpv6V2Tool::definition(), Box::new(NetParseIpv6V2Tool)),
        (NetParseTcpV2Tool::definition(), Box::new(NetParseTcpV2Tool)),
        (NetParseUdpV2Tool::definition(), Box::new(NetParseUdpV2Tool)),
        (NetParseIcmpV2Tool::definition(), Box::new(NetParseIcmpV2Tool)),
        (NetParseArpV2Tool::definition(), Box::new(NetParseArpV2Tool)),
        (NetDetectProtocolV2Tool::definition(), Box::new(NetDetectProtocolV2Tool)),
        (NetDecodeChunkedV2Tool::definition(), Box::new(NetDecodeChunkedV2Tool)),
        (NetIcmpTypeNameV2Tool::definition(), Box::new(NetIcmpTypeNameV2Tool)),
        (NetIsMulticastAddrV2Tool::definition(), Box::new(NetIsMulticastAddrV2Tool)),
    ]
}

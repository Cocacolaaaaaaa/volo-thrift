use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use anyhow::{Context, Result};
use std::process;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,

    #[arg(short, long, default_value_t = 9090)]
    port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == args.interface)
        .with_context(|| format!("Interface {} not found", args.interface))?;

    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unsupported channel type"),
        Err(e) => anyhow::bail!("Error creating channel: {}", e),
    };
        

    println!("Listening on {} for Thrift traffic on port {}", args.interface, args.port);

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet = EthernetPacket::new(packet).unwrap();
                match ethernet.get_ethertype() {
                    EtherTypes::Ipv4 => process_ipv4_packet(&ethernet, args.port),
                    _ => (),
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
                process::exit(1);
            }
        }
    }
}

fn process_ipv4_packet(ethernet: &EthernetPacket, port: u16) {
    let ipv4 = Ipv4Packet::new(ethernet.payload()).unwrap();
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        let tcp = TcpPacket::new(ipv4.payload()).unwrap();
        if tcp.get_source() == port || tcp.get_destination() == port {
            process_thrift_payload(tcp.payload());
        }
    }
}

fn process_thrift_payload(payload: &[u8]) {
    let mut offset = 0;
    
    // 检查协议头和版本
    if payload.len() < 4 {
        return;
    }

    let protocol_id = payload[0];
    let protocol_version = payload[1];
    let is_compact = protocol_id == 0x82 && (protocol_version & 0x1F) == 0x01;
    let is_binary = protocol_id == 0x80 && protocol_version == 0x01;

    if !is_compact && !is_binary {
        return;
    }

    // 解析消息类型和版本
    let message_type = if is_compact {
        (payload[2] & 0x07) as u8  // Compact协议的消息类型在第三个字节的低3位
    } else {
        let version_and_type = i32::from_be_bytes(payload[..4].try_into().unwrap());
        (version_and_type & 0xFF) as u8
    };
    offset += if is_compact { 3 } else { 4 }; // Compact协议头长度不同

    // 读取方法名（Compact协议使用长度前缀字符串）
    let (name_len, method_name) = match read_string(payload, &mut offset) {
        Some(v) => v,
        None => return,
    };

    // 读取序列号（Compact协议使用varint编码）
    let seq_id = if is_compact {
        let mut value = 0u32;
        let mut shift = 0;
        loop {
            if offset >= payload.len() {
                return;
            }
            let byte = payload[offset];
            offset += 1;
            value |= ((byte as u32 & 0x7F) << shift);
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return; // 防止溢出
            }
        }
        (value >> 1) as u32 ^ (!(value & 1) + 1) // ZigZag解码
    } else {
        if payload.len() < offset + 4 {
            return;
        }
        let id = u32::from_be_bytes(payload[offset..offset+4].try_into().unwrap());
        offset += 4;
        id
    };

    // 剩余部分为消息体
    let body = &payload[offset..];

    println!("Thrift Message [{}]:", if is_compact { "Compact" } else { "Binary" });
    println!("  Method: {}", method_name);
    println!("  Type: {} ({})", message_type, message_type_str(message_type));
    println!("  Seq ID: {}", seq_id);
    println!("  Body length: {} bytes", body.len());
    println!("  Body (hex): {}", hex::encode(body));
    println!();
}

fn read_string(payload: &[u8], offset: &mut usize) -> Option<(usize, String)> {
    if payload.len() < *offset + 4 {
        return None;
    }
    
    let len = u32::from_be_bytes(payload[*offset..*offset+4].try_into().unwrap()) as usize;
    *offset += 4;
    
    if payload.len() < *offset + len {
        return None;
    }
    
    let s = String::from_utf8_lossy(&payload[*offset..*offset+len]).to_string();
    *offset += len;
    Some((len, s))
}

fn message_type_str(t: u8) -> &'static str {
    match t {
        1 => "Call",
        2 => "Reply",
        3 => "Exception",
        4 => "Oneway",
        _ => "Unknown",
    }
}
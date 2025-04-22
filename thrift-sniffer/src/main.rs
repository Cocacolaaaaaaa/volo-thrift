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
    if payload.is_empty() {
        return;
    }
    println!("Full Payload (hex bytes):");
    for (i, byte) in payload.iter().enumerate() {
        print!("{:02X} ", byte);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    println!();

    let mut cursor = 0;

    // Read message size (4 bytes)
    let _message_size = read_u32(payload, &mut cursor);
    println!("Message size: {}", _message_size);

    // Read version (1 byte high nibble = message type, low 3 bytes = version)
    let version_type = read_u32(payload, &mut cursor);
    let message_type = (version_type >> 24) & 0xFF;
    println!("Message type: {} ({})", message_type, message_type_to_str(message_type));

    // Read method name
    let method_name_len = read_u32(payload, &mut cursor);
    let method_name = read_string(payload, &mut cursor, method_name_len as usize);
    println!("Method name: {}", method_name);

    // Read sequence id
    let seq_id = read_u32(payload, &mut cursor);
    println!("Seq ID: {}", seq_id);

    // === Start reading arguments ===
    // Each field starts with: field type (1 byte) + field id (2 bytes)

    loop {
        if cursor >= payload.len() {
            println!("End of payload.");
            break;
        }

        let field_type = read_u8(payload, &mut cursor);
        if field_type == 0x00 {
            println!("TType::STOP (0x00)");
            break;
        }

        let field_id = read_u16(payload, &mut cursor);
        println!("Field ID: {}, Type: {}", field_id, ttype_to_str(field_type));

        match field_type {
            0x08 => { // i32
                let value = read_i32(payload, &mut cursor);
                println!("  -> i32 Value: {}", value);
            }
            0x0B => { // string
                let len = read_u32(payload, &mut cursor);
                let s = read_string(payload, &mut cursor, len as usize);
                println!("  -> string: {}", s);
            }
            0x0C => { // struct
                println!("  -> Begin struct");
                continue;
            }
            _ => {
                println!("  !! Unknown type {}, skipping", field_type);
                break;
            }
        }
    }
}

fn read_u8(buf: &[u8], cursor: &mut usize) -> u8 {
    let val = buf[*cursor];
    *cursor += 1;
    val
}

fn read_u16(buf: &[u8], cursor: &mut usize) -> u16 {
    let val = u16::from_be_bytes([buf[*cursor], buf[*cursor + 1]]);
    *cursor += 2;
    val
}

fn read_u32(buf: &[u8], cursor: &mut usize) -> u32 {
    let val = u32::from_be_bytes([buf[*cursor], buf[*cursor + 1], buf[*cursor + 2], buf[*cursor + 3]]);
    *cursor += 4;
    val
}

fn read_i32(buf: &[u8], cursor: &mut usize) -> i32 {
    let val = i32::from_be_bytes([buf[*cursor], buf[*cursor + 1], buf[*cursor + 2], buf[*cursor + 3]]);
    *cursor += 4;
    val
}

fn read_string(buf: &[u8], cursor: &mut usize, len: usize) -> String {
    let s = &buf[*cursor..*cursor + len];
    *cursor += len;
    String::from_utf8_lossy(s).to_string()
}

fn message_type_to_str(t: u32) -> &'static str {
    match t {
        1 => "CALL",
        2 => "REPLY",
        3 => "EXCEPTION",
        4 => "ONEWAY",
        _ => "UNKNOWN",
    }
}

fn ttype_to_str(t: u8) -> &'static str {
    match t {
        0x00 => "STOP",
        0x01 => "VOID",
        0x02 => "BOOL",
        0x03 => "BYTE",
        0x04 => "DOUBLE",
        0x06 => "I16",
        0x08 => "I32",
        0x0A => "I64",
        0x0B => "STRING",
        0x0C => "STRUCT",
        0x0D => "MAP",
        0x0E => "SET",
        0x0F => "LIST",
        _ => "UNKNOWN",
    }
}

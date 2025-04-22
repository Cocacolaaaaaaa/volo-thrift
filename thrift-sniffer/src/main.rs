use clap::Parser;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use anyhow::{Context, Result};
use std::process;

//命令行参数
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

    // 指定的网卡
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == args.interface)
        .with_context(|| format!("Interface {} not found", args.interface))?;

    // 创建 data link 通道，拿到接收器 rx
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => anyhow::bail!("Unsupported channel type"),
        Err(e) => anyhow::bail!("Error creating channel: {}", e),
    };
        

    println!("Listening on {} for Thrift traffic on port {}", args.interface, args.port);

    
    // 持续接收并处理每个以太网帧
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

// 处理 IPv4 数据包
// 解析 TCP 数据包，检查源或目的端口是否匹配
fn process_ipv4_packet(ethernet: &EthernetPacket, port: u16) {
    let ipv4 = Ipv4Packet::new(ethernet.payload()).unwrap();
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        let tcp = TcpPacket::new(ipv4.payload()).unwrap();
        if tcp.get_source() == port || tcp.get_destination() == port {
            process_thrift_payload(tcp.payload());
        }
    }
}

//Thrift 报文预处理
fn process_thrift_payload(payload: &[u8]) {
    if payload.len() < 16 {
        return;
    }

    println!("Full Payload (hex):");
    dump_bytes(payload);

    // THeader 协议识别
    let protocol_id = payload[4];
    if protocol_id != 0x10 {
        println!("Not a THeader protocol. Skipping.");
        return;
    }

    // 读取 header length
    let header_len_words = payload[12] as usize;
    let header_len = header_len_words * 4;
    let base_header_len = 4 + 8;
    let header_total_len = base_header_len + header_len;

    if payload.len() <= header_total_len {
        println!("Invalid payload or THeader too large.");
        return;
    }

    // 从 header 末尾处寻找 0x80（BinaryProtocol 版本字节）
    let mut trans_offset = header_total_len;
    while trans_offset < payload.len() && payload[trans_offset] != 0x80 {
        trans_offset += 1;
    }

    if trans_offset + 4 > payload.len() {
        println!("Unable to find valid Thrift Binary payload.");
        return;
    }

    println!("\nStripped THeader. Parsing BinaryProtocol payload:");
    dump_bytes(&payload[trans_offset..]);

     // Thrift BinaryProtocol 解析
    parse_thrift_binary(&payload[trans_offset..]);
}

fn parse_thrift_binary(data: &[u8]) {
    let mut offset = 0;

    if data.len() < 4 {
        println!("Data too short to contain message header.");
        return;
    }

    // 读取 message type + version
    let message_type_and_version = u32::from_be_bytes(data[0..4].try_into().unwrap());
    offset += 4;

    let version = message_type_and_version & 0xffff0000;
    if version != 0x80010000 {
        println!("Unexpected Thrift binary version.");
        return;
    }

    let message_type = message_type_and_version & 0x000000ff;

    let message_type_str = match message_type {
        0x01 => "Call",
        0x02 => "Reply",
        0x03 => "Exception",
        0x04 => "Oneway",
        _ => "Unknown",
    };

    println!("Message Type: {} (0x{:02X})", message_type_str, message_type);

    // 读取方法名长度 + 方法名
    let name_len = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
    offset += 4;

    if data.len() < offset + name_len {
        println!("Payload too short to read method name.");
        return;
    }

    let method_name = String::from_utf8_lossy(&data[offset..offset+name_len]);
    println!("Method Name: {}", method_name);
    offset += name_len;

    //读取 Sequence ID
    let seq_id = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap());
    offset += 4;
    println!("Sequence ID: {}", seq_id);

    //解析字段列表
    println!("\n--- Begin Fields ---");
    while offset + 1 <= data.len() {
        let field_type = data[offset];
        offset += 1;

        if field_type == 0x00 {
            println!("Field STOP (0x00)");
            break;
        }

        if offset + 2 > data.len() {
            println!("Unexpected end while reading field ID.");
            break;
        }

        let field_id = u16::from_be_bytes(data[offset..offset+2].try_into().unwrap());
        offset += 2;

        print!("field {} type:", field_id);
        match field_type {
            0x0A => { // i64
                if offset + 8 > data.len() {
                    println!("Not enough data for i64.");
                    break;
                }
                let value = i64::from_be_bytes(data[offset..offset+8].try_into().unwrap());
                offset += 8;
                println!("i64 = {}", value);
            }
            0x0B => { // string
                if offset + 4 > data.len() {
                    println!("Not enough data for string length.");
                    break;
                }
                let len = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
                offset += 4;

                if offset + len > data.len() {
                    println!("String truncated.");
                    break;
                }

                let s = String::from_utf8_lossy(&data[offset..offset+len]);
                offset += len;
                println!("string = \"{}\"", s);
            }
            0x02 => { // bool
                if offset + 1 > data.len() {
                    println!("Not enough data for bool.");
                    break;
                }
                let value = data[offset] != 0;
                offset += 1;
                println!("bool = {}", value);
            }
            0x01 => { // double
                if offset + 8 > data.len() {
                    println!("Not enough data for double.");
                    break;
                }
                let value = f64::from_be_bytes(data[offset..offset+8].try_into().unwrap());
                offset += 8;
                println!("double = {}", value);
            }
            0x0C => {
                println!("Start of struct:");
                offset = parse_struct(data, offset);
            }        
            0x0F => {
                println!("Field Type 0x0F: Struct handling not implemented.");
                offset += 6;
            }
            _ => {
                println!("Unknown or unhandled type: 0x{:02X}", field_type);
                break;
            }
        }
    }
    println!("--- End Fields ---\n");
}

fn dump_bytes(data: &[u8]) {
    for (i, byte) in data.iter().enumerate() {
        print!("{:02X} ", byte);
        if (i + 1) % 16 == 0 {
            println!();
        }
    }
    if data.len() % 16 != 0 {
        println!();
    }
}

fn parse_struct(data: &[u8], mut offset: usize) -> usize {
    loop {
        if offset + 1 > data.len() {
            break;
        }
        let field_type = data[offset];
        offset += 1;

        if field_type == 0x00 {
            println!("End of struct (STOP).");
            break;
        }



        if offset + 2 > data.len() {
            println!("Unexpected end of data while reading field ID.");
            break;
        }

        let field_id = u16::from_be_bytes(data[offset..offset+2].try_into().unwrap());
        offset += 2;

        match field_type {
            0x0A => {
                let val = i64::from_be_bytes(data[offset..offset+8].try_into().unwrap());
                offset += 8;
                println!("field {} (i64): {}", field_id, val);
            }
            0x0B => {
                let len = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
                offset += 4;
                let s = String::from_utf8_lossy(&data[offset..offset+len]);
                offset += len;
                println!("field {} (string): {}", field_id, s);
            }
            0x0D => { // list
                let elem_type = data[offset]; // 获取元素类型
                offset += 2;
                let list_len = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
                offset += 4;
            
                println!("field {} (list):", field_id);
            
                for i in 0..list_len {
                    if offset + 4 > data.len() {
                        println!("Not enough data to read element length for index {}", i);
                        break;
                    }
                    
                    let len = u32::from_be_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
                    offset += 4;
            
                    if offset + len > data.len() {
                        println!("Not enough data to read element data for index {}", i);
                        break;
                    }
            
                    // 解析列表元素类型
                    match elem_type {
                        0x0A => { // 假设是 string 类型
                            let s = String::from_utf8_lossy(&data[offset..offset+len]);
                            offset += len;
                            println!("  [{}] string: {}", i, s);
                        }
                        0x0B => { // 假设是 i64 类型
                            if offset + 8 > data.len() {
                                println!("Not enough data to read i64 for index {}", i);
                                break;
                            }
                            let val = i64::from_be_bytes(data[offset..offset+8].try_into().unwrap());
                            offset += 8;
                            println!("  [{}] i64: {}", i, val);
                        }
                        _ => {
                            println!("  [{}] Unknown element type: 0x{:02X}", i, elem_type);
                            break;
                        }
                    }
                }
            }
            
            0x0C => {
                println!("field {} Start of struct:", field_id);
                offset = parse_struct(data, offset);
            }
            _ => {
                println!("Unknown field type: 0x{:02X}", field_type);
                break;
            }
        }
    }
    offset
}

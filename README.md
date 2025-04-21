# thrift-dump工具
volo-example为使用volo-thrift创建的服务端与客户端
thrift-sniffer为dump工具，拦截thrift通信数据流，根据thrift协议对二进制数据进行解析
# 使用方法
cd volo-example 
cargo run --bin server

cd thrift-sniffer
cargo run -- --interface {} --port {}
如 cargo run -- --interface lo --port 9090

cd volo-example 
cargo run --bin client

# failed
抓不到包orz 
我用的wsl，网络通信可能有问题，也有可能是逻辑有问题
事情多，也没时间去服务器测试了:<
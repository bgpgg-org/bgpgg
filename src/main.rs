use bgpgg::server::BgpServer;

fn main() {
    let server = BgpServer { peers: Vec::new() };

    server.run();
}

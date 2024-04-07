use std::net::{TcpListener, TcpStream};

pub struct Peer {}

pub struct BgpServer {
    pub peers: Vec<Peer>,
}

impl BgpServer {
    pub fn run(&self) {
        println!("Bgpgg server is running.");
        let listener = TcpListener::bind("127.0.0.1:179").unwrap();

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    self.add_peer(stream);
                }
                Err(e) => {}
            }
        }
    }

    fn add_peer(&self, stream: TcpStream) {}
}

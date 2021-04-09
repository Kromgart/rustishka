use tokio::net::TcpListener;

mod proxy;




#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Server starting...");

    let tcp_lsn = TcpListener::bind("127.0.0.1:8080").await?;
    println!("Listening on 127.0.0.1:8080");

    loop {
        let (mut stream, _addr) = tcp_lsn.accept().await?;
        tokio::spawn(async move {
            println!("---- INCOMING ----");
            if let Err(e) = proxy::handle_stream(&mut stream).await {
                println!("Error: {:?}", e);
            }
            println!("-----  END  ------");
        });
    }
}

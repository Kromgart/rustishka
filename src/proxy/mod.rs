use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};


mod parsing;


#[derive(Debug)]
pub enum ProxyError {
    ClientTcpRead(std::io::Error),
    ClientTcpWrite(std::io::Error),

    Hyper(hyper::Error),
    Parse(parsing::ParserError),

    //ServerTcpRead(std::io::Error),
    //ServerTcpWrite(std::io::Error),

    ServerTcpConnect(std::io::Error),
    TcpUpstream(std::io::Error),
    TcpDownstream(std::io::Error),
}


pub type ProxyResult = Result<(), ProxyError>;

const PEEK_TEST: &[u8] = b"CONNECT ";
const PEEK_LEN: usize = PEEK_TEST.len();

pub async fn handle_stream(mut cl_stream: TcpStream) -> ProxyResult {
    {
        let mut peek_buf = [0u8; PEEK_LEN];

        let rd = cl_stream.peek(peek_buf.as_mut()).await.map_err(ProxyError::ClientTcpRead)?;
        if rd < PEEK_LEN {
            if rd > 0 {
                println!("Proxy: First read too small");
                cl_stream
                    .write(
                    b"HTTP/1.1 500 Internal Server Error\r\n\
                    Content-Length: 27\r\n\
                    Connection: close\r\n\r\n\
                    Proxy: First read too small")
                    .await.map_err(ProxyError::ClientTcpWrite)?;
            } else {
                println!("Proxy: client sent EOF (0-length 'read')");
            }

            return Ok(());
        } else if peek_buf.as_ref() == PEEK_TEST {
            return handle_connect_verb::<PEEK_LEN>(cl_stream).await;
        }
    }

    handle_plain_http(cl_stream).await
}


async fn handle_plain_http<IO>(cl_stream: IO) -> ProxyResult
    where IO: AsyncReadExt + AsyncWriteExt + Unpin + 'static
{
    /*
    cl_stream
        .write(
        b"HTTP/1.1 200 OK\r\n\
        Content-Length: 13\r\n\
        Connection: close\r\n\r\n\
        Proxy: HELLO!")
        .await.map_err(ProxyError::ClientTcpWrite)?;

    return Ok(());
    */

    use hyper::{Body, Request, Response, Client};

    let http_client = std::sync::Arc::new(Client::new());

    let service = hyper::service::service_fn(move |mut req: Request<Body>| { 
        let http_client = http_client.clone();
        async move {
            // NOTE: hyper requires absolute URI in Request
            let uri = req.uri();
            println!("Client -> {} {}", req.method(), uri);

            //----- Process/transform uri ----
            if uri.path() == "favico.ico" {
                return Ok(Response::new(Body::from("hyper favico!")));  // as Result<Response<Body>, hyper::Error>
            }
            //-------------------------------


            *req.version_mut() = hyper::Version::HTTP_11;

            //----- Process/transform headers ----
            let hs = req.headers_mut();

            use hyper::header as H;
            let _ = hs.remove(H::CONNECTION);
            //-----------------------------------


            http_client.request(req).await
        }
    });


    let h = hyper::server::conn::Http::new()
        .http1_only(true)
        .http1_keep_alive(true)
        .serve_connection(cl_stream, service);

    h.await.map_err(ProxyError::Hyper)
}


async fn handle_connect_verb<const SKIP: usize>(mut cl_stream: TcpStream) -> ProxyResult {

    let srv_stream = {
        let mut buf = [0u8; 8 * 1024];
        let mut parser = parsing::BufferedParser::new(&mut cl_stream, &mut buf);
        let _ = parser.skip_n(SKIP).await.map_err(ProxyError::Parse)?;
        let (dom_1, dom_2) = parser.parse_domain().await.map_err(ProxyError::Parse)?;
        let _ = parser.parse_const(b":", parsing::TokenType::Port).await.map_err(ProxyError::Parse)?;
        let (port_1, port_2) = parser.parse_port().await.map_err(ProxyError::Parse)?;
        let _ = parser.skip_until_endswith(b"\r\n\r\n").await.map_err(ProxyError::Parse)?;

        let domain = unsafe { parser.get_ascii(dom_1, dom_2) };
        let port: u16 = unsafe { atoi::atoi(parser.get(port_1, port_2)).expect("Cannot parse CONNECT port") };
    
        println!("Proxy: CONNECT to {}:{}", domain, port);

        TcpStream::connect((domain, port)).await.map_err(ProxyError::ServerTcpConnect)?
    };

    cl_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.map_err(ProxyError::ClientTcpWrite)?;

    let (mut srv_rx, mut srv_tx) = srv_stream.into_split();
    let (mut cl_rx, mut cl_tx) = cl_stream.into_split();

    let mut upstream = tokio::spawn(async move {
        let mut buf = [0u8; 8 * 1024];
        loop {
            if let 0 = send_data(&mut cl_rx, &mut srv_tx, &mut buf).await.map_err(ProxyError::TcpUpstream)? {
                return Ok::<usize, ProxyError>(0);
            }
        }
    });

    let mut downstream = tokio::spawn(async move {
        let mut buf = [0u8; 8 * 1024];
        loop {
            if let 0 = send_data(&mut srv_rx, &mut cl_tx, &mut buf).await.map_err(ProxyError::TcpDownstream)? {
                return Ok::<usize, ProxyError>(0);
            }
        }
    });

    //println!("Proxy: futures ready");

    tokio::select! {
        _ = &mut upstream => { (&mut downstream).abort() }
        _ = &mut downstream => { (&mut upstream).abort() }
    };
    
    println!("Proxy: tunnel ends");
    return Ok(());
}


async fn send_data(rx: &mut tokio::net::tcp::OwnedReadHalf, tx: &mut tokio::net::tcp::OwnedWriteHalf, buf: &mut[u8]) -> Result<usize, std::io::Error> {
    let n = rx.read(buf).await?;
    if n != 0 {
        tx.write_all(unsafe { buf.get_unchecked(0 .. n)}).await?;
        println!("tranferred bytes: {}", n);
    }

    Ok(n)
}

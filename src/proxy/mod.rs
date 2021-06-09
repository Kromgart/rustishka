use std::io::Error as IOErr;
//use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinError;

use tokio_rustls::webpki::{DNSName, DNSNameRef};

mod parsing;


#[derive(Debug)]
pub enum ProxyError {
    ClientTcpEOF,
    ClientTcpRead(IOErr),
    ClientTcpWrite(IOErr),

    Hyper(hyper::Error),
    Parse(parsing::ParserError),

    //ServerTcpEOF,
    ServerTcpRead(IOErr),
    //ServerTcpWrite(IOErr),

    ServerTcpConnect(IOErr),
    TcpTunnelUpstream(Result<IOErr, JoinError>),
    TcpTunnelDownstream(Result<IOErr, JoinError>),

    TlsDns(tokio_rustls::webpki::InvalidDNSNameError),
    TlsConnector(IOErr),
    TlsMissingCerts,
}


pub type ProxyResult<T> = Result<T, ProxyError>;

const PEEK_TEST: &[u8] = b"CONNECT ";
const PEEK_LEN: usize = PEEK_TEST.len();

pub async fn handle_stream(mut cl_stream: TcpStream, cfg: crate::Config) -> ProxyResult<()> {

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
        return handle_connect_verb::<PEEK_LEN>(cl_stream, &cfg).await;
    }

    handle_plain_http(cl_stream).await
}


async fn handle_plain_http<IO>(cl_stream: IO) -> ProxyResult<()>
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

use der_parser::oid;
static X509_SAN_OID: oid::Oid<'static>  = oid!(2.5.29.17);

async fn handle_connect_verb<const SKIP: usize>(mut cl_stream: TcpStream, cfg: &crate::Config) -> ProxyResult<()> {

    let (srv_stream, dns) = get_srv_stream::<SKIP>(&mut cl_stream).await?;

    match dns {
        None => {
            // Transparent TCP tunnel

            let (srv_rx, srv_tx) = srv_stream.into_split();
            let (cl_rx, cl_tx) = cl_stream.into_split();

            let mut upstream = tokio::spawn(stream_data(cl_rx, srv_tx));
            let mut downstream = tokio::spawn(stream_data(srv_rx, cl_tx));

            let res: ProxyResult<()> = tokio::select! {
                r = &mut upstream => { 
                    (&mut downstream).abort();
                    mk_res(r, ProxyError::TcpTunnelUpstream)
                }
                r = &mut downstream => { 
                    (&mut upstream).abort();
                    mk_res(r, ProxyError::TcpTunnelDownstream)
                }
            };

            //println!("TCP tunnel closed");
            res
        },
        Some(name) => {
            // Unwrap TLS
            use rustls::Session;
            let srv_stream = cfg.tls_connector.connect(name.as_ref(), srv_stream).await.map_err(ProxyError::TlsConnector)?;

            // TODO: move this to TLS handshake (get cert according to client's TLS SNI)
            let mitm_cert = make_mitm_cert(&srv_stream, &cfg.ca_cert);

            Ok(())
        }
    }
}


#[derive(Debug)]
pub enum MitmGenError {
    ServerNoCert,
    ServerCertParse(x509_parser::error::X509Error),
    ServerNoSanExt,
    ServerSanExtParse,
    ServerSanExtNonDNSName(String),

    CertGen(rcgen::RcgenError),
}


fn make_mitm_cert(srv_stream: &tokio_rustls::client::TlsStream<TcpStream>, ca_cert: &rcgen::Certificate) -> Result<(Vec<String>, Vec<u8>), MitmGenError> {
    use rustls::Session;
    use x509_parser::nom::Finish;
    use x509_parser::extensions::{ ParsedExtension, SubjectAlternativeName, GeneralName };

    let (_, cl_ses) = srv_stream.get_ref();
    let certs = cl_ses.get_peer_certificates().ok_or(MitmGenError::ServerNoCert)?;
    let cert = certs.get(0).ok_or(MitmGenError::ServerNoCert)?;
    let (_, cr) = x509_parser::parse_x509_certificate(cert.as_ref()).finish().map_err(MitmGenError::ServerCertParse)?; 
    let v = cr.extensions().get(&X509_SAN_OID).ok_or(MitmGenError::ServerNoSanExt)?;

    if let ParsedExtension::SubjectAlternativeName(SubjectAlternativeName { general_names: gnames }) = v.parsed_extension() { 

        let mut dnames_str = Vec::<String>::with_capacity(gnames.len());
        for gen_name in gnames {
            match gen_name {
                GeneralName::DNSName(dns_str) => dnames_str.push(String::from(*dns_str)),
                _ => return Err(MitmGenError::ServerSanExtNonDNSName(String::from(format!("{:?}", gen_name))))
            }
        }

        let cert_param = rcgen::CertificateParams::new(dnames_str.clone());
        let cert = rcgen::Certificate::from_params(cert_param).map_err(MitmGenError::CertGen)?;

        let cert_der = cert.serialize_der_with_signer(ca_cert).map_err(MitmGenError::CertGen)?;

        Ok((dnames_str, cert_der))
    } else {
        Err(MitmGenError::ServerSanExtParse)
    }
}


async fn stream_data(mut rx: tokio::net::tcp::OwnedReadHalf, mut tx: tokio::net::tcp::OwnedWriteHalf) -> Result<(), IOErr> {
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = rx.read(&mut buf).await?;
        if 0 != n {
            tx.write_all(unsafe { buf.get_unchecked(0 .. n)}).await?;
            //println!("tranferred bytes: {}", n);
        } else {
            return Ok(());
        }
    }
}


#[inline]
fn mk_res<F>(r: Result<Result<(), IOErr>, JoinError>, maperr: F) -> ProxyResult<()>
where F: Fn(Result<IOErr, JoinError>) -> ProxyError
{
    match r {
        Ok(r2) => {
            match r2 {
                Ok(()) => Ok(()),
                Err(e) => Err(maperr(Ok(e))),
            }
        },
        Err(join_err) => Err(maperr(Err(join_err)))
    }
}


async fn get_srv_stream<const SKIP: usize>(cl_stream: &mut TcpStream) -> ProxyResult<(TcpStream, Option<DNSName>)> {
    let mut buf = [0u8; 1024];
    let mut parser = parsing::BufferedParser::new(cl_stream, &mut buf);

    let _ = parser.skip_n(SKIP).await.map_err(ProxyError::Parse)?;
    let (dom_1, dom_2) = parser.parse_domain().await.map_err(ProxyError::Parse)?;
    let _ = parser.parse_const(b":", parsing::TokenType::Port).await.map_err(ProxyError::Parse)?;
    let (port_1, port_2) = parser.parse_port().await.map_err(ProxyError::Parse)?;
    let _ = parser.skip_until_endswith(b"\r\n\r\n").await.map_err(ProxyError::Parse)?;

    drop(parser);

    let domain = unsafe { std::str::from_utf8_unchecked(buf.get_unchecked(dom_1 .. dom_2)) };
    let port: u16 = unsafe { atoi::atoi(buf.get_unchecked(port_1 .. port_2)).expect("Cannot parse CONNECT port") };

    // TODO: check blocked domains
    // ...

    let srv_stream = TcpStream::connect((domain, port)).await.map_err(ProxyError::ServerTcpConnect)?;

    cl_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.map_err(ProxyError::ClientTcpWrite)?;
    
    let bypass = {
        // TODO: check bypass domains
        if domain == "docs.rs" {
            true
        } else {
            let mut tls_rec_type = 0u8;
            let rd = cl_stream.peek(std::slice::from_mut(&mut tls_rec_type)).await.map_err(ProxyError::ServerTcpRead)?;
            if rd == 0 {
                return Err(ProxyError::ClientTcpEOF);
            }

            tls_rec_type != 22u8 // is not TLS handshake ?
        }
    };

    if bypass {
        println!("Client -> Raw CONNECT to {}:{}", domain, port);
        Ok((srv_stream, None))
    } else {
        println!("Client -> TLS CONNECT to {}:{}", domain, port);
        match DNSNameRef::try_from_ascii_str(domain) {
            Ok(dnsref) => Ok((srv_stream, Some(dnsref.to_owned()))),
            Err(e) => Err(ProxyError::TlsDns(e))
        }
    }
}


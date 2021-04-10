use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};


mod parsing;

use parsing::{BufferedParser, TokenType, ParserError};


#[derive(Debug)]
pub enum ProxyError {
    ClientParse(ParserError),
    ClientTcpRead(std::io::Error),
    ClientTcpWrite(std::io::Error),

    ServerParse(ParserError),
    ServerTcpRead(std::io::Error),
    ServerTcpWrite(std::io::Error),

    ServerTcpConnect(std::io::Error),
}


pub async fn handle_stream(client_stream: &mut TcpStream) -> Result<(), ProxyError> {

    let (mut cl_rx, cl_tx) = client_stream.split();
    let mut request = parser_wrappers::mk_request_parser(&mut cl_rx);
    let _n = request.fill().await?;
    
    //println!("First fill ({} bytes)", _n);
    //println!("------- RAW BUFFER START ------------");
    //println!("{}", request.inner.get_ascii(0, _n));
    //println!("-------- RAW BUFFER END -------------");

    let (_, met_e) = request.parse_method().await?;
    request.parse_const(b" http://", TokenType::Protocol).await?;
    let (dom_s, dom_e) = request.parse_domain().await?;
    let (path_s, path_e) = request.parse_path().await?;

    // TODO: check if connection allowed

    let domain = unsafe { request.inner.get_ascii(dom_s, dom_e) };
    let mut server_stream: TcpStream = TcpStream::connect((domain, 80u16)).await.map_err(ProxyError::ServerTcpConnect)?;
    let (mut srv_rx, srv_tx) = server_stream.split();

    let mut srv_buf = BufWriter::new(srv_tx);
    unsafe {
        srv_buf.write(request.inner.get(0, met_e + 1)).await.map_err(ProxyError::ServerTcpWrite)?;
        srv_buf.write(request.inner.get(path_s, path_e)).await.map_err(ProxyError::ServerTcpWrite)?;
    }
    srv_buf.write(b" HTTP/1.0\r\n").await.map_err(ProxyError::ServerTcpWrite)?;


    request.parse_const(b" ", TokenType::HTTPVersion).await?;
    let (ver_maj, ver_min) = request.parse_version_eol().await?;

    unsafe {
    println!("Method: '{}'\nDomain: '{}'\nPath: '{}'\nVersion: {}.{}\n", 
        request.inner.get_ascii(0, met_e),
        request.inner.get_ascii(dom_s, dom_e),
        request.inner.get_ascii(path_s, path_e),
        ver_maj, ver_min);
    }

    if let Some(r_len) = request.process_headers(&mut srv_buf).await? {
        if r_len > 0 {
            request.dump_remainder(&mut srv_buf, r_len).await?;
        }
    }

    srv_buf.flush().await.map_err(ProxyError::ServerTcpWrite)?;


    // REQUEST SENT, PROCESSING RESPONSE


    let mut cl_buf = BufWriter::new(cl_tx);
    let mut response = parser_wrappers::mk_response_parser(&mut srv_rx);
    
    response.fill().await?;
    //println!("{}", response.get_ascii(0, response.end));

    let (_, stat_e) = response.parse_resp_status().await?;
    response.parse_const(b"\r\n", TokenType::StatusLine).await?;
    cl_buf.write(unsafe { response.inner.get(0, stat_e + 2) }).await.map_err(ProxyError::ClientTcpWrite)?;

    if let Some(r_len) = response.process_headers(&mut cl_buf).await? {
        if r_len > 0 {
            response.dump_remainder(&mut cl_buf, r_len).await?;
        }
    }

    cl_buf.flush().await.map_err(ProxyError::ClientTcpWrite)?;


    Ok(())
}



mod parser_wrappers {

    use std::marker::PhantomData;
    use super::*;


    pub trait ErrMapper {
        fn map_parser(e: ParserError) -> ProxyError;
        fn map_io_read(e: std::io::Error) -> ProxyError;
        fn map_io_write(e: std::io::Error) -> ProxyError;
    }


    pub struct ClientMapper;

    impl ErrMapper for ClientMapper {
        #[inline]
        fn map_parser(e: ParserError) -> ProxyError {
            ProxyError::ClientParse(e)
        }

        #[inline]
        fn map_io_read(e: std::io::Error) -> ProxyError {
            ProxyError::ClientTcpRead(e)
        }

        #[inline]
        fn map_io_write(e: std::io::Error) -> ProxyError {
            ProxyError::ServerTcpWrite(e)
        }
    }


    pub struct ServerMapper;

    impl ErrMapper for ServerMapper {
        #[inline]
        fn map_parser(e: ParserError) -> ProxyError {
            ProxyError::ServerParse(e)
        }

        #[inline]
        fn map_io_read(e: std::io::Error) -> ProxyError {
            ProxyError::ServerTcpRead(e)
        }

        #[inline]
        fn map_io_write(e: std::io::Error) -> ProxyError {
            ProxyError::ClientTcpWrite(e)
        }
    }


    pub struct MappedParser<'reader, S, M, const BUF_LEN: usize> {
        pub inner: BufferedParser<'reader, S, BUF_LEN>,
        m: PhantomData<M>
    }

    impl<'reader, S, M, const BUF_LEN: usize> MappedParser<'reader, S, M, BUF_LEN>
        where S: Unpin + AsyncReadExt,
              M: ErrMapper
    {
        pub fn new(stream: &'reader mut S) -> MappedParser<'reader, S, M, BUF_LEN> {
            MappedParser {
                inner: BufferedParser::new(stream),
                m: PhantomData
            }
        }

        #[inline]
        pub async fn fill(&mut self) -> Result<usize, ProxyError> {
            self.inner.fill().await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_method(&mut self) -> Result<(usize, usize), ProxyError> {
            self.inner.parse_method().await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_domain(&mut self) -> Result<(usize, usize), ProxyError> {
            self.inner.parse_domain().await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_path(&mut self) -> Result<(usize, usize), ProxyError> {
            self.inner.parse_path().await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_header_value(&mut self) -> Result<(usize, usize), ProxyError> {
            self.inner.parse_header_value().await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_const<const LEN: usize>(
            &mut self, 
            con: &'static [u8; LEN], 
            token_type: TokenType) -> Result<(), ProxyError> 
        {
            self.inner.parse_const(con, token_type).await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_version_eol(&mut self) -> Result<(u8, u8), ProxyError> {
            self.inner.parse_version_eol().await.map_err(M::map_parser)
        }

        #[inline]
        pub async fn parse_resp_status(&mut self) -> Result<(usize, usize), ProxyError> {
            self.inner.parse_resp_status().await.map_err(M::map_parser)
        }

        pub async fn process_headers<W>(&mut self, target: &mut BufWriter<W>) -> Result<Option<usize>, ProxyError> 
        where W: AsyncWriteExt + Unpin,
        {
            let mut content_length: Option<usize> = None;
            loop {
                match self.inner.parse_header_name().await {
                    Ok((hname_s, hname_e)) => {
                        self.parse_const(b": ", TokenType::HeaderName).await?;
                        let (hval_s, hval_e) = self.parse_header_value().await?;
                        self.parse_const(b"\r\n", TokenType::HeaderValue).await?;

                        unsafe {
                            if b"Content-Length" == self.inner.get(hname_s, hname_e) {
                                content_length = atoi::atoi(self.inner.get(hval_s, hval_e));
                                //println!("Content-Length: {:?}", response_length);
                            }

                            target.write(self.inner.get(hname_s, hval_e + 2)).await.map_err(M::map_io_write)?;
                        }

                        //println!("header: {:?}", response.get_ascii(hname_s, hval_e + 2));
                    },
                    Err(ParserError::InvalidByte(b, _)) if b == b'\r' => break,
                    Err(e) => { return Err(M::map_parser(e)); }
                }
            }

            self.parse_const(b"\r\n", TokenType::HeadEnd).await?;
            target.write(b"\r\n").await.map_err(M::map_io_write)?;
            Ok(content_length)
        }

        pub async fn dump_remainder<W>(&mut self, target: &mut BufWriter<W>, mut len: usize) -> Result<(), ProxyError> 
        where W: AsyncWriteExt + Unpin,
        {
            let remainder = self.inner.get_remainder();
            target.write(remainder).await.map_err(M::map_io_write)?;
            len -= remainder.len();
            
            let (stream, buf) = self.inner.borrow_parts();
            while len > 0 {
                let n = stream.read(buf).await.map_err(M::map_io_read)?;
                if n > 0 {
                    unsafe { target.write(buf.get_unchecked(0 .. n)).await.map_err(M::map_io_write)?; }
                    len -= n;
                    //println!("Read chunk: {:?}", n);
                } else {
                    break;
                }
            }

            Ok(())
        }
    }

    #[inline]
    pub fn mk_request_parser<'reader, S: Unpin + AsyncReadExt>(stream: &'reader mut S) -> MappedParser<'reader, S, ClientMapper, { 1024*8 }> {
        MappedParser::new(stream)
    }

    #[inline]
    pub fn mk_response_parser<'reader, S: Unpin + AsyncReadExt>(stream: &'reader mut S) -> MappedParser<'reader, S, ServerMapper, { 1024*8 }> {
        MappedParser::new(stream)
    }
}


use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;


#[inline]
fn is_uppercase(c: u8) -> bool {
    c >= b'A' && c <= b'Z'
}


macro_rules! make_map_256 {
    ($($flag:expr,)+) => ([
        $($flag != 0,)+
    ])
}


macro_rules! make_map_128 {
    ($($flag:expr,)+) => ([
        $($flag != 0,)+
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
        false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, 
    ])
}


static DOMAIN_MAP: [bool; 256] = make_map_128![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0,
//                                         -  .   
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
//  0  1  2  3  4  5  6  7  8  9                  
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//     A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
//  P  Q  R  S  T  U  V  W  X  Y  Z               
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//     a  b  c  d  e  f  g  h  i  j  k  l  m  n  o
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
//  p  q  r  s  t  u  v  w  x  y  z               
];


#[inline]
fn is_domain(b: u8) -> bool {
    unsafe { *DOMAIN_MAP.get_unchecked(b as usize) }
}


static PATH_MAP: [bool; 256] = make_map_128![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//     !     #  $  %  &  '  (  )  *  +  ,  -  .  /
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1,
//  0  1  2  3  4  5  6  7  8  9  :  ;     =     ?
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  @  A  B  C  D  E  F  G  H  I  J  K  L  M  N  O
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  P  Q  R  S  T  U  V  W  X  Y  Z  [  \  ]  ^  _
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
//  `  a  b  c  d  e  f  g  h  i  j  k  l  m  n  o
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
//  p  q  r  s  t  u  v  w  x  y  z  {  |  }  ~   
];


#[inline]
fn is_path(b: u8) -> bool {
    unsafe { *PATH_MAP.get_unchecked(b as usize) }
}


static HEADER_NAME_MAP: [bool; 256] = make_map_128![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0,
];


#[inline]
fn is_headername(b: u8) -> bool {
    unsafe { *HEADER_NAME_MAP.get_unchecked(b as usize) }
}


static HEADER_VALUE_MAP: [bool; 256] = make_map_256![
    0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
];


#[inline]
fn is_headervalue(b: u8) -> bool {
    unsafe { *HEADER_VALUE_MAP.get_unchecked(b as usize) }
}


macro_rules! get_digit_and_next {
    ( $ptr:ident ) => {
        {
            let v: u8 = *$ptr - 48;
            $ptr = $ptr.add(1);
            v
        }
    }
}


macro_rules! expect_byte {
    ( $ptr:ident, $token_type:expr, $b:expr ) => {
        let v = *$ptr;
        if v != $b {
            return Err(ProxyError::ParseErr((v, $token_type)));
        }
    };
}


macro_rules! expect_byte_seq {
    ( $ptr:ident, $token_type:expr, $b0:expr $(, $bi:expr)+ ) => {
        expect_byte_seq!($ptr, $token_type, $b0);
        $(expect_byte_seq!($ptr, $token_type, $bi);)+
    };

    ( $ptr:ident, $token_type:expr, $b:expr ) => {
        expect_byte!($ptr, $token_type, $b);
        $ptr = $ptr.add(1);
    };
}


#[derive(Debug)]
pub enum TcpReadError {
    IO(std::io::Error),
    EOF
}


#[derive(Debug)]
pub enum ProxyError {
    ClientTcpRead(TcpReadError),
    BufferFull,
    ParseErr(ParseError),
}


pub type ParseError = (u8, TokenType);

#[derive(Debug)]
pub enum TokenType {
    Method,
    Protocol,
    Domain,
//  Port,
    Path,
    HTTPVersion,
    HeaderName,
    HeaderValue,
    HeadEnd
}


pub async fn handle_stream(stream: &mut TcpStream) -> Result<(), ProxyError> {
    unsafe {
        let mut client = Buffer::new(stream);
        let _n = client.fill().await?;
        
        //println!("---- RAW BUFFER BEGIN ({} bytes) ----", n);
        //println!("{}", std::str::from_utf8(&client.buf[0 .. client.end]).unwrap());
        //println!("-------- RAW BUFFER END --------------");

        let (_, met_e) = client.parse_method().await?;
        client.parse_const(b" http://", TokenType::Protocol).await?;
        let (dom_s, dom_e) = client.parse_domain().await?;
        let (path_s, path_e) = client.parse_path().await?;
        client.parse_const(b" ", TokenType::HTTPVersion).await?;
        let (ver_maj, ver_min) = client.parse_version_eol().await?;

        println!("\n--------------------\nMethod: '{}'\nDomain: '{}'\nPath: '{}'\nVersion: {}.{}\n", 
            std::str::from_utf8(&client.buf[0 .. met_e]).unwrap(), 
            std::str::from_utf8(&client.buf[dom_s .. dom_e]).unwrap(),
            std::str::from_utf8(&client.buf[path_s .. path_e]).unwrap(),
            ver_maj, ver_min);

        loop {
            match client.parse_header_name().await {
                Ok((hname_s, hname_e)) => {
                    client.parse_const(b": ", TokenType::HeaderName).await?;
                    let (hval_s, hval_e) = client.parse_header_value().await?;
                    client.parse_const(b"\r\n", TokenType::HeaderValue).await?;

                    println!("Header '{}': '{}'",
                        std::str::from_utf8(&client.buf[hname_s .. hname_e]).unwrap(),
                        std::str::from_utf8(&client.buf[hval_s .. hval_e]).unwrap());
                },
                Err(ProxyError::ParseErr((b, _))) if b == b'\r' => break,
                Err(e) => { return Err(e); }
            }
        }

        client.parse_const(b"\r\n", TokenType::HeadEnd).await?;
    }

    Ok(())
}


macro_rules! mk_parsetoken_fn {
    ($self:ident, $is_token:ident, $token_type:expr) => {{
        let start: usize = $self.pos;
        let mut token_len: usize = 0;
        loop {
            let data = $self.buf.get_unchecked($self.pos .. $self.end);
            let (n, last) = match_while(data, $is_token);
            token_len += n;

            match last {
                Some(b) => {
                    if token_len > 0 {
                        $self.pos += token_len;
                        return Ok((start, $self.pos))
                    } else {
                        return Err(ProxyError::ParseErr((b, $token_type)))
                    }
                },
                None => {
                    $self.fill().await?;
                    continue;
                }
            }
        }
    }}
}


const BUFFER_SIZE: usize = 8196;
const BUFFER_TAIL: usize = 8000;


struct Buffer<'reader, S> {
    stream: &'reader mut S,
    buf: [u8; BUFFER_SIZE],
    pos: usize,
    end: usize,
}



impl<'reader, S: AsyncReadExt + Unpin> Buffer<'reader, S> {

    fn new(stream: &'reader mut S) -> Buffer<'reader, S> {
        Buffer {
            stream,
            buf: [0u8; BUFFER_SIZE],
            pos: 0usize,
            end: 0usize,
        }
    }

    async unsafe fn fill(&mut self) -> Result<usize, ProxyError> {
        // TODO: expect some content-length limits; possible buffer move/defrag
        if self.end > BUFFER_TAIL {
            return Err(ProxyError::BufferFull);
        }

        let r = self.stream.read(self.buf.get_unchecked_mut(self.end .. BUFFER_SIZE)).await;
        match r {
            Ok(n) => {
                if n > 0 { 
                    self.end += n;
                    Ok(n)
                } else {
                    Err(ProxyError::ClientTcpRead(TcpReadError::EOF))
                }
            },
            Err(e) => Err(ProxyError::ClientTcpRead(TcpReadError::IO(e))),
        }
    }

    async unsafe fn parse_method(&mut self) -> Result<(usize, usize), ProxyError> {
        mk_parsetoken_fn!(self, is_uppercase, TokenType::Method);
    }

    async unsafe fn parse_domain(&mut self) -> Result<(usize, usize), ProxyError> {
        mk_parsetoken_fn!(self, is_domain, TokenType::Domain);
    }

    async unsafe fn parse_path(&mut self) -> Result<(usize, usize), ProxyError> {
        mk_parsetoken_fn!(self, is_path, TokenType::Path);
    }

    async unsafe fn parse_header_name(&mut self) -> Result<(usize, usize), ProxyError> {
        mk_parsetoken_fn!(self, is_headername, TokenType::HeaderName);
    }

    async unsafe fn parse_header_value(&mut self) -> Result<(usize, usize), ProxyError> {
        mk_parsetoken_fn!(self, is_headervalue, TokenType::HeaderValue);
    }

    async unsafe fn parse_const<const LEN: usize>(&mut self, con: &'static [u8; LEN], token_type: TokenType) -> Result<(), ProxyError> {
        while LEN > self.end - self.pos {
            let _n = self.fill().await?;
        }

        let data = self.buf.get_unchecked(self.pos .. self.pos + LEN);

        for i in 0 .. LEN {
            let c = *data.get_unchecked(i); 
            if con[i] != c {
                return Err(ProxyError::ParseErr((c, token_type)));
            }
        }

        self.pos += LEN;
        Ok(())
    }


    async unsafe fn parse_version_eol(&mut self) -> Result<(u8, u8), ProxyError> {
        // ensure that enough bytes were fetched:
        const LEN: usize = b"HTTP/1.1\r\n".len();
        while LEN > self.end - self.pos {
            let _n = self.fill().await?;
        }

        let mut p: *const u8 = self.buf.get_unchecked(self.pos);
        expect_byte_seq!(p, TokenType::HTTPVersion, b'H', b'T', b'T', b'P', b'/');
        let maj = get_digit_and_next!(p);
        expect_byte_seq!(p, TokenType::HTTPVersion, b'.');
        let min = get_digit_and_next!(p);
        expect_byte_seq!(p, TokenType::HTTPVersion, b'\r');
        expect_byte!(p, TokenType::HTTPVersion, b'\n');

        self.pos += LEN;
        Ok((maj, min))
    }

}


fn match_while<F>(buf: &[u8], is_token: F) -> (usize, Option<u8>)
    where F: Fn(u8) -> bool
{
    let mut x = 0usize;
    let mut i = buf.iter();
    loop {
        match i.next() {
            None => {
                return (x, None);
            },
            Some(&b) => {
                if is_token(b) {
                    x += 1;
                    continue;
                } else {
                    return (x, Some(b));
                }
            }
        }
    }
}



/*
#[cfg(test)]
mod tests {
    use super::*;

    use tokio_test::block_on;
    use tokio_test::io::Builder;


    macro_rules! mk_buffer_read {
        ($buf:ident, $($chunk:expr),+) => {
            let mut mock_stream = Builder::new()
                $(.read($chunk))+
                .build();
            let mut $buf = Buffer::new(&mut mock_stream);
        }
    }


    fn test_token_head<P>(data: &[u8], r1: usize, r2: P::Output, buf_pos: usize )
        where P: Parser + Default,
              P::Output: PartialEq + std::fmt::Debug
    {
        unsafe {
            mk_buffer_read!(buf, data);

            let (n, res) = block_on(buf.parse_as::<P>()).unwrap();

            assert_eq!(n, r1);
            assert_eq!(res, r2);
            assert_eq!(buf.pos, buf_pos)
        }
    }

    #[test]
    fn test_method() {
        test_token_head::<MethodParser>(b"GET http://httpbin.org/get HTTP/1.1\r\n", 0, 3, 4);
    }

}
*/

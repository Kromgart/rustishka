use tokio::io::AsyncReadExt;


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
            return Err(ParserError::InvalidByte(v, $token_type));
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


macro_rules! mk_parsetoken_fn {
    ($self:ident, $is_token:ident, $token_type:expr) => {{
        debug_assert!($self.pos < $self.end);
        unsafe {
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
                        return Err(ParserError::InvalidByte(b, $token_type))
                    }
                },
                None => {
                    $self.fill().await?;
                    continue;
                }
            }
        }
        }
    }}
}


#[derive(Debug)]
pub enum ParserError {
    InvalidByte(u8, TokenType),
    TcpRead(std::io::Error),
    TcpEOF,
    BufferFull,
}


pub type ParseResult<T> = Result<T, ParserError>;


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
    HeadEnd,
    StatusLine,
}


pub struct BufferedParser<'reader, S, const BUF_SIZE: usize> {
    buf: [u8; BUF_SIZE],
    stream: &'reader mut S,
    pos: usize,
    end: usize,
}


impl<'reader, S: AsyncReadExt + Unpin, const BUF_SIZE: usize> BufferedParser<'reader, S, BUF_SIZE> {

    pub fn new(stream: &'reader mut S) -> BufferedParser<'reader, S, BUF_SIZE> {
        BufferedParser {
            stream,
            buf: [0u8; BUF_SIZE],
            pos: 0usize,
            end: 0usize,
        }
    }

    #[inline]
    pub unsafe fn get(&self, start: usize, end: usize) -> &[u8]  {
        debug_assert!(start < end);
        debug_assert!(end <= self.end);
        self.buf.get_unchecked(start .. end)
    }

    #[inline]
    pub unsafe fn get_ascii(&self, start: usize, end: usize) -> &str {
        std::str::from_utf8_unchecked(self.get(start, end))
    }

    #[inline]
    pub fn get_remainder(&self) -> &[u8] {
        debug_assert!(self.pos < self.end);
        unsafe { self.buf.get_unchecked(self.pos .. self.end) }
    }

    #[inline]
    pub fn borrow_parts<'a>(&'a mut self) -> (&'a mut S, &'a mut [u8]) {
        self.pos = 0;
        self.end = 0;
        unsafe { ( self.stream, self.buf.get_unchecked_mut(0 .. BUF_SIZE) ) }
    }

    pub async fn fill(&mut self) -> ParseResult<usize> {
        if self.end >= BUF_SIZE {
            return Err(ParserError::BufferFull);
        }

        // INVARIANT: self.end < BUF_SIZE
        let r = unsafe { self.stream.read(self.buf.get_unchecked_mut(self.end .. BUF_SIZE)).await };
        match r {
            Ok(n) => {
                if n > 0 { 
                    self.end += n;
                    Ok(n)
                } else {
                    Err(ParserError::TcpEOF)
                }
            },
            Err(e) => Err(ParserError::TcpRead(e)),
        }
    }

    pub async fn parse_method(&mut self) -> ParseResult<(usize, usize)> {
        mk_parsetoken_fn!(self, is_uppercase, TokenType::Method);
    }

    pub async fn parse_domain(&mut self) -> ParseResult<(usize, usize)> {
        mk_parsetoken_fn!(self, is_domain, TokenType::Domain);
    }

    pub async fn parse_path(&mut self) -> ParseResult<(usize, usize)> {
        mk_parsetoken_fn!(self, is_path, TokenType::Path);
    }

    pub async fn parse_resp_status(&mut self) -> ParseResult<(usize, usize)> {
        mk_parsetoken_fn!(self, is_resp_line, TokenType::StatusLine);
    }

    pub async fn parse_header_name(&mut self) -> ParseResult<(usize, usize)> {
        mk_parsetoken_fn!(self, is_headername, TokenType::HeaderName);
    }

    pub async fn parse_header_value(&mut self) -> ParseResult<(usize, usize)> {
        mk_parsetoken_fn!(self, is_headervalue, TokenType::HeaderValue);
    }

    pub async fn parse_const<const LEN: usize>(
        &mut self, 
        con: &'static [u8; LEN], 
        token_type: TokenType) -> ParseResult<()> 
    {
        unsafe {
        while LEN > self.end - self.pos {
            let _n = self.fill().await?;
        }

        let data = self.buf.get_unchecked(self.pos .. self.pos + LEN);

        for i in 0 .. LEN {
            let c = *data.get_unchecked(i); 
            if con[i] != c {
                return Err(ParserError::InvalidByte(c, token_type));
            }
        }

        self.pos += LEN;
        }
        Ok(())
    }


    pub async fn parse_version_eol(&mut self) -> ParseResult<(u8, u8)> {
        // ensure that enough bytes were fetched:
        const LEN: usize = b"HTTP/1.1\r\n".len();

        unsafe {
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

}








#[inline]
fn is_uppercase(c: u8) -> bool {
    c >= b'A' && c <= b'Z'
}

#[inline]
fn is_resp_line(c: u8) -> bool {
    c != b'\r'
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



fn match_while<F: Fn(u8) -> bool>(buf: &[u8], is_token: F) -> (usize, Option<u8>) {
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

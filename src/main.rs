#![allow(type_alias_bounds)]
#![feature(addr_parse_ascii)]
use ariadne::{Color, ColorGenerator, Fmt, Label, Report, ReportKind, Source};
use clap::Parser as CliParser;
use peekable_fwd_bwd::Peekable;
use std::{
    cmp::max,
    fmt::{Debug, Error, Formatter},
    fs::{self, File},
    io::{self, prelude::*},
    iter::Iterator,
    net::{Ipv4Addr, Ipv6Addr},
    ops::Range,
    path::{Path, PathBuf},
    process,
    slice::{Iter, IterMut},
    str::{self, Chars},
};

#[derive(CliParser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(
        short = 'd',
        long,
        help = "Report the job to do instead of actually doing it"
    )]
    dry_run: bool,

    #[arg(
        short = 'D',
        long,
        help = "Dump currently active rules to either a file or standard output"
    )]
    dump: bool,

    #[arg(
        short,
        long,
        help = "Path to a file where to dump currently active rules"
    )]
    output: Option<PathBuf>,

    #[arg(help = "Forwarding declaration file")]
    input: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Default)]
enum Keyword {
    #[default]
    None,
    Forward,
    From,
    To,
    This,
    Including,
    Excluding,
    Services,
    Define,
    Network,
    Machine,
    In,
    At,
}

#[derive(Clone, Copy, Debug, PartialEq, Default)]
enum Indent {
    #[default]
    Space,
    Tab,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum IpAddr {
    #[default]
    Local,
    Ipv4Addr(Ipv4Addr),
    Ipv6Addr(Ipv6Addr),
}

#[derive(Clone, Debug, PartialEq, Default)]
enum Token {
    #[default]
    None,
    Comma,
    Quote,
    LParen,
    RParen,
    Keyword(Keyword),
    Indent(Vec<Indent>),
    Ident(String),
    IpAddr(IpAddr, u8),
    Number(i16),
    String(String),
    List(Vec<Spanned<Token>>),
}

type Span = Range<usize>;
type Spanned<T> = (T, Span);
type PeekableBuffer<T>
where
    T: Iterator,
    T::Item: Clone,
= Peekable<T, 2, 2>;

struct PeekableTrackableBuffer<'a> {
    pub index: usize,
    pub line: usize,
    prev_column: usize,
    pub column: usize,
    buffer: PeekableBuffer<Chars<'a>>,
}

impl<'a> PeekableTrackableBuffer<'a> {
    #[inline]
    pub fn new(value: &'a str) -> Self {
        Self {
            index: 0,
            line: 1,
            prev_column: 1,
            column: 0,
            buffer: PeekableBuffer::<Chars<'a>>::new(value.chars()),
        }
    }

    #[inline]
    pub fn peek_bwd(&'a mut self) -> Option<&char> {
        self.buffer.peek_bwd()
    }

    #[inline]
    pub fn peek_fwd(&mut self) -> Option<&char> {
        self.buffer.peek_fwd()
    }

    #[inline]
    pub fn peek(&mut self) -> Option<&char> {
        self.buffer.peek()
    }

    #[inline]
    pub fn peek_bwd_nth(&mut self, i: usize) -> Option<&char> {
        self.buffer.peek_bwd_nth(i)
    }

    pub fn peek_fwd_nth(&mut self, i: usize) -> Option<&char> {
        self.buffer.peek_fwd_nth(i)
    }

    #[inline]
    pub fn peek_nth(&mut self, i: usize) -> Option<&char> {
        self.buffer.peek_nth(i)
    }
}

impl<'a> Iterator for PeekableTrackableBuffer<'a> {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        let value = self.buffer.next();
        self.index += 1;
        if let Some(c) = value {
            if ['\r', '\n'].contains(&c) {
                self.line += 1;
                self.prev_column = self.column;
                self.column = 0;
            } else {
                self.column += 1;
            }
        }
        value
    }
}

#[derive(Clone, Debug, Default)]
struct Lexer<'a> {
    pub input_filename: &'a str,
    data: &'a str,
}

impl<'a> Lexer<'a> {
    pub fn iter(&self) -> LexerIter<'a> {
        LexerIter {
            lexer: self.clone(),
            marker: Marker::new((0, 0)),
            colors: ColorGenerator::new(),
            buffer: PeekableTrackableBuffer::new(self.data),
        }
    }
}

impl<'a> From<(&'a str, &'a str)> for Lexer<'a> {
    fn from(data: (&'a str, &'a str)) -> Self {
        Lexer {
            input_filename: data.0,
            data: data.1,
        }
    }
}

impl<'a> From<&'a str> for Lexer<'a> {
    fn from(data: &'a str) -> Self {
        Lexer {
            input_filename: "<input>",
            data,
        }
    }
}

impl<'a> IntoIterator for Lexer<'a> {
    type Item = Spanned<Token>;
    type IntoIter = LexerIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
enum LexerState {
    #[default]
    None,
    Ident,
    Number,
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Marker {
    pub start: usize,
    pub end: usize,
    locked: bool,
}

impl Marker {
    #[inline]
    pub fn new(value: (usize, usize)) -> Self {
        Marker {
            start: value.0,
            end: value.0,
            locked: false,
        }
    }

    #[inline]
    pub fn lock(&mut self) {
        self.locked = true;
    }

    #[inline]
    pub fn unlock(&mut self) {
        self.locked = false;
    }

    #[inline]
    pub fn sync(&mut self) {
        self.start = max(self.start, self.end);
        self.end = self.start;
    }

    pub fn advance(&mut self) {
        self.advance_by(1);
    }

    pub fn advance_by(&mut self, n: usize) {
        if self.locked {
            self.end += n;
        } else {
            self.start += n;
        }
    }

    pub fn as_range(&mut self) -> Range<usize> {
        let start = self.start;
        let end = self.end;
        self.sync();

        Range {
            start: start,
            end: end,
        }
    }
}

impl From<(usize, usize)> for Marker {
    fn from(value: (usize, usize)) -> Self {
        Marker::new(value)
    }
}

struct LexerIter<'a> {
    lexer: Lexer<'a>,
    marker: Marker,
    colors: ColorGenerator,
    buffer: PeekableTrackableBuffer<'a>,
}

impl<'a> Iterator for LexerIter<'a> {
    type Item = Spanned<Token>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&c) = self.buffer.peek() {
            if c.is_whitespace() {
                if self.buffer.column == 0 && ['\t', ' '].contains(&c) {
                    self.marker.lock();
                    let mut indentation = vec![];

                    'indent: while let Some(&cc) = self.buffer.peek() {
                        if !cc.is_whitespace() {
                            break 'indent;
                        }

                        if cc == '\t' {
                            indentation.push(Indent::Tab);
                        } else if cc == ' ' {
                            indentation.push(Indent::Space);
                        }

                        self.marker.advance();
                        self.buffer.next();
                    }

                    self.marker.unlock();
                    return Some((Token::Indent(indentation), self.marker.as_range()));
                }

                self.marker.advance();
                self.buffer.next();
                self.marker.sync();
                continue;
            }

            if c.is_ascii_alphabetic() {
                self.marker.lock();
                let mut value = String::new();
                let mut subnet = String::new();
                let mut state = LexerState::Ident;

                'either_ident_ipv6: loop {
                    match state {
                        LexerState::Ident => {
                            'ident: while let Some(&cc) = self.buffer.peek() {
                                if cc.is_whitespace() {
                                    break 'either_ident_ipv6;
                                }
                                if cc.is_ascii_alphanumeric() || ['_', '.'].contains(&cc) {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                } else if cc == ':' {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                    state = LexerState::Ipv6;
                                    println!("Jumping to State::Ipv6");
                                    continue 'either_ident_ipv6;
                                } else {
                                    self.marker.unlock();
                                    panic!("UUU AAA @");
                                }
                            }
                        }
                        LexerState::Ipv6 => {
                            'ipv6: while let Some(&cc) = self.buffer.peek() {
                                println!("Jumped to LexerState::Ipv6");
                                if cc.is_whitespace() {
                                    break 'either_ident_ipv6;
                                }
                                if cc.is_digit(16) || cc == ':' {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                } else if cc == '/' {
                                    self.marker.advance();
                                    self.buffer.next();
                                    'subnet: while let Some(&cc) = self.buffer.peek() {
                                        if cc.is_whitespace() {
                                            break 'either_ident_ipv6;
                                        }
                                        if cc.is_digit(16) {
                                            subnet.push(cc);
                                            self.marker.advance();
                                            self.buffer.next();
                                        } else {
                                            self.marker.unlock();
                                            panic!("UUU AAA");
                                        }
                                    }
                                } else {
                                    self.marker.unlock();
                                    panic!("{:?} = {:?} {:#?}", value, cc, cc);
                                }
                            }
                        }
                        _ => {}
                    }
                }

                self.marker.unlock();
                let token = match value.to_ascii_lowercase().as_str() {
                    "forward" => Token::Keyword(Keyword::Forward),
                    "from" => Token::Keyword(Keyword::From),
                    "to" => Token::Keyword(Keyword::To),
                    "this" => Token::Keyword(Keyword::This),
                    "including" => Token::Keyword(Keyword::Including),
                    "excluding" => Token::Keyword(Keyword::Excluding),
                    "services" => Token::Keyword(Keyword::Services),
                    "define" => Token::Keyword(Keyword::Define),
                    "network" => Token::Keyword(Keyword::Network),
                    "machine" => Token::Keyword(Keyword::Machine),
                    "in" => Token::Keyword(Keyword::In),
                    "at" => Token::Keyword(Keyword::At),
                    _ if state == LexerState::Ident => Token::Ident(value),
                    _ if state == LexerState::Ipv6 => Token::IpAddr(
                        IpAddr::Ipv6Addr(
                            Ipv6Addr::parse_ascii(value.as_bytes())
                                .expect("Couldn't parse ipv4 address"),
                        ),
                        subnet.parse().unwrap(),
                    ),
                    _ => panic!(),
                };

                return Some((token, self.marker.as_range()));
            }

            if c.is_digit(10) {
                self.marker.lock();
                let mut value = String::new();
                let mut subnet = String::new();
                let mut state = LexerState::Number;

                'either_num_ipv4_ipv6: loop {
                    match state {
                        LexerState::Number => {
                            'num: while let Some(&cc) = self.buffer.peek() {
                                if cc.is_whitespace() {
                                    break 'either_num_ipv4_ipv6;
                                }
                                if cc.is_digit(10) {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                } else if cc == '.' {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                    state = LexerState::Ipv4;
                                    continue 'either_num_ipv4_ipv6;
                                } else if cc.is_digit(16) || cc == ':' {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                    state = LexerState::Ipv6;
                                    continue 'either_num_ipv4_ipv6;
                                } else {
                                    self.marker.unlock();
                                    panic!("UUU AAA");
                                }
                            }
                        }
                        LexerState::Ipv4 => {
                            'ipv4: while let Some(&cc) = self.buffer.peek() {
                                if cc.is_whitespace() {
                                    break 'either_num_ipv4_ipv6;
                                }
                                if cc.is_digit(10) || cc == '.' {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                } else if cc == '/' {
                                    self.marker.advance();
                                    self.buffer.next();
                                    'subnet: while let Some(&cc) = self.buffer.peek() {
                                        if cc.is_whitespace() {
                                            break 'either_num_ipv4_ipv6;
                                        }
                                        if cc.is_digit(10) {
                                            subnet.push(cc);
                                            self.marker.advance();
                                            self.buffer.next();
                                        } else {
                                            self.marker.unlock();
                                            panic!("UUU AAA");
                                        }
                                    }
                                } else {
                                    self.marker.unlock();
                                    panic!("{:?} = {:?} {:#?}", value, cc, cc);
                                }
                            }
                        }
                        LexerState::Ipv6 => {
                            'ipv6: while let Some(&cc) = self.buffer.peek() {
                                if cc.is_whitespace() {
                                    break 'either_num_ipv4_ipv6;
                                }
                                if cc.is_digit(16) || cc == ':' {
                                    value.push(cc);
                                    self.marker.advance();
                                    self.buffer.next();
                                } else if cc == '/' {
                                    self.marker.advance();
                                    self.buffer.next();
                                    'subnet: while let Some(&cc) = self.buffer.peek() {
                                        if cc.is_whitespace() {
                                            break 'either_num_ipv4_ipv6;
                                        }
                                        if cc.is_digit(16) {
                                            subnet.push(cc);
                                            self.marker.advance();
                                            self.buffer.next();
                                        } else {
                                            self.marker.unlock();
                                            panic!("UUU AAA");
                                        }
                                    }
                                } else {
                                    self.marker.unlock();
                                    panic!("{:?} = {:?} {:#?}", value, cc, cc);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                
                if subnet.is_empty() {
                    subnet = "0".to_string();
                }

                self.marker.unlock();
                let token = match state {
                    LexerState::Number => {
                        Token::Number(value.parse().expect("Couldn't parse number"))
                    }
                    LexerState::Ipv4 => Token::IpAddr(
                        IpAddr::Ipv4Addr(
                            Ipv4Addr::parse_ascii(value.as_bytes())
                                .expect("Couldn't parse ipv4 address"),
                        ),
                        subnet.parse().unwrap(),
                    ),
                    LexerState::Ipv6 => Token::IpAddr(
                        IpAddr::Ipv6Addr(
                            Ipv6Addr::parse_ascii(value.as_bytes())
                                .expect("Couldn't parse ipv6 address"),
                        ),
                        subnet.parse().unwrap(),
                    ),
                    _ => panic!(),
                };

                return Some((token, self.marker.as_range()));
            }

            if c == '"' {
                self.marker.lock();
                let mut value = String::new();
                self.marker.advance();
                self.buffer.next();
                'str: while let Some(&cc) = self.buffer.peek() {
                    if cc == '"' {
                        self.marker.advance();
                        self.buffer.next();
                        break 'str;
                    }
                    value.push(cc);
                    self.marker.advance();
                    self.buffer.next();
                }
                self.marker.unlock();
                return Some((Token::String(value), self.marker.as_range()));
            }

            self.marker.unlock();
            self.marker.lock();
            self.marker.advance();
            let token = match c {
                '(' => Token::LParen,
                ')' => Token::RParen,
                ',' => Token::Comma,
                _ => panic!(
                    "{}:{}: Unexpected character: {}",
                    self.buffer.line, self.buffer.column, c
                ),
            };
            self.buffer.next();
            self.marker.unlock();
            return Some((token, self.marker.as_range()));
        }

        None
    }
}

#[derive(Clone, Debug, Default)]
struct ForwardingOrder {
    pub blocks: Vec<ForwardBlock>,
}

#[derive(Clone, Debug, Default)]
struct ForwardBlock {
    pub incoming_addr: IpAddr,
}

struct Parser<'a> {
    tokens: PeekableBuffer<LexerIter<'a>>,
}

impl<'a> Parser<'a> {
    pub fn parse(&mut self) -> ForwardingOrder {
        while let Some(token) = self.tokens.peek() {
            println!("token {:?}", token);
            self.tokens.next();
        }

        ForwardingOrder::default()
    }
}

impl<'a> From<Lexer<'a>> for Parser<'a> {
    fn from(lexer: Lexer<'a>) -> Self {
        Self {
            tokens: PeekableBuffer::<LexerIter<'a>>::new(lexer.iter()),
        }
    }
}

impl<'a> From<&'a str> for Parser<'a> {
    fn from(string: &'a str) -> Self {
        Self::from(Lexer::from(string))
    }
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let input = cli
        .input
        .expect("Forwarding declaration file not specified");
    assert!(fs::metadata(input.clone()).is_ok());
    let input_data = fs::read(input.clone())?;
    let input_data = str::from_utf8(input_data.as_slice()).expect("Malformed UTF-8 string");

    let lexer = Lexer::from((input.as_str(), input_data));
    let mut parser = Parser::from(lexer);

    parser.parse();

    Ok(())
}

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::net::Ipv4Addr;

// pub const PROTOCOL_ICMP: u8 = 0x01;
// pub const PROTOCOL_TCP: u8 = 0x06;
// pub const PROTOCOL_UDP: u8 = 0x11;

pub const ICMP_KIND_ECHO: u8 = 0x08;
pub const ICMP_KIND_ECHO_REPLY: u8 = 0x00;
pub const ICMP_KIND_DESTINATION_UNREACHABLE: u8 = 0x03;
// pub const ICMP_KIND_TIME_EXCEEDED: u8 = 0x0b;

pub(crate) enum Protocol {
    ICMP,
    TCP,
    UDP,
    Unknown(u8),
}

impl Protocol {
    pub fn value(&self) -> u8 {
        match *self {
            Self::ICMP => 0x01,
            Self::TCP => 0x06,
            Self::UDP => 0x11,
            Self::Unknown(v) => v,
        }
    }

    pub fn from(v: u8) -> Self {
        match v {
            0x01 => Self::ICMP,
            0x06 => Self::TCP,
            0x11 => Self::UDP,
            v => Self::Unknown(v),
        }
    }
}

// #[derive(Clone)]
pub(crate) struct Ipv4(Vec<u8>);

#[allow(dead_code)]
impl Ipv4 {
    pub fn new(data: Vec<u8>) -> Self {
        Ipv4(data)
    }

    pub fn version(&self) -> u8 {
        self.0[0] >> 4
    }

    pub fn ttl(&self) -> u8 {
        self.0[8]
    }

    pub fn set_ttl(&mut self, ttl: u8) {
        self.0[8] = ttl;
    }

    pub fn protocol(&self) -> Protocol {
        Protocol::from(self.0[9])
    }

    pub fn set_protocol(&mut self, protocol: Protocol) {
        self.0[9] = protocol.value();
    }

    pub fn head_len(&self) -> u16 {
        ((self.0[0] & 0x0f) as u16) << 2
    }

    pub fn total_len(&self) -> u16 {
        Cursor::new(&self.0[2..]).read_u16::<BigEndian>().unwrap()
    }

    pub fn set_total_length(&mut self) {
        let n = self.0.len();
        Cursor::new(&mut self.0[2..4])
            .write_u16::<BigEndian>(n as u16)
            .unwrap()
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[12], self.0[13], self.0[14], self.0[15])
    }

    pub fn set_src(&mut self, addr: Ipv4Addr) {
        self.0[12..16].clone_from_slice(&addr.octets());
    }

    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.0[16], self.0[17], self.0[18], self.0[19])
    }

    pub fn set_dst(&mut self, addr: Ipv4Addr) {
        self.0[16..20].clone_from_slice(&addr.octets());
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[self.head_len() as usize..]
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let a = self.head_len() as usize;
        let slen = self.0[a..].len();
        let plen = payload.len();
        if plen > slen {
            self.0[a..].clone_from_slice(&payload[..slen]);
            for &b in payload[slen..].iter() {
                self.0.push(b);
            }
        } else {
            self.0[a..].clone_from_slice(payload);
        }
    }

    pub fn get_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn update_checksum(&mut self) {
        self.0[10..12].clone_from_slice(&[0, 0]);
        let p = &self.0[..self.head_len() as usize];
        let r = &checksum(0, p);
        self.0[10..12].clone_from_slice(r);
    }

    pub fn packet(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) struct ICMP(Vec<u8>);

#[allow(dead_code)]
impl ICMP {
    pub fn new(data: Vec<u8>) -> Self {
        ICMP(data)
    }

    pub fn kind(&self) -> u8 {
        self.0[0]
    }

    pub fn set_kind(&mut self, kind: u8) {
        self.0[0] = kind;
    }

    pub fn code(&self) -> u8 {
        self.0[1]
    }

    pub fn set_code(&mut self, code: u8) {
        self.0[1] = code;
    }

    pub fn payload(&self) -> &[u8] {
        &self.0[8..]
    }

    pub fn set_payload(&mut self, payload: &[u8]) {
        let slen = self.0[8..].len();
        let plen = payload.len();
        if plen > slen {
            self.0[8..].clone_from_slice(&payload[..slen]);
            for &b in payload[slen..].iter() {
                self.0.push(b);
            }
        } else {
            self.0[8..].clone_from_slice(payload);
        }
    }

    pub fn update_checksum(&mut self) {
        self.0[2..4].clone_from_slice(&[0, 0]);
        let p = &self.0[..];
        let r = &checksum(0, p);
        self.0[2..4].clone_from_slice(r);
    }

    pub fn packet(&self) -> &[u8] {
        &self.0
    }
}

#[allow(dead_code)]
pub(crate) struct TCP(Vec<u8>);

#[allow(dead_code)]
impl TCP {
    pub fn new(data: Vec<u8>) -> Self {
        TCP(data)
    }
}

pub(crate) struct UDP(Vec<u8>);

#[allow(dead_code)]
impl UDP {
    pub fn new(data: Vec<u8>) -> Self {
        UDP(data)
    }

    pub fn src(&self) -> u16 {
        Cursor::new(&self.0).read_u16::<BigEndian>().unwrap()
    }

    pub fn set_src(&mut self, port: u16) {
        Cursor::new(&mut self.0)
            .write_u16::<BigEndian>(port)
            .unwrap()
    }

    pub fn dst(&self) -> u16 {
        Cursor::new(&self.0[2..]).read_u16::<BigEndian>().unwrap()
    }

    pub fn set_dst(&mut self, port: u16) {
        Cursor::new((&self.0[2..]).to_vec())
            .write_u16::<BigEndian>(port)
            .unwrap()
    }

    pub fn update_checksum(&mut self, psum: u32) {
        self.0[6..8].clone_from_slice(&[0, 0]);
        let p = &self.0[..];
        let r = &checksum(psum, p);
        self.0[6..8].clone_from_slice(r);
    }

    pub fn packet(&self) -> &[u8] {
        &self.0
    }
}

fn checksum(s: u32, p: &[u8]) -> [u8; 2] {
    let mut s: u32 = s;
    s += sum(p);
    s = (s >> 16) + (s & 0xffff);
    s += s >> 16;
    s = !s;
    [((s >> 8) as u8), (s as u8)]
}

fn sum(p: &[u8]) -> u32 {
    let mut s: u32 = 0;
    let n = p.len();
    for i in (0..n).step_by(2) {
        s += (p[i] as u32) << 8;
        if i + 1 < n {
            s += p[i + 1] as u32;
        }
    }
    s
}

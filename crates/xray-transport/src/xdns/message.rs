//! The DNS messages xdns writes and reads: queries as Go's `dnsmessage`
//! packs them, and answers as its `Message.Unpack` reads them, which decides
//! what a client accepts.
use super::domain::{Domain, TYPE_A, TYPE_AAAA, TYPE_CNAME, TYPE_TXT};

const TYPE_NS: u16 = 2;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_SRV: u16 = 33;
const TYPE_OPT: u16 = 41;
const TYPE_SVCB: u16 = 64;
const TYPE_HTTPS: u16 = 65;
const CLASS_INET: u16 = 1;

/// `dnsmessage`'s `nonEncodedNameMax`.
const NAME_MAX: usize = 254;

/// A query for `name`, `qtype` in class IN, recursion desired, with an OPT
/// record advertising `edns0` when it is set, as Xray's client packs it.
pub(crate) fn query(id: u16, name: &[u8], qtype: u16, edns0: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + name.len() + 2 + 4 + 11);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&u16::from(edns0 > 0).to_be_bytes());
    // The name's labels, each after its length, then the root.
    for label in name[..name.len() - 1].split(|&byte| byte == b'.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_INET.to_be_bytes());
    if edns0 > 0 {
        out.push(0);
        out.extend_from_slice(&TYPE_OPT.to_be_bytes());
        out.extend_from_slice(&edns0.to_be_bytes());
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }
    out
}

pub(crate) struct Message {
    bits: u16,
    questions: Vec<Question>,
    answers: Vec<Record>,
}

struct Question {
    name: Vec<u8>,
    qtype: u16,
}

struct Record {
    name: Vec<u8>,
    rtype: u16,
    body: Body,
}

enum Body {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Cname(Vec<u8>),
    Txt(Vec<Vec<u8>>),
    Other,
}

/// Where a client stopped reading a response, or the packets it carried.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Read {
    /// It does not unpack.
    Unpack,
    /// It is not a successful, untruncated response to one question.
    Header,
    /// Its question is for none of the domains or a type its domain does
    /// not take.
    Domain,
    /// What the answer carried, and the packets in it, if they parse.
    Answer {
        decoded: Vec<u8>,
        packets: Vec<Vec<u8>>,
    },
}

/// `xdnsClient.read` without its channels: the first of `domains` whose
/// name matches the question decodes the answer.
pub(crate) fn read(response: &[u8], domains: &[Domain]) -> Read {
    let Some(message) = unpack(response) else {
        return Read::Unpack;
    };
    let response_bit = message.bits & 0x8000 != 0;
    let truncated = message.bits & 0x0200 != 0;
    if !response_bit || truncated || message.bits & 0xF != 0 || message.questions.len() != 1 {
        return Read::Header;
    }
    let question = &message.questions[0];
    let Some(domain) = domains
        .iter()
        .find(|domain| domain.is_domain(&question.name))
    else {
        return Read::Domain;
    };
    if !domain.has_type(question.qtype) {
        return Read::Domain;
    }
    let decoded = decode_answer(&message, question.qtype, domain);
    let packets = unframe(&decoded);
    Read::Answer { decoded, packets }
}

/// `Resp.Decode` for a response: one TXT answer's strings joined, or the
/// fragments of the A, AAAA or CNAME answers under the domain, sorted by
/// their index, the first carrying the count.
fn decode_answer(message: &Message, qtype: u16, domain: &Domain) -> Vec<u8> {
    if qtype == TYPE_TXT {
        let mut decoded = Vec::new();
        if let [answer] = &message.answers[..] {
            if domain.is_domain(&answer.name) && answer.rtype == TYPE_TXT {
                if let Body::Txt(strings) = &answer.body {
                    for string in strings {
                        decoded.extend_from_slice(string);
                    }
                }
            }
        }
        return decoded;
    }
    let mut fragments: Vec<Vec<u8>> = Vec::new();
    for answer in &message.answers {
        if !domain.is_domain(&answer.name) || answer.rtype != qtype {
            continue;
        }
        match &answer.body {
            Body::A(a) => fragments.push(a.to_vec()),
            Body::Aaaa(a) => fragments.push(a.to_vec()),
            Body::Cname(target) => {
                let decoded = domain.decode(target);
                if !decoded.is_empty() {
                    fragments.push(decoded);
                }
            }
            _ => {}
        }
    }
    // Go's sort is not stable, but two fragments with one index fail below
    // whichever comes first.
    fragments.sort_by_key(|fragment| fragment[0]);
    match fragments.first() {
        Some(first) if first.len() >= 2 && usize::from(first[1]) <= fragments.len() => {}
        _ => return Vec::new(),
    }
    let mut decoded = fragments[0][2..].to_vec();
    for i in 1..fragments.len() {
        if fragments[i][0] == fragments[i - 1][0] {
            return Vec::new();
        }
        decoded.extend_from_slice(&fragments[i][1..]);
    }
    decoded
}

/// The packets of a decoded answer: each a 14-bit length and its bytes, the
/// last flagged by the top two bits. Anything malformed loses them all.
pub(crate) fn unframe(decoded: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut rest = decoded;
    while rest.len() > 1 {
        let last = rest[0] & 0xC0 == 0xC0;
        let length = usize::from(rest[0] & 0x3F) << 8 | usize::from(rest[1]);
        rest = &rest[2..];
        if length > rest.len() {
            return Vec::new();
        }
        packets.push(rest[..length].to_vec());
        if last {
            break;
        }
        rest = &rest[length..];
        if rest.len() < 2 {
            packets.clear();
        }
    }
    packets
}

/// `Message.Unpack`: the header, then every record of every section, each
/// body as its type reads it.
fn unpack(msg: &[u8]) -> Option<Message> {
    if msg.len() < 12 {
        return None;
    }
    let field = |i: usize| u16::from_be_bytes([msg[i], msg[i + 1]]);
    let bits = field(2);
    let counts = [field(4), field(6), field(8), field(10)];
    let mut off = 12;
    let mut questions = Vec::new();
    for _ in 0..counts[0] {
        let (name, next) = unpack_name(msg, off)?;
        let qtype = uint16(msg, next)?;
        uint16(msg, next + 2)?;
        off = next + 4;
        questions.push(Question { name, qtype });
    }
    let mut answers = Vec::new();
    for (section, &count) in counts[1..].iter().enumerate() {
        for _ in 0..count {
            let (name, next) = unpack_name(msg, off)?;
            let rtype = uint16(msg, next)?;
            uint16(msg, next + 2)?;
            uint32(msg, next + 4)?;
            let length = usize::from(uint16(msg, next + 8)?);
            let body_off = next + 10;
            let body = unpack_body(msg, body_off, rtype, length)?;
            off = body_off + length;
            if section == 0 {
                answers.push(Record { name, rtype, body });
            }
        }
    }
    Some(Message {
        bits,
        questions,
        answers,
    })
}

fn uint16(msg: &[u8], off: usize) -> Option<u16> {
    let bytes = msg.get(off..off.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn uint32(msg: &[u8], off: usize) -> Option<u32> {
    let bytes = msg.get(off..off.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// A record's body as `unpackResourceBody` reads it. Most types read only
/// what they need and never check it against the record's length.
fn unpack_body(msg: &[u8], off: usize, rtype: u16, length: usize) -> Option<Body> {
    Some(match rtype {
        TYPE_A => Body::A(msg.get(off..off + 4)?.try_into().ok()?),
        TYPE_AAAA => Body::Aaaa(msg.get(off..off + 16)?.try_into().ok()?),
        TYPE_CNAME => Body::Cname(unpack_name(msg, off)?.0),
        TYPE_NS | TYPE_PTR => {
            unpack_name(msg, off)?;
            Body::Other
        }
        TYPE_SOA => {
            let (_, next) = unpack_name(msg, off)?;
            let (_, next) = unpack_name(msg, next)?;
            for i in 0..5 {
                uint32(msg, next + 4 * i)?;
            }
            Body::Other
        }
        TYPE_MX => {
            uint16(msg, off)?;
            unpack_name(msg, off + 2)?;
            Body::Other
        }
        TYPE_SRV => {
            for i in 0..3 {
                uint16(msg, off + 2 * i)?;
            }
            unpack_name(msg, off + 6)?;
            Body::Other
        }
        TYPE_TXT => Body::Txt(unpack_txt(msg, off, length)?),
        TYPE_SVCB | TYPE_HTTPS => {
            unpack_svcb(msg, off, length)?;
            Body::Other
        }
        TYPE_OPT => {
            unpack_opt(msg, off, length)?;
            Body::Other
        }
        _ => {
            msg.get(off..off + length)?;
            Body::Other
        }
    })
}

/// `unpackTXTResource`: strings until the record's length, none running
/// past it.
fn unpack_txt(msg: &[u8], mut off: usize, length: usize) -> Option<Vec<Vec<u8>>> {
    let mut strings = Vec::new();
    let mut n = 0;
    while n < length {
        let size = usize::from(*msg.get(off)?);
        let text = msg.get(off + 1..off + 1 + size)?;
        if length - n < size + 1 {
            return None;
        }
        n += size + 1;
        off += 1 + size;
        strings.push(text.to_vec());
    }
    Some(strings)
}

/// `unpackOPTResource`: options until the record's length; the last may
/// run past it.
fn unpack_opt(msg: &[u8], mut off: usize, length: usize) -> Option<()> {
    let end = off + length;
    while off < end {
        uint16(msg, off)?;
        let size = usize::from(uint16(msg, off + 2)?);
        off += 4;
        msg.get(off..off + size)?;
        off += size;
    }
    Some(())
}

/// `unpackSVCBResource`: a priority, a target and parameters in strictly
/// increasing order of key, filling the record exactly.
fn unpack_svcb(msg: &[u8], off: usize, length: usize) -> Option<()> {
    let end = off + length;
    if end > msg.len() {
        return None;
    }
    uint16(msg, off)?;
    let (_, mut off) = unpack_name(msg, off + 2)?;
    let mut previous = None;
    while off < end {
        let key = uint16(msg, off)?;
        if previous.is_some_and(|previous| key <= previous) {
            return None;
        }
        let size = usize::from(uint16(msg, off + 2)?);
        off += 4;
        if off + size > end {
            return None;
        }
        previous = Some(key);
        off += size;
    }
    (off == end).then_some(())
}

/// `Name.unpack`: labels and up to ten compression pointers, the name's
/// bytes with a dot after each label, and the offset after it.
fn unpack_name(msg: &[u8], off: usize) -> Option<(Vec<u8>, usize)> {
    let mut current = off;
    let mut next = off;
    let mut pointers = 0;
    let mut name = Vec::new();
    loop {
        let c = usize::from(*msg.get(current)?);
        current += 1;
        match c & 0xC0 {
            0x00 => {
                if c == 0 {
                    break;
                }
                let label = msg.get(current..current + c)?;
                if label.contains(&b'.') || name.len() + c >= NAME_MAX {
                    return None;
                }
                name.extend_from_slice(label);
                name.push(b'.');
                current += c;
            }
            0xC0 => {
                let low = usize::from(*msg.get(current)?);
                current += 1;
                if pointers == 0 {
                    next = current;
                }
                pointers += 1;
                if pointers > 10 {
                    return None;
                }
                current = (c ^ 0xC0) << 8 | low;
            }
            _ => return None,
        }
    }
    if name.is_empty() {
        name.push(b'.');
    }
    if pointers == 0 {
        next = current;
    }
    Some((name, next))
}

/// The question of a query, for tests that play the server: its name, its
/// type and its OPT record's UDP size.
#[cfg(test)]
pub(crate) fn question(query: &[u8]) -> Option<(Vec<u8>, u16, Option<u16>)> {
    let (name, next) = unpack_name(query, 12)?;
    let qtype = uint16(query, next)?;
    let edns0 = (uint16(query, 10)? == 1)
        .then(|| uint16(query, next + 4 + 3))
        .flatten();
    Some((name, qtype, edns0))
}

/// A TXT answer to `query` carrying `data`, as Xray's server writes one.
#[cfg(test)]
pub(crate) fn txt_answer(query: &[u8], data: &[u8]) -> Vec<u8> {
    let (_, question_end) = unpack_name(query, 12).unwrap();
    let mut out = query[..2].to_vec();
    out.extend_from_slice(&0x8400u16.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
    out.extend_from_slice(&query[12..question_end + 4]);
    let strings: Vec<&[u8]> = data.chunks(255).collect();
    let length: usize = strings.iter().map(|s| s.len() + 1).sum();
    out.extend_from_slice(&[0xC0, 12]);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_INET.to_be_bytes());
    out.extend_from_slice(&60u32.to_be_bytes());
    out.extend_from_slice(&(length as u16).to_be_bytes());
    for string in strings {
        out.push(string.len() as u8);
        out.extend_from_slice(string);
    }
    out
}

/// Packets framed as Xray's server frames them.
#[cfg(test)]
pub(crate) fn frame(packets: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, packet) in packets.iter().enumerate() {
        let mut length = packet.len() as u16;
        if i + 1 == packets.len() {
            length |= 0xC000;
        }
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(packet);
    }
    out
}

#[cfg(test)]
mod tests;

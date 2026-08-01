use bytes::Bytes;
use thiserror::Error;
use xray_config::{DnsOutboundRule, DnsOutboundRuleAction, DnsOutboundSettings, DnsQTypeRange};
use xray_transport::CompiledDomainMatcherSet;

const DNS_HEADER_LEN: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_TYPE_OPT: u16 = 41;
const DNS_CLASS_IN: u16 = 1;
const DNS_RCODE_REFUSED: u16 = 5;

const DNS_FLAG_QR: u16 = 0x8000;
const DNS_FLAG_AA: u16 = 0x0400;
const DNS_FLAG_TC: u16 = 0x0200;
const DNS_FLAG_RD: u16 = 0x0100;
const DNS_FLAG_RA: u16 = 0x0080;
const DNS_FLAG_Z: u16 = 0x0040;
const DNS_FLAG_AD: u16 = 0x0020;
const DNS_FLAG_CD: u16 = 0x0010;
const DNS_FLAG_RCODE: u16 = 0x000f;
const DNS_OPCODE_MASK: u16 = 0x7800;
const DNS_EDNS_DO: u32 = 0x0000_8000;
const DNS_EDNS_Z_MASK: u32 = 0x0000_7fff;

const HIJACK_UNSAFE_AD: u16 = 1 << 0;
const HIJACK_UNSAFE_CD: u16 = 1 << 1;
const HIJACK_UNSAFE_DO: u16 = 1 << 2;
const HIJACK_UNSAFE_EDNS_OPTIONS: u16 = 1 << 3;
const HIJACK_UNSAFE_UNSUPPORTED_EDNS: u16 = 1 << 4;
const HIJACK_UNSAFE_MULTIPLE_QUESTIONS: u16 = 1 << 5;
const HIJACK_UNSAFE_NON_INTERNET_CLASS: u16 = 1 << 6;
const HIJACK_UNSAFE_NON_QUESTION_RECORDS: u16 = 1 << 7;

/// Information from one unframed DNS query needed by the outbound classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsOutboundQuery {
    id: u16,
    request_flags: u16,
    domain: String,
    qtype: u16,
    qclass: u16,
    question_count: u16,
    first_question_end: usize,
    question_section_end: usize,
    edns_udp_payload_size: Option<u16>,
    hijack_unsafe: DnsHijackUnsafe,
    domain_error: Option<DnsQueryParseError>,
}

impl DnsOutboundQuery {
    pub const fn id(&self) -> u16 {
        self.id
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    pub const fn qtype(&self) -> u16 {
        self.qtype
    }

    pub const fn qclass(&self) -> u16 {
        self.qclass
    }

    pub const fn question_count(&self) -> u16 {
        self.question_count
    }

    pub const fn request_flags(&self) -> u16 {
        self.request_flags
    }

    pub const fn question_section_end(&self) -> usize {
        self.question_section_end
    }

    /// UDP payload size advertised by a validated EDNS(0) OPT record.
    pub const fn edns_udp_payload_size(&self) -> Option<u16> {
        self.edns_udp_payload_size
    }

    pub const fn hijack_unsafe(&self) -> Option<DnsHijackUnsafe> {
        if self.hijack_unsafe.is_empty() {
            None
        } else {
            Some(self.hijack_unsafe)
        }
    }
}

/// Reasons why forwarding a query into the core resolver would lose semantics.
///
/// The outbound executor must handle this decision explicitly; it must not turn
/// it into a direct query implicitly because that could bypass split-DNS rules.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DnsHijackUnsafe(u16);

impl DnsHijackUnsafe {
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub const fn authenticated_data(self) -> bool {
        self.0 & HIJACK_UNSAFE_AD != 0
    }

    pub const fn checking_disabled(self) -> bool {
        self.0 & HIJACK_UNSAFE_CD != 0
    }

    pub const fn dnssec_ok(self) -> bool {
        self.0 & HIJACK_UNSAFE_DO != 0
    }

    pub const fn has_edns_options(self) -> bool {
        self.0 & HIJACK_UNSAFE_EDNS_OPTIONS != 0
    }

    pub const fn has_unsupported_edns(self) -> bool {
        self.0 & HIJACK_UNSAFE_UNSUPPORTED_EDNS != 0
    }

    pub const fn has_multiple_questions(self) -> bool {
        self.0 & HIJACK_UNSAFE_MULTIPLE_QUESTIONS != 0
    }

    pub const fn has_non_internet_class(self) -> bool {
        self.0 & HIJACK_UNSAFE_NON_INTERNET_CLASS != 0
    }

    pub const fn has_non_question_records(self) -> bool {
        self.0 & HIJACK_UNSAFE_NON_QUESTION_RECORDS != 0
    }

    fn insert(&mut self, reason: u16) {
        self.0 |= reason;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsOutboundDecision {
    Direct,
    Drop,
    Reject,
    Hijack,
    HijackUnsafe(DnsHijackUnsafe),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DnsQueryParseError {
    #[error("truncated DNS header")]
    TruncatedHeader,
    #[error("DNS message is not a query")]
    NotQuery,
    #[error("unsupported DNS query opcode {0}")]
    UnsupportedOpcode(u8),
    #[error("DNS query has unexpected header flags 0x{0:04x}")]
    UnexpectedHeaderFlags(u16),
    #[error("DNS query has no questions")]
    MissingQuestion,
    #[error("truncated DNS name")]
    TruncatedName,
    #[error("invalid DNS name label type")]
    InvalidNameLabelType,
    #[error("invalid DNS name compression pointer")]
    InvalidNamePointer,
    #[error("DNS name exceeds 255 wire bytes")]
    NameTooLong,
    #[error("DNS question domain is not valid UTF-8")]
    InvalidDomainEncoding,
    #[error("DNS question domain contains a dot inside a wire label")]
    InvalidDomainLabel,
    #[error("truncated DNS question")]
    TruncatedQuestion,
    #[error("truncated DNS resource record")]
    TruncatedRecord,
    #[error("invalid EDNS OPT resource record")]
    InvalidEdns,
    #[error("malformed EDNS option data")]
    MalformedEdnsOptions,
    #[error("trailing bytes after DNS sections")]
    TrailingData,
}

#[derive(Debug, Default)]
pub struct CompiledDnsOutboundPolicy {
    rules: Box<[CompiledDnsOutboundRule]>,
}

impl CompiledDnsOutboundPolicy {
    pub fn new(settings: &DnsOutboundSettings) -> Self {
        Self::from_rules(&settings.rules)
    }

    pub fn from_rules(rules: &[DnsOutboundRule]) -> Self {
        Self {
            rules: rules
                .iter()
                .map(CompiledDnsOutboundRule::new)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }

    pub fn decide(&self, query: &DnsOutboundQuery, own_link: bool) -> DnsOutboundDecision {
        if own_link {
            return DnsOutboundDecision::Direct;
        }

        let action = self.selected_action(query.qtype, &query.domain);
        decision_for_action(action, query)
    }

    fn selected_action(&self, qtype: u16, domain: &str) -> DnsOutboundRuleAction {
        self.rules
            .iter()
            .find(|rule| rule.matches(qtype, domain))
            .map_or_else(
                || {
                    if is_address_qtype(qtype) {
                        DnsOutboundRuleAction::Hijack
                    } else {
                        DnsOutboundRuleAction::Reject
                    }
                },
                |rule| rule.action,
            )
    }

    /// Parses and classifies one unframed DNS message.
    ///
    /// Own-link traffic bypasses parsing, matching Xray's recursion guard: the
    /// original bytes must be forwarded directly even when the local resolver
    /// would not understand them. Direct, Drop, and Reject deliberately require
    /// only the first question; full RR and EDNS validation is deferred until a
    /// query is actually selected for Hijack.
    pub fn decide_message(
        &self,
        message: &[u8],
        own_link: bool,
    ) -> Result<DnsOutboundDecision, DnsQueryParseError> {
        if own_link {
            return Ok(DnsOutboundDecision::Direct);
        }

        let mut query = parse_dns_query_prefix(message)?;
        let action = self.selected_action(query.qtype, &query.domain);
        if action != DnsOutboundRuleAction::Hijack {
            return Ok(decision_for_action(action, &query));
        }
        if !is_address_qtype(query.qtype) {
            return Ok(DnsOutboundDecision::Reject);
        }

        validate_dns_query_envelope(message, &mut query)?;
        Ok(decision_for_action(action, &query))
    }
}

fn decision_for_action(
    action: DnsOutboundRuleAction,
    query: &DnsOutboundQuery,
) -> DnsOutboundDecision {
    match action {
        DnsOutboundRuleAction::Direct => DnsOutboundDecision::Direct,
        DnsOutboundRuleAction::Drop => DnsOutboundDecision::Drop,
        DnsOutboundRuleAction::Reject => DnsOutboundDecision::Reject,
        DnsOutboundRuleAction::Hijack if !is_address_qtype(query.qtype) => {
            DnsOutboundDecision::Reject
        }
        DnsOutboundRuleAction::Hijack => query.hijack_unsafe().map_or(
            DnsOutboundDecision::Hijack,
            DnsOutboundDecision::HijackUnsafe,
        ),
    }
}

#[derive(Debug)]
struct CompiledDnsOutboundRule {
    action: DnsOutboundRuleAction,
    all_qtypes: bool,
    qtype_ranges: Box<[(u16, u16)]>,
    all_domains: bool,
    domain_matchers: CompiledDomainMatcherSet,
}

impl CompiledDnsOutboundRule {
    fn new(rule: &DnsOutboundRule) -> Self {
        Self {
            action: rule.action,
            all_qtypes: rule.qtype_ranges.is_empty(),
            qtype_ranges: compile_qtype_ranges(&rule.qtype_ranges),
            all_domains: rule.domain_matchers.is_empty(),
            domain_matchers: CompiledDomainMatcherSet::new(
                rule.domain_matchers
                    .iter()
                    .map(crate::transport_domain_matcher)
                    .collect(),
            ),
        }
    }

    fn matches(&self, qtype: u16, domain: &str) -> bool {
        (self.all_qtypes || qtype_ranges_contain(&self.qtype_ranges, qtype))
            && (self.all_domains || self.domain_matchers.matches(domain))
    }
}

fn compile_qtype_ranges(ranges: &[DnsQTypeRange]) -> Box<[(u16, u16)]> {
    let mut compiled = ranges
        .iter()
        .map(|range| (range.start(), range.end()))
        .collect::<Vec<_>>();
    compiled.sort_unstable();

    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(compiled.len());
    for (start, end) in compiled {
        if let Some(previous) = merged.last_mut() {
            if start <= previous.1.saturating_add(1) {
                previous.1 = previous.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged.into_boxed_slice()
}

fn qtype_ranges_contain(ranges: &[(u16, u16)], qtype: u16) -> bool {
    let candidate = ranges.partition_point(|(_, end)| *end < qtype);
    ranges
        .get(candidate)
        .is_some_and(|(start, end)| (*start..=*end).contains(&qtype))
}

const fn is_address_qtype(qtype: u16) -> bool {
    matches!(qtype, DNS_TYPE_A | DNS_TYPE_AAAA)
}

/// Parses one complete, unframed DNS QUERY and returns its first question.
pub fn parse_dns_query(message: &[u8]) -> Result<DnsOutboundQuery, DnsQueryParseError> {
    let mut query = parse_dns_query_prefix(message)?;
    validate_dns_query_envelope(message, &mut query)?;
    Ok(query)
}

pub(crate) fn parse_dns_query_prefix(
    message: &[u8],
) -> Result<DnsOutboundQuery, DnsQueryParseError> {
    if message.len() < DNS_HEADER_LEN {
        return Err(DnsQueryParseError::TruncatedHeader);
    }

    let id = read_u16(message, 0).ok_or(DnsQueryParseError::TruncatedHeader)?;
    let request_flags = read_u16(message, 2).ok_or(DnsQueryParseError::TruncatedHeader)?;
    let question_count = read_u16(message, 4).ok_or(DnsQueryParseError::TruncatedHeader)?;
    if question_count == 0 {
        return Err(DnsQueryParseError::MissingQuestion);
    }

    let mut offset = DNS_HEADER_LEN;
    let mut domain = String::new();
    let domain_error = read_dns_name(message, &mut offset, Some(&mut domain))?;
    if domain.is_empty() {
        domain.push('.');
    }
    domain.make_ascii_lowercase();
    let qtype = read_u16(message, offset).ok_or(DnsQueryParseError::TruncatedQuestion)?;
    let qclass = read_u16(
        message,
        offset
            .checked_add(2)
            .ok_or(DnsQueryParseError::TruncatedQuestion)?,
    )
    .ok_or(DnsQueryParseError::TruncatedQuestion)?;
    offset = offset
        .checked_add(4)
        .ok_or(DnsQueryParseError::TruncatedQuestion)?;

    let mut hijack_unsafe = DnsHijackUnsafe::default();
    if request_flags & DNS_FLAG_AD != 0 {
        hijack_unsafe.insert(HIJACK_UNSAFE_AD);
    }
    if request_flags & DNS_FLAG_CD != 0 {
        hijack_unsafe.insert(HIJACK_UNSAFE_CD);
    }
    if question_count != 1 {
        hijack_unsafe.insert(HIJACK_UNSAFE_MULTIPLE_QUESTIONS);
    }
    if qclass != DNS_CLASS_IN {
        hijack_unsafe.insert(HIJACK_UNSAFE_NON_INTERNET_CLASS);
    }

    Ok(DnsOutboundQuery {
        id,
        request_flags,
        domain,
        qtype,
        qclass,
        question_count,
        first_question_end: offset,
        question_section_end: offset,
        edns_udp_payload_size: None,
        hijack_unsafe,
        domain_error,
    })
}

fn validate_dns_query_envelope(
    message: &[u8],
    query: &mut DnsOutboundQuery,
) -> Result<(), DnsQueryParseError> {
    if let Some(error) = query.domain_error {
        return Err(error);
    }
    if query.request_flags & DNS_FLAG_QR != 0 {
        return Err(DnsQueryParseError::NotQuery);
    }
    let opcode = ((query.request_flags & DNS_OPCODE_MASK) >> 11) as u8;
    if opcode != 0 {
        return Err(DnsQueryParseError::UnsupportedOpcode(opcode));
    }
    let unexpected_flags = query.request_flags
        & (DNS_FLAG_AA | DNS_FLAG_TC | DNS_FLAG_RA | DNS_FLAG_Z | DNS_FLAG_RCODE);
    if unexpected_flags != 0 {
        return Err(DnsQueryParseError::UnexpectedHeaderFlags(unexpected_flags));
    }
    let answer_count = read_u16(message, 6).ok_or(DnsQueryParseError::TruncatedHeader)?;
    let authority_count = read_u16(message, 8).ok_or(DnsQueryParseError::TruncatedHeader)?;
    let additional_count = read_u16(message, 10).ok_or(DnsQueryParseError::TruncatedHeader)?;
    let mut offset = query.first_question_end;

    for _ in 1..query.question_count {
        let _ = read_dns_name(message, &mut offset, None)?;
        offset = offset
            .checked_add(4)
            .filter(|end| *end <= message.len())
            .ok_or(DnsQueryParseError::TruncatedQuestion)?;
    }
    query.question_section_end = offset;

    if answer_count != 0 || authority_count != 0 {
        query
            .hijack_unsafe
            .insert(HIJACK_UNSAFE_NON_QUESTION_RECORDS);
    }

    let mut seen_opt = false;
    let mut edns_udp_payload_size = None;
    parse_resource_records(
        message,
        &mut offset,
        answer_count,
        false,
        &mut seen_opt,
        &mut query.hijack_unsafe,
        &mut edns_udp_payload_size,
    )?;
    parse_resource_records(
        message,
        &mut offset,
        authority_count,
        false,
        &mut seen_opt,
        &mut query.hijack_unsafe,
        &mut edns_udp_payload_size,
    )?;
    parse_resource_records(
        message,
        &mut offset,
        additional_count,
        true,
        &mut seen_opt,
        &mut query.hijack_unsafe,
        &mut edns_udp_payload_size,
    )?;

    query.edns_udp_payload_size = edns_udp_payload_size;

    if offset != message.len() {
        return Err(DnsQueryParseError::TrailingData);
    }
    Ok(())
}

fn parse_resource_records(
    message: &[u8],
    offset: &mut usize,
    count: u16,
    is_additional: bool,
    seen_opt: &mut bool,
    hijack_unsafe: &mut DnsHijackUnsafe,
    edns_udp_payload_size: &mut Option<u16>,
) -> Result<(), DnsQueryParseError> {
    for _ in 0..count {
        let owner_start = *offset;
        let _ = read_dns_name(message, offset, None)?;
        let owner_is_root = *offset == owner_start.saturating_add(1)
            && message.get(owner_start).copied() == Some(0);
        let record_type = read_u16(message, *offset).ok_or(DnsQueryParseError::TruncatedRecord)?;
        let record_class = read_u16(
            message,
            offset
                .checked_add(2)
                .ok_or(DnsQueryParseError::TruncatedRecord)?,
        )
        .ok_or(DnsQueryParseError::TruncatedRecord)?;
        let record_ttl = read_u32(
            message,
            offset
                .checked_add(4)
                .ok_or(DnsQueryParseError::TruncatedRecord)?,
        )
        .ok_or(DnsQueryParseError::TruncatedRecord)?;
        let data_len = usize::from(
            read_u16(
                message,
                offset
                    .checked_add(8)
                    .ok_or(DnsQueryParseError::TruncatedRecord)?,
            )
            .ok_or(DnsQueryParseError::TruncatedRecord)?,
        );
        let data_start = offset
            .checked_add(10)
            .ok_or(DnsQueryParseError::TruncatedRecord)?;
        let data_end = data_start
            .checked_add(data_len)
            .filter(|end| *end <= message.len())
            .ok_or(DnsQueryParseError::TruncatedRecord)?;

        if record_type == DNS_TYPE_OPT {
            if !is_additional || !owner_is_root || *seen_opt {
                return Err(DnsQueryParseError::InvalidEdns);
            }
            *seen_opt = true;
            *edns_udp_payload_size = Some(record_class);
            if record_ttl & DNS_EDNS_DO != 0 {
                hijack_unsafe.insert(HIJACK_UNSAFE_DO);
            }
            let extended_rcode = (record_ttl >> 24) as u8;
            let version = (record_ttl >> 16) as u8;
            if extended_rcode != 0 || version != 0 || record_ttl & DNS_EDNS_Z_MASK != 0 {
                hijack_unsafe.insert(HIJACK_UNSAFE_UNSUPPORTED_EDNS);
            }
            if data_len != 0 {
                validate_edns_options(message, data_start, data_end)?;
                hijack_unsafe.insert(HIJACK_UNSAFE_EDNS_OPTIONS);
            }
            let _udp_payload_size = record_class;
        } else if is_additional {
            hijack_unsafe.insert(HIJACK_UNSAFE_NON_QUESTION_RECORDS);
        }

        *offset = data_end;
    }
    Ok(())
}

fn validate_edns_options(
    message: &[u8],
    mut offset: usize,
    data_end: usize,
) -> Result<(), DnsQueryParseError> {
    while offset < data_end {
        let header_end = offset
            .checked_add(4)
            .filter(|end| *end <= data_end)
            .ok_or(DnsQueryParseError::MalformedEdnsOptions)?;
        let option_len = usize::from(
            read_u16(message, offset + 2).ok_or(DnsQueryParseError::MalformedEdnsOptions)?,
        );
        offset = header_end
            .checked_add(option_len)
            .filter(|end| *end <= data_end)
            .ok_or(DnsQueryParseError::MalformedEdnsOptions)?;
    }
    Ok(())
}

fn read_dns_name(
    message: &[u8],
    offset: &mut usize,
    mut domain: Option<&mut String>,
) -> Result<Option<DnsQueryParseError>, DnsQueryParseError> {
    let mut cursor = *offset;
    let mut jumped = false;
    let mut expanded_len = 1usize;
    let mut pointer_count = 0usize;
    let mut domain_error = None;

    loop {
        let label_len = *message
            .get(cursor)
            .ok_or(DnsQueryParseError::TruncatedName)?;
        match label_len & 0xc0 {
            0xc0 => {
                let next = *message
                    .get(cursor + 1)
                    .ok_or(DnsQueryParseError::TruncatedName)?;
                let pointer = (usize::from(label_len & 0x3f) << 8) | usize::from(next);
                if pointer < DNS_HEADER_LEN || pointer >= cursor {
                    return Err(DnsQueryParseError::InvalidNamePointer);
                }
                if !jumped {
                    *offset = cursor + 2;
                    jumped = true;
                }
                cursor = pointer;
                pointer_count += 1;
                if pointer_count > 128 {
                    return Err(DnsQueryParseError::InvalidNamePointer);
                }
            }
            0x00 if label_len == 0 => {
                if !jumped {
                    *offset = cursor + 1;
                }
                return Ok(domain_error);
            }
            0x00 => {
                let label_start = cursor + 1;
                let label_end = label_start
                    .checked_add(usize::from(label_len))
                    .filter(|end| *end <= message.len())
                    .ok_or(DnsQueryParseError::TruncatedName)?;
                expanded_len = expanded_len
                    .checked_add(usize::from(label_len) + 1)
                    .filter(|len| *len <= 255)
                    .ok_or(DnsQueryParseError::NameTooLong)?;

                if let Some(output) = domain.as_deref_mut() {
                    let label = message
                        .get(label_start..label_end)
                        .ok_or(DnsQueryParseError::TruncatedName)?;
                    if label.contains(&b'.') {
                        domain_error.get_or_insert(DnsQueryParseError::InvalidDomainLabel);
                    }
                    if !output.is_empty() {
                        output.push('.');
                    }
                    match std::str::from_utf8(label) {
                        Ok(label) => output.push_str(label),
                        Err(_) => {
                            domain_error.get_or_insert(DnsQueryParseError::InvalidDomainEncoding);
                            output.push_str(&String::from_utf8_lossy(label));
                        }
                    }
                }

                cursor = label_end;
                if !jumped {
                    *offset = cursor;
                }
            }
            _ => return Err(DnsQueryParseError::InvalidNameLabelType),
        }
    }
}

fn read_u16(message: &[u8], offset: usize) -> Option<u16> {
    let bytes = message.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(message: &[u8], offset: usize) -> Option<u32> {
    let bytes = message.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Builds a REFUSED response for one complete, unframed DNS QUERY.
pub fn build_refused_response(message: &[u8]) -> Result<Bytes, DnsQueryParseError> {
    let query = parse_dns_query_prefix(message)?;
    let mut response = Vec::with_capacity(query.first_question_end);
    response.extend_from_slice(&message[..query.first_question_end]);

    let response_flags = DNS_FLAG_QR
        | DNS_FLAG_AA
        | DNS_FLAG_RA
        | (query.request_flags & (DNS_FLAG_RD | DNS_FLAG_CD))
        | DNS_RCODE_REFUSED;
    response[2..4].copy_from_slice(&response_flags.to_be_bytes());
    response[4..6].copy_from_slice(&1_u16.to_be_bytes());
    response[6..12].fill(0);
    Ok(Bytes::from(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use xray_config::DomainMatcher;

    fn query(id: u16, domain: &str, qtype: u16, flags: u16) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&id.to_be_bytes());
        message.extend_from_slice(&flags.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        for label in domain.trim_end_matches('.').split('.') {
            if label.is_empty() {
                continue;
            }
            message.push(u8::try_from(label.len()).expect("test label fits DNS wire format"));
            message.extend_from_slice(label.as_bytes());
        }
        message.push(0);
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message
    }

    fn with_edns(mut message: Vec<u8>, ttl: u32, options: &[u8]) -> Vec<u8> {
        message[10..12].copy_from_slice(&1_u16.to_be_bytes());
        message.push(0);
        message.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        message.extend_from_slice(&1232_u16.to_be_bytes());
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(
            &u16::try_from(options.len())
                .expect("test EDNS options fit")
                .to_be_bytes(),
        );
        message.extend_from_slice(options);
        message
    }

    fn settings(rules: Vec<DnsOutboundRule>) -> DnsOutboundSettings {
        DnsOutboundSettings {
            rules,
            ..DnsOutboundSettings::default()
        }
    }

    fn rule(
        action: DnsOutboundRuleAction,
        qtype_ranges: Vec<DnsQTypeRange>,
        domain_matchers: Vec<DomainMatcher>,
    ) -> DnsOutboundRule {
        DnsOutboundRule {
            action,
            qtype_ranges,
            domain_matchers,
        }
    }

    #[test]
    fn parser_normalizes_the_first_question() {
        let message = query(0x1234, "WWW.Example.COM.", DNS_TYPE_AAAA, DNS_FLAG_RD);
        let parsed = parse_dns_query(&message).unwrap();

        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.domain(), "www.example.com");
        assert_eq!(parsed.qtype(), DNS_TYPE_AAAA);
        assert_eq!(parsed.qclass(), DNS_CLASS_IN);
        assert_eq!(parsed.question_count(), 1);
        assert_eq!(parsed.request_flags(), DNS_FLAG_RD);
        assert_eq!(parsed.question_section_end(), message.len());
        assert_eq!(parsed.hijack_unsafe(), None);
    }

    #[test]
    fn parser_distinguishes_non_queries_and_malformed_queries() {
        let mut response = query(1, "example.com", DNS_TYPE_A, 0);
        response[2] |= 0x80;
        assert_eq!(
            parse_dns_query(&response),
            Err(DnsQueryParseError::NotQuery)
        );

        let mut no_question = query(1, "example.com", DNS_TYPE_A, 0);
        no_question[4..6].fill(0);
        assert_eq!(
            parse_dns_query(&no_question),
            Err(DnsQueryParseError::MissingQuestion)
        );

        let mut pointer_loop = query(1, "example.com", DNS_TYPE_A, 0);
        pointer_loop[12] = 0xc0;
        pointer_loop[13] = 0x0c;
        assert_eq!(
            parse_dns_query(&pointer_loop),
            Err(DnsQueryParseError::InvalidNamePointer)
        );

        assert_eq!(
            parse_dns_query(&[0; 11]),
            Err(DnsQueryParseError::TruncatedHeader)
        );
    }

    #[test]
    fn policy_is_ordered_and_compiles_qtype_and_domain_matchers() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![
            rule(
                DnsOutboundRuleAction::Direct,
                vec![DnsQTypeRange::new(1, 2).unwrap()],
                vec![DomainMatcher::Suffix("Example.COM.".into())],
            ),
            rule(
                DnsOutboundRuleAction::Drop,
                vec![DnsQTypeRange::single(DNS_TYPE_A)],
                vec![],
            ),
            rule(DnsOutboundRuleAction::Reject, vec![], vec![]),
        ]));

        assert_eq!(
            policy
                .decide_message(&query(1, "WWW.example.com", DNS_TYPE_A, 0), false)
                .unwrap(),
            DnsOutboundDecision::Direct
        );
        assert_eq!(
            policy
                .decide_message(&query(1, "other.test", DNS_TYPE_A, 0), false)
                .unwrap(),
            DnsOutboundDecision::Drop
        );
        assert_eq!(
            policy
                .decide_message(&query(1, "other.test", 16, 0), false)
                .unwrap(),
            DnsOutboundDecision::Reject
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![
            rule(DnsOutboundRuleAction::Drop, vec![], vec![]),
            rule(DnsOutboundRuleAction::Direct, vec![], vec![]),
        ]));
        let message = query(1, "example.com", DNS_TYPE_A, 0);

        assert_eq!(
            policy.decide_message(&message, false).unwrap(),
            DnsOutboundDecision::Drop
        );
    }

    #[test]
    fn fallback_hijacks_only_address_queries() {
        let policy = CompiledDnsOutboundPolicy::default();

        for qtype in [DNS_TYPE_A, DNS_TYPE_AAAA] {
            assert_eq!(
                policy
                    .decide_message(&query(1, "example.com", qtype, 0), false)
                    .unwrap(),
                DnsOutboundDecision::Hijack
            );
        }
        assert_eq!(
            policy
                .decide_message(&query(1, "example.com", 16, 0), false)
                .unwrap(),
            DnsOutboundDecision::Reject
        );
    }

    #[test]
    fn own_link_forces_direct_before_parsing_or_rules() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![rule(
            DnsOutboundRuleAction::Drop,
            vec![],
            vec![],
        )]));

        assert_eq!(
            policy.decide_message(&[0xff], true).unwrap(),
            DnsOutboundDecision::Direct
        );
    }

    #[test]
    fn direct_preserves_a_message_with_a_malformed_trailing_record() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![rule(
            DnsOutboundRuleAction::Direct,
            vec![],
            vec![],
        )]));
        let mut message = query(1, "example.com", DNS_TYPE_A, 0);
        message[10..12].copy_from_slice(&1_u16.to_be_bytes());
        message.push(0); // OPT owner without the fixed resource-record fields.
        let original = message.clone();

        assert_eq!(
            policy.decide_message(&message, false).unwrap(),
            DnsOutboundDecision::Direct
        );
        assert_eq!(message, original);
        assert_eq!(
            parse_dns_query(&message),
            Err(DnsQueryParseError::TruncatedRecord)
        );
    }

    #[test]
    fn direct_classifies_update_opcode_from_the_first_question_only() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![rule(
            DnsOutboundRuleAction::Direct,
            vec![],
            vec![],
        )]));
        let mut message = query(2, "update.example", 6, 5 << 11);
        message[8..10].copy_from_slice(&1_u16.to_be_bytes());
        message.push(0);

        assert_eq!(
            policy.decide_message(&message, false).unwrap(),
            DnsOutboundDecision::Direct
        );
        assert_eq!(
            parse_dns_query(&message),
            Err(DnsQueryParseError::UnsupportedOpcode(5))
        );
    }

    #[test]
    fn qtype_only_direct_accepts_non_utf8_wire_label() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![rule(
            DnsOutboundRuleAction::Direct,
            vec![DnsQTypeRange::single(DNS_TYPE_A)],
            vec![],
        )]));
        let mut message = query(3, "opaque.example", DNS_TYPE_A, 0);
        message[13] = 0xff;

        assert_eq!(
            policy.decide_message(&message, false).unwrap(),
            DnsOutboundDecision::Direct
        );
        assert_eq!(
            parse_dns_query(&message),
            Err(DnsQueryParseError::InvalidDomainEncoding)
        );
    }

    #[test]
    fn malformed_trailing_record_fails_closed_only_when_hijacking() {
        let policy = CompiledDnsOutboundPolicy::default();
        let mut message = query(1, "example.com", DNS_TYPE_A, 0);
        message[10..12].copy_from_slice(&1_u16.to_be_bytes());
        message.push(0);

        assert_eq!(
            policy.decide_message(&message, false),
            Err(DnsQueryParseError::TruncatedRecord)
        );
    }

    #[test]
    fn explicit_hijack_of_non_address_query_is_rejected() {
        let policy = CompiledDnsOutboundPolicy::new(&settings(vec![rule(
            DnsOutboundRuleAction::Hijack,
            vec![],
            vec![],
        )]));

        assert_eq!(
            policy
                .decide_message(&query(1, "example.com", 16, 0), false)
                .unwrap(),
            DnsOutboundDecision::Reject
        );
    }

    #[test]
    fn dnssec_and_edns_semantics_are_typed_as_unsafe_hijacks() {
        let policy = CompiledDnsOutboundPolicy::default();

        let ad = policy
            .decide_message(&query(1, "example.com", DNS_TYPE_A, DNS_FLAG_AD), false)
            .unwrap();
        let DnsOutboundDecision::HijackUnsafe(ad) = ad else {
            panic!("expected unsafe AD hijack");
        };
        assert!(ad.authenticated_data());

        let cd = policy
            .decide_message(&query(1, "example.com", DNS_TYPE_A, DNS_FLAG_CD), false)
            .unwrap();
        let DnsOutboundDecision::HijackUnsafe(cd) = cd else {
            panic!("expected unsafe CD hijack");
        };
        assert!(cd.checking_disabled());

        let dnssec_ok = with_edns(query(1, "example.com", DNS_TYPE_A, 0), DNS_EDNS_DO, &[]);
        let DnsOutboundDecision::HijackUnsafe(dnssec_ok) =
            policy.decide_message(&dnssec_ok, false).unwrap()
        else {
            panic!("expected unsafe DO hijack");
        };
        assert!(dnssec_ok.dnssec_ok());

        let options = with_edns(query(1, "example.com", DNS_TYPE_A, 0), 0, &[0, 3, 0, 0]);
        let DnsOutboundDecision::HijackUnsafe(options) =
            policy.decide_message(&options, false).unwrap()
        else {
            panic!("expected unsafe EDNS options hijack");
        };
        assert!(options.has_edns_options());

        let unsupported = with_edns(query(1, "example.com", DNS_TYPE_A, 0), 1 << 16, &[]);
        let DnsOutboundDecision::HijackUnsafe(unsupported) =
            policy.decide_message(&unsupported, false).unwrap()
        else {
            panic!("expected unsupported EDNS hijack");
        };
        assert!(unsupported.has_unsupported_edns());
    }

    #[test]
    fn empty_supported_edns_can_be_hijacked() {
        let policy = CompiledDnsOutboundPolicy::default();
        let message = with_edns(query(1, "example.com", DNS_TYPE_A, 0), 0, &[]);

        assert_eq!(
            policy.decide_message(&message, false).unwrap(),
            DnsOutboundDecision::Hijack
        );
    }

    #[test]
    fn malformed_edns_options_are_rejected_by_the_parser() {
        let message = with_edns(query(1, "example.com", DNS_TYPE_A, 0), 0, &[0, 3, 0, 4]);

        assert_eq!(
            parse_dns_query(&message),
            Err(DnsQueryParseError::MalformedEdnsOptions)
        );
    }

    #[test]
    fn refused_response_preserves_id_questions_and_relevant_flags() {
        let message = with_edns(
            query(
                0xabcd,
                "Example.COM",
                16,
                DNS_FLAG_RD | DNS_FLAG_AD | DNS_FLAG_CD,
            ),
            0,
            &[],
        );
        let parsed = parse_dns_query(&message).unwrap();
        let response = build_refused_response(&message).unwrap();
        let flags = read_u16(&response, 2).unwrap();

        assert_eq!(&response[..2], &0xabcd_u16.to_be_bytes());
        assert_eq!(flags & DNS_FLAG_QR, DNS_FLAG_QR);
        assert_eq!(flags & DNS_FLAG_AA, DNS_FLAG_AA);
        assert_eq!(flags & DNS_FLAG_RA, DNS_FLAG_RA);
        assert_eq!(flags & DNS_FLAG_RD, DNS_FLAG_RD);
        assert_eq!(flags & DNS_FLAG_CD, DNS_FLAG_CD);
        assert_eq!(flags & DNS_FLAG_AD, 0);
        assert_eq!(flags & DNS_FLAG_RCODE, DNS_RCODE_REFUSED);
        assert_eq!(read_u16(&response, 4), Some(1));
        assert_eq!(read_u16(&response, 6), Some(0));
        assert_eq!(read_u16(&response, 8), Some(0));
        assert_eq!(read_u16(&response, 10), Some(0));
        assert_eq!(
            &response[DNS_HEADER_LEN..],
            &message[DNS_HEADER_LEN..parsed.question_section_end]
        );
    }
}

//! The `header-custom` mask of Xray-core v26.10.31: items that send random
//! bytes, fixed bytes, captured variables or the value of a transform, and
//! the TCP handshake and UDP prefix or standalone exchange that use them.
//!
//! Xray runs the client's handshake on the first write. A client always
//! writes first, so the dialer runs it as soon as TCP connects, which gives
//! the same bytes in the same order and lets REALITY complete over the
//! socket afterwards.
use std::{collections::HashMap, fmt, io, net::SocketAddr, time::Duration};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) mod quic;
pub(crate) mod udp;
pub use udp::HeaderCustomUdpConfig;

/// The `header-custom` TCP mask a client applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HeaderCustomTcpConfig {
    /// Sequences the client sends, in turn with `servers`.
    pub clients: Vec<Vec<CustomItem>>,
    /// Sequences the server answers with, each checked byte for byte.
    pub servers: Vec<Vec<CustomItem>>,
}

/// One item of a sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomItem {
    /// Milliseconds to wait before the item when the upper bound is positive.
    pub delay: (i32, i32),
    /// This many random bytes, each within `rand_range`.
    pub rand: i32,
    pub rand_range: (u8, u8),
    pub packet: Vec<u8>,
    /// Saves the item's bytes under this name.
    pub capture: String,
    /// The bytes saved under this name.
    pub reuse: String,
    pub transform: Option<CustomExpr>,
}

/// An operation over arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomExpr {
    pub op: String,
    pub args: Vec<CustomArg>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustomArg {
    Bytes(Vec<u8>),
    U64(u64),
    Reuse(String),
    Metadata(String),
    Transform(CustomExpr),
}

/// Why an item could not be evaluated, measured or matched, in Xray's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError(String);

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for EvalError {}

fn error(message: impl Into<String>) -> EvalError {
    EvalError(message.into())
}

/// A transform's value: bytes, or an unsigned integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    Bytes(Vec<u8>),
    U64(u64),
}

impl Value {
    fn bytes(self) -> Result<Vec<u8>, EvalError> {
        match self {
            Self::Bytes(bytes) => Ok(bytes),
            Self::U64(_) => Err(error("expr value is not bytes")),
        }
    }

    fn u64(&self) -> Result<u64, EvalError> {
        match self {
            Self::U64(value) => Ok(*value),
            Self::Bytes(_) => Err(error("expr value is not u64")),
        }
    }
}

/// Captured variables and the connection's addresses.
#[derive(Debug, Clone, Default)]
pub(crate) struct Context {
    pub(crate) vars: HashMap<String, Vec<u8>>,
    metadata: HashMap<String, u64>,
}

impl Context {
    /// The metadata Xray's `loadMetadata` takes from a connection's local and
    /// remote addresses. It names the remote end `src` and the local `dst`.
    pub(crate) fn with_addresses(local: Option<SocketAddr>, remote: Option<SocketAddr>) -> Self {
        let mut context = Self::default();
        for (prefix, alias, address) in [("local", "dst", local), ("remote", "src", remote)] {
            let Some(address) = address else {
                continue;
            };
            let port = u64::from(address.port());
            context.metadata.insert(format!("{prefix}_port"), port);
            context.metadata.insert(format!("{alias}_port_u16"), port);
            let ipv4 = match address {
                SocketAddr::V4(address) => Some(*address.ip()),
                SocketAddr::V6(address) => address.ip().to_ipv4_mapped(),
            };
            if let Some(ipv4) = ipv4 {
                let ip = u64::from(u32::from(ipv4));
                context.metadata.insert(format!("{prefix}_ip4_u32"), ip);
                context.metadata.insert(format!("{alias}_ip4_u32"), ip);
            }
        }
        context
    }

    fn sizes(&self) -> HashMap<String, usize> {
        self.vars
            .iter()
            .map(|(name, value)| (name.clone(), value.len()))
            .collect()
    }
}

/// The longest item sent or read, and `pad` result, here. Xray-core
/// allocates whatever is asked, and captures can double an item each step.
const MAX_ITEM: usize = 1 << 20;

/// Go's `crypto.RandBetween`: the upper end is never drawn.
fn rand_between(from: i64, to: i64) -> i64 {
    let (from, to) = (from.min(to), from.max(to));
    if to - from <= 1 {
        return from;
    }
    from + rand::thread_rng().gen_range(0..to - from)
}

/// An item's bytes, saved under its capture name.
pub(crate) fn evaluate_item(
    item: &CustomItem,
    context: &mut Context,
) -> Result<Vec<u8>, EvalError> {
    let value = if item.rand > 0 {
        let (low, high) = (
            item.rand_range.0.min(item.rand_range.1),
            item.rand_range.0.max(item.rand_range.1),
        );
        let mut rng = rand::thread_rng();
        (0..item.rand).map(|_| rng.gen_range(low..=high)).collect()
    } else if !item.packet.is_empty() {
        item.packet.clone()
    } else if !item.reuse.is_empty() {
        context
            .vars
            .get(&item.reuse)
            .cloned()
            .ok_or_else(|| error(format!("unknown variable: {}", item.reuse)))?
    } else if let Some(expr) = &item.transform {
        evaluate_expr(expr, context)?.bytes()?
    } else {
        Vec::new()
    };
    if !item.capture.is_empty() {
        context.vars.insert(item.capture.clone(), value.clone());
    }
    Ok(value)
}

/// How many bytes an item takes, from the sizes of the variables before it.
pub(crate) fn measure_item(
    item: &CustomItem,
    sizes: &mut HashMap<String, usize>,
) -> Result<usize, EvalError> {
    let size = if item.rand > 0 {
        item.rand as usize
    } else if !item.packet.is_empty() {
        item.packet.len()
    } else if !item.reuse.is_empty() {
        *sizes
            .get(&item.reuse)
            .ok_or_else(|| error(format!("unknown variable: {}", item.reuse)))?
    } else if let Some(expr) = &item.transform {
        measure_expr(expr, sizes)?
    } else {
        0
    };
    if !item.capture.is_empty() {
        sizes.insert(item.capture.clone(), size);
    }
    Ok(size)
}

fn measure_expr(expr: &CustomExpr, sizes: &HashMap<String, usize>) -> Result<usize, EvalError> {
    let literal_length = |index: usize, count: usize, what: &str| {
        if expr.args.len() != count {
            return Err(error(format!("{} expects {count} args", expr.op)));
        }
        match &expr.args[index] {
            CustomArg::U64(value) => {
                usize::try_from(*value).map_err(|_| error("item size overflow"))
            }
            _ => Err(error(format!("{what} length must be u64"))),
        }
    };
    match expr.op.as_str() {
        "concat" => expr.args.iter().try_fold(0usize, |total, arg| {
            total
                .checked_add(measure_arg(arg, sizes)?)
                .ok_or_else(|| error("item size overflow"))
        }),
        "slice" => literal_length(2, 3, "slice"),
        "be16" | "le16" => Ok(2),
        "be32" | "le32" => Ok(4),
        "le64" => Ok(8),
        "pad" => literal_length(1, 3, "pad"),
        "truncate" => literal_length(1, 2, "truncate"),
        op => Err(error(format!("expr size is not bytes for op: {op}"))),
    }
}

fn measure_arg(arg: &CustomArg, sizes: &HashMap<String, usize>) -> Result<usize, EvalError> {
    match arg {
        CustomArg::Bytes(bytes) => Ok(bytes.len()),
        CustomArg::U64(_) => Err(error("u64 arg has no byte width")),
        CustomArg::Reuse(name) => sizes
            .get(name)
            .copied()
            .ok_or_else(|| error(format!("unknown variable: {name}"))),
        CustomArg::Metadata(name) => Err(error(format!("metadata not implemented: {name}"))),
        CustomArg::Transform(expr) => measure_expr(expr, sizes),
    }
}

fn evaluate_arg(arg: &CustomArg, context: &Context) -> Result<Value, EvalError> {
    match arg {
        CustomArg::Bytes(bytes) => Ok(Value::Bytes(bytes.clone())),
        CustomArg::U64(value) => Ok(Value::U64(*value)),
        CustomArg::Reuse(name) => context
            .vars
            .get(name)
            .cloned()
            .map(Value::Bytes)
            .ok_or_else(|| error(format!("unknown variable: {name}"))),
        CustomArg::Metadata(name) => context
            .metadata
            .get(name)
            .copied()
            .map(Value::U64)
            .ok_or_else(|| error(format!("unknown metadata: {name}"))),
        CustomArg::Transform(expr) => evaluate_expr(expr, context),
    }
}

fn args<const N: usize>(expr: &CustomExpr, context: &Context) -> Result<[Value; N], EvalError> {
    let name = match expr.op.as_str() {
        "xor16" | "xor32" => "xor",
        op => op,
    };
    if expr.args.len() != N {
        return Err(error(format!(
            "{name} expects {N} arg{}",
            if N == 1 { "" } else { "s" }
        )));
    }
    let mut values = Vec::with_capacity(N);
    for arg in &expr.args {
        values.push(evaluate_arg(arg, context)?);
    }
    Ok(values.try_into().unwrap_or_else(|_| unreachable!()))
}

/// A transform's value, as Xray's `evaluateExpr` computes it.
pub(crate) fn evaluate_expr(expr: &CustomExpr, context: &Context) -> Result<Value, EvalError> {
    match expr.op.as_str() {
        "concat" => {
            let mut out = Vec::new();
            for arg in &expr.args {
                out.extend(evaluate_arg(arg, context)?.bytes()?);
            }
            Ok(Value::Bytes(out))
        }
        "slice" => {
            let [source, offset, length] = args::<3>(expr, context)?;
            let source = source.bytes()?;
            let (offset, length) = (offset.u64()?, length.u64()?);
            let end = offset.wrapping_add(length);
            if end > source.len() as u64 || end < offset {
                return Err(error("slice out of bounds"));
            }
            Ok(Value::Bytes(source[offset as usize..end as usize].to_vec()))
        }
        "xor16" | "xor32" => {
            let [left, right] = args::<2>(expr, context)?;
            let (left, right) = (left.u64()?, right.u64()?);
            let (mask, op) = if expr.op == "xor16" {
                (0xFFFF, "xor16")
            } else {
                (0xFFFF_FFFF, "xor32")
            };
            if left > mask || right > mask {
                return Err(error(format!("{op} overflow")));
            }
            Ok(Value::U64((left ^ right) & mask))
        }
        "be16" | "be32" | "le16" | "le32" | "le64" => {
            let [value] = args::<1>(expr, context)?;
            let value = value.u64()?;
            let overflow = || error(format!("{} overflow", expr.op));
            Ok(Value::Bytes(match expr.op.as_str() {
                "be16" => u16::try_from(value)
                    .map_err(|_| overflow())?
                    .to_be_bytes()
                    .to_vec(),
                "le16" => u16::try_from(value)
                    .map_err(|_| overflow())?
                    .to_le_bytes()
                    .to_vec(),
                "be32" => u32::try_from(value)
                    .map_err(|_| overflow())?
                    .to_be_bytes()
                    .to_vec(),
                "le32" => u32::try_from(value)
                    .map_err(|_| overflow())?
                    .to_le_bytes()
                    .to_vec(),
                _ => value.to_le_bytes().to_vec(),
            }))
        }
        "pad" => {
            let [source, target, fill] = args::<3>(expr, context)?;
            let source = source.bytes()?;
            let target = target.u64()?;
            let fill = fill.bytes()?;
            if fill.is_empty() {
                return Err(error("pad fill must not be empty"));
            }
            if target < source.len() as u64 {
                return Err(error("pad target shorter than source"));
            }
            // Xray-core allocates whatever the target says.
            if target > MAX_ITEM as u64 {
                return Err(error("pad target too large"));
            }
            let target = target as usize;
            let mut out = source;
            while out.len() < target {
                let remaining = target - out.len();
                out.extend_from_slice(&fill[..remaining.min(fill.len())]);
            }
            Ok(Value::Bytes(out))
        }
        "truncate" => {
            let [source, length] = args::<2>(expr, context)?;
            let source = source.bytes()?;
            let length = length.u64()?;
            if length > source.len() as u64 {
                return Err(error("truncate out of bounds"));
            }
            Ok(Value::Bytes(source[..length as usize].to_vec()))
        }
        "add" | "sub" | "and" | "or" => {
            let [left, right] = args::<2>(expr, context)?;
            let (left, right) = (left.u64()?, right.u64()?);
            Ok(Value::U64(match expr.op.as_str() {
                "add" => left
                    .checked_add(right)
                    .ok_or_else(|| error("add overflow"))?,
                "sub" => left
                    .checked_sub(right)
                    .ok_or_else(|| error("sub underflow"))?,
                "and" => left & right,
                _ => left | right,
            }))
        }
        "shl" | "shr" => {
            let [value, shift] = args::<2>(expr, context)?;
            let (value, shift) = (value.u64()?, shift.u64()?);
            if shift >= 64 {
                return Err(error("shift out of range"));
            }
            if expr.op == "shr" {
                return Ok(Value::U64(value >> shift));
            }
            if value > (u64::MAX >> shift) {
                return Err(error("shl overflow"));
            }
            Ok(Value::U64(value << shift))
        }
        op => Err(error(format!("unsupported expr op: {op}"))),
    }
}

/// Whether `received` holds what `item` expects, capturing it if asked.
pub(crate) fn match_item(
    item: &CustomItem,
    received: &[u8],
    context: &mut Context,
) -> Result<bool, EvalError> {
    let matched = if item.rand > 0 {
        true
    } else if !item.packet.is_empty() {
        item.packet == received
    } else if !item.reuse.is_empty() {
        context
            .vars
            .get(&item.reuse)
            .is_some_and(|saved| saved == received)
    } else if let Some(expr) = &item.transform {
        evaluate_expr(expr, context)?.bytes()? == received
    } else {
        true
    };
    if matched && !item.capture.is_empty() {
        context.vars.insert(item.capture.clone(), received.to_vec());
    }
    Ok(matched)
}

fn auth_failed(reason: impl fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        format!("header auth failed: {reason}"),
    )
}

/// The client's side of the TCP handshake: each client sequence, then the
/// server sequence that answers it, then the server sequences left.
pub async fn client_handshake<S>(
    stream: &mut S,
    config: &HeaderCustomTcpConfig,
    local: Option<SocketAddr>,
    remote: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut context = Context::with_addresses(local, remote);
    let mut servers = config.servers.iter();
    for client in &config.clients {
        write_sequence(stream, client, &mut context).await?;
        if let Some(server) = servers.next() {
            read_sequence(stream, server, &mut context).await?;
        }
    }
    for server in servers {
        read_sequence(stream, server, &mut context).await?;
    }
    Ok(())
}

/// Sends a sequence as Xray's `writeSequenceWithContext` does: items are
/// merged into one write, and an item with a delay first sends what came
/// before it and waits.
async fn write_sequence<S>(
    stream: &mut S,
    sequence: &[CustomItem],
    context: &mut Context,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin + ?Sized,
{
    let mut merged = Vec::new();
    for item in sequence {
        if item.delay.1 > 0 {
            if !merged.is_empty() {
                stream.write_all(&merged).await?;
                stream.flush().await?;
                merged.clear();
            }
            let millis = rand_between(i64::from(item.delay.0), i64::from(item.delay.1));
            if millis > 0 {
                tokio::time::sleep(Duration::from_millis(millis as u64)).await;
            }
        }
        let bytes = evaluate_item(item, context).map_err(auth_failed)?;
        if bytes.len() > MAX_ITEM {
            return Err(auth_failed("an item exceeds 1 MiB"));
        }
        merged.extend(bytes);
    }
    if !merged.is_empty() {
        stream.write_all(&merged).await?;
        stream.flush().await?;
    }
    Ok(())
}

/// Reads and checks a sequence as Xray's `readSequenceWithContext` does.
async fn read_sequence<S>(
    stream: &mut S,
    sequence: &[CustomItem],
    context: &mut Context,
) -> io::Result<()>
where
    S: AsyncRead + Unpin + ?Sized,
{
    for item in sequence {
        let length = measure_item(item, &mut context.sizes()).map_err(auth_failed)?;
        if length > MAX_ITEM {
            return Err(auth_failed("an item exceeds 1 MiB"));
        }
        let mut received = vec![0; length];
        stream.read_exact(&mut received).await?;
        if !match_item(item, &received, context).map_err(auth_failed)? {
            return Err(auth_failed("the server's bytes do not match"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

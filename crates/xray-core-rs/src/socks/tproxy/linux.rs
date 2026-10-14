use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::{io, mem, os::fd::AsRawFd};
use xray_config::TproxySettings;
use xray_routing::Network;

const MAX_TCP_CONNECTIONS: usize = 1024;
// Four full-sized packets cap pending payload memory at 256 KiB per flow.
const UDP_FLOW_QUEUE: usize = 4;

fn socket(addr: SocketAddr, tcp: bool, mark: u32) -> io::Result<Socket> {
    let socket = Socket::new(
        Domain::for_address(addr),
        if tcp { Type::STREAM } else { Type::DGRAM },
        Some(if tcp { Protocol::TCP } else { Protocol::UDP }),
    )?;
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
        option(&socket, libc::IPPROTO_IPV6, libc::IPV6_TRANSPARENT, 1)?;
    } else {
        option(&socket, libc::IPPROTO_IP, libc::IP_TRANSPARENT, 1)?;
    }
    if mark != 0 {
        option(&socket, libc::SOL_SOCKET, libc::SO_MARK, mark)?;
    }
    Ok(socket)
}
fn option(socket: &Socket, level: i32, name: i32, value: u32) -> io::Result<()> {
    // SAFETY: the live socket owns fd; value is a properly sized native integer.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            (&value as *const u32).cast(),
            mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub(crate) fn bind(
    inbound: &xray_config::InboundConfig,
    settings: TproxySettings,
) -> Result<Bound, crate::CoreError> {
    if (!settings.tcp && !settings.udp) || settings.mark > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TPROXY needs at least one network and a nonnegative i32 mark",
        )
        .into());
    }
    let ip = inbound.listen.parse::<IpAddr>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TPROXY needs a literal listen address",
        )
    })?;
    let mut addr = SocketAddr::new(ip, inbound.port);
    let tcp = if settings.tcp {
        let socket = socket(addr, true, settings.mark)?;
        socket.bind(&addr.into())?;
        socket.listen(1024)?;
        addr = socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("invalid TPROXY bind address"))?;
        Some(TcpListener::from_std(socket.into())?)
    } else {
        None
    };
    let udp = if settings.udp {
        let socket = socket(addr, false, settings.mark)?;
        if ip.is_ipv4() {
            option(&socket, libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR, 1)?;
        } else {
            option(&socket, libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR, 1)?;
        }
        socket.bind(&addr.into())?;
        addr = socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("invalid TPROXY bind address"))?;
        Some(UdpSocket::from_std(socket.into())?)
    } else {
        None
    };
    Ok(Bound {
        addr,
        tcp,
        udp,
        mark: settings.mark,
    })
}
fn reply_socket(target: SocketAddr, mark: u32) -> io::Result<Arc<UdpSocket>> {
    let socket = socket(target, false, mark)?;
    option(&socket, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;
    socket.bind(&target.into())?;
    Ok(Arc::new(UdpSocket::from_std(socket.into())?))
}
fn target(addr: SocketAddr, network: Network) -> Target {
    Target::new(TargetAddr::Ip(addr.ip()), addr.port(), network)
}
// Reject a direct connection back into the local listener, while allowing a
// remote original destination that happens to use the interception port.
fn intercepted(destination: SocketAddr, listener: SocketAddr) -> bool {
    if destination.port() == 0
        || destination.ip().is_unspecified()
        || destination.ip().is_multicast()
    {
        return false;
    }
    if destination.port() != listener.port() {
        return true;
    }
    if !listener.ip().is_unspecified() {
        return destination.ip() != listener.ip();
    }
    if destination.ip().is_loopback() {
        return false;
    }
    let mut addresses = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes an owned list; freeifaddrs releases it after
    // traversal. This uncommon same-port case never caches stale interface IPs.
    unsafe {
        if libc::getifaddrs(&mut addresses) != 0 {
            return false;
        }
        let mut current = addresses;
        let mut local = false;
        while !current.is_null() {
            let entry = &*current;
            if !entry.ifa_addr.is_null() {
                let length = match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => mem::size_of::<libc::sockaddr_in>(),
                    libc::AF_INET6 => mem::size_of::<libc::sockaddr_in6>(),
                    _ => 0,
                };
                if length != 0
                    && decode_address(entry.ifa_addr, length)
                        .is_ok_and(|addr| addr.ip() == destination.ip())
                {
                    local = true;
                    break;
                }
            }
            current = entry.ifa_next;
        }
        libc::freeifaddrs(addresses);
        !local
    }
}

pub(crate) async fn serve(bound: Bound, context: Context, mut shutdown: watch::Receiver<bool>) {
    let mut tasks = JoinSet::new();
    if let Some(tcp) = bound.tcp {
        tasks.spawn(serve_tcp(
            tcp,
            bound.addr,
            context.clone(),
            shutdown.clone(),
        ));
    }
    if let Some(udp) = bound.udp {
        tasks.spawn(serve_udp(
            udp,
            bound.addr,
            bound.mark,
            context,
            shutdown.clone(),
        ));
    }
    loop {
        if *shutdown.borrow() || tasks.is_empty() {
            break;
        }
        tokio::select! { _=shutdown.changed()=>break, _=tasks.join_next()=>{} }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}
async fn serve_tcp(
    listener: TcpListener,
    addr: SocketAddr,
    context: Context,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _=shutdown.changed()=>break,
            _=connections.join_next(),if !connections.is_empty()=>{},
            accepted=listener.accept()=>{
                let (stream,_)=match accepted {
                    Ok(v)=>v,
                    Err(error)=>{
                        if accept_error_wants_backoff(error.kind()) {
                            let delay=backoff.next_delay();
                            tokio::select! { _=shutdown.changed()=>break,_=tokio::time::sleep(delay)=>{} }
                        }
                        continue;
                    }
                };
                backoff.reset();
                let Ok(destination)=stream.local_addr() else {continue;};
                if connections.len()>=MAX_TCP_CONNECTIONS || !intercepted(destination,addr) {continue;}
                if stream.set_nodelay(true).is_err() { continue; }
                let ctx=context.clone();
                connections.spawn(async move {
                    handle_socks_connect::<false>(stream,target(destination,Network::Tcp),ctx.inbound_tag,ctx.config,
                        ctx.router,ctx.dns,ctx.dialer,ctx.sniffing,ctx.policy,ctx.logger,ctx.registry).await;
                });
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}
async fn serve_udp(
    socket: UdpSocket,
    addr: SocketAddr,
    mark: u32,
    context: Context,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buffer = vec![0; 65_536];
    let mut flows = HashMap::new();
    let mut tasks = JoinSet::new();
    let budgets = SocksUdpBudgets::default();
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _=shutdown.changed()=>break,
            joined=tasks.join_next_with_id(),if !tasks.is_empty()=>{
                if let Some(result)=joined {
                    match result {Ok((id,key))=>remove_socks_udp_flow_by_task_id(&mut flows,id,Some(&key)),Err(error)=>remove_socks_udp_flow_by_task_id(&mut flows,error.id(),None)}
                }
            }
            packet=receive(&socket,&mut buffer)=>{
                let (len,client,destination)=match packet {Ok(v)=>v,Err(_)=>continue};
                if !intercepted(destination,addr) {continue;}
                let target=target(destination,Network::Udp);let key=(client,target.clone());
                if let Some(flow)=flows.get_mut(&key) {
                    match flow.sender.try_send(Bytes::copy_from_slice(&buffer[..len])) {
                        Ok(())=>{flow.last_activity=monotonic_millis();continue;},
                        Err(mpsc::error::TrySendError::Full(_))=>continue,
                        Err(mpsc::error::TrySendError::Closed(_))=>{}
                    }
                    if let Some(flow) = flows.remove(&key) { flow.abort_handle.abort(); }
                }
                // Include aborted tasks until they are joined: eviction releases
                // flow permits before the task's buffers have been reclaimed.
                if tasks.len() >= SOCKS_UDP_MAX_FLOWS_GLOBAL { continue; }
                let Some(permits)=admit_socks_udp_flow(&mut flows,&budgets,&context.logger) else {continue;};
                let Ok(reply)=reply_socket(destination,mark) else {continue;};
                let (sender,receiver)=mpsc::channel(UDP_FLOW_QUEUE);
                if sender.try_send(Bytes::copy_from_slice(&buffer[..len])).is_err(){continue;}
                let ctx=SocksUdpFlowContext {reply:UdpReply::Transparent(reply),client_addr:client,
                    inbound_tag:context.inbound_tag.clone(),outbound_router:context.router.clone(),
                    dns_resolvers:context.dns.clone(),transport_dialer:context.dialer.clone(),sniffing:context.sniffing.clone(),
                    runtime_logger:context.logger.clone(),connection_registry:context.registry.clone()};
                let close=shutdown.clone();let completed_key=key.clone();
                let abort_handle=tasks.spawn(async move {
                    bridge_socks_udp_flow(target,ctx,receiver,close,permits.pending_open).await;
                    completed_key
                });
                flows.insert(key,SocksUdpFlowEntry{sender,task_id:abort_handle.id(),abort_handle,last_activity:monotonic_millis(),global_permit:permits.global});
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn receive(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    loop {
        socket.readable().await?;
        match socket.try_io(tokio::io::Interest::READABLE, || {
            recv_original(socket, buffer)
        }) {
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::Interrupted =>
            {
                continue
            }
            result => return result,
        }
    }
}
fn recv_original(
    socket: &UdpSocket,
    buffer: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    // Native-word alignment is sufficient for cmsghdr and both sockaddr forms.
    let mut control = [0usize; 32];
    let mut source: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr().cast(),
        iov_len: buffer.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = (&mut source as *mut libc::sockaddr_storage).cast();
    msg.msg_namelen = mem::size_of_val(&source) as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = mem::size_of_val(&control);
    // SAFETY: every output pointer refers to the live writable allocation above.
    let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, libc::MSG_DONTWAIT) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated transparent datagram",
        ));
    }
    let source = decode_address(
        (&source as *const libc::sockaddr_storage).cast(),
        msg.msg_namelen as usize,
    )?;
    let mut destination = None;
    // SAFETY: recvmsg returned a bounded, aligned control buffer. Check each
    // payload length before interpreting a sockaddr; never use msg_name as dst.
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let header = &*cmsg;
            let size = libc::CMSG_LEN(0) as usize;
            if header.cmsg_len < size {
                break;
            }
            if (header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_ORIGDSTADDR)
                || (header.cmsg_level == libc::IPPROTO_IPV6
                    && header.cmsg_type == libc::IPV6_ORIGDSTADDR)
            {
                destination = Some(decode_address(
                    libc::CMSG_DATA(cmsg).cast(),
                    header.cmsg_len - size,
                )?);
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }
    let destination = destination.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "missing UDP original destination",
        )
    })?;
    Ok((len as usize, source, destination))
}
fn decode_address(address: *const libc::sockaddr, len: usize) -> io::Result<SocketAddr> {
    if len < mem::size_of::<libc::sa_family_t>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short socket address",
        ));
    }
    // SAFETY: callers provide len readable bytes from kernel sockaddr buffers;
    // unaligned loads avoid assuming alignment of an ancillary payload.
    unsafe {
        match (*address).sa_family as i32 {
            libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
                let addr = address.cast::<libc::sockaddr_in>().read_unaligned();
                Ok(SocketAddr::new(
                    Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes()).into(),
                    u16::from_be(addr.sin_port),
                ))
            }
            libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
                let addr = address.cast::<libc::sockaddr_in6>().read_unaligned();
                Ok(std::net::SocketAddrV6::new(
                    Ipv6Addr::from(addr.sin6_addr.s6_addr),
                    u16::from_be(addr.sin6_port),
                    u32::from_be(addr.sin6_flowinfo),
                    addr.sin6_scope_id,
                )
                .into())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported socket address",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn original_destination_ancillary_data_and_truncation() {
        for bind in ["127.0.0.1:0", "[::1]:0"] {
            let address: SocketAddr = bind.parse().unwrap();
            let raw = Socket::new(
                Domain::for_address(address),
                Type::DGRAM,
                Some(Protocol::UDP),
            )
            .unwrap();
            raw.set_nonblocking(true).unwrap();
            if address.is_ipv4() {
                option(&raw, libc::IPPROTO_IP, libc::IP_RECVORIGDSTADDR, 1).unwrap();
            } else {
                option(&raw, libc::IPPROTO_IPV6, libc::IPV6_RECVORIGDSTADDR, 1).unwrap();
            }
            raw.bind(&address.into()).unwrap();
            let receiver = UdpSocket::from_std(raw.into()).unwrap();
            let target = receiver.local_addr().unwrap();
            let sender = UdpSocket::bind(address).await.unwrap();
            sender.send_to(b"original", target).await.unwrap();
            let mut buffer = [0; 16];
            let (n, source, original) = receive(&receiver, &mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], b"original");
            assert_eq!(source, sender.local_addr().unwrap());
            assert_eq!(original, target);
            sender.send_to(&[7; 32], target).await.unwrap();
            assert_eq!(
                receive(&receiver, &mut buffer).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            let no_metadata = UdpSocket::bind(address).await.unwrap();
            sender
                .send_to(b"missing", no_metadata.local_addr().unwrap())
                .await
                .unwrap();
            assert_eq!(
                receive(&no_metadata, &mut buffer).await.unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
    #[test]
    fn direct_listener_loops_are_rejected_without_rejecting_remote_same_port() {
        assert!(!intercepted(
            "127.0.0.1:12345".parse().unwrap(),
            "0.0.0.0:12345".parse().unwrap()
        ));
        assert!(intercepted(
            "192.0.2.1:12345".parse().unwrap(),
            "0.0.0.0:12345".parse().unwrap()
        ));
        assert!(intercepted(
            "[2001:db8::1]:12345".parse().unwrap(),
            "[::]:12345".parse().unwrap()
        ));
    }
}

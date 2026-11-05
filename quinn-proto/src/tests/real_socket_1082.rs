use super::*;
use std::{
    io::{self, IoSliceMut},
    net::UdpSocket,
    os::fd::AsFd,
    thread,
    time::Duration as StdDuration,
};

use quinn_udp::{RecvMeta, UdpSocketState};

struct RealSockets {
    pair: Pair,
    client: UdpSocket,
    server: UdpSocket,
    server_state: UdpSocketState,
    server_a: SocketAddr,
    server_b: SocketAddr,
}

impl RealSockets {
    fn new(ipv6: bool) -> Self {
        // The optional socket is created in a separate network namespace by
        // the test launcher, then inherited as stdin. Cloning the descriptor is
        // safe and keeps the socket attached to the client's namespace.
        let inherited = std::env::var_os("QUINN_TEST_INHERITED_UDP").is_some();
        let (listen, ip_a, ip_b, client_ip) = if ipv6 {
            ("[::]:0", "fd00:1082::1", "fd00:1082::2", "fd00:1082::3")
        } else if inherited {
            ("0.0.0.0:0", "10.108.2.1", "10.108.2.2", "10.108.2.3")
        } else {
            ("0.0.0.0:0", "127.0.0.1", "127.0.0.2", "127.0.0.3")
        };
        let server = UdpSocket::bind(listen).unwrap();
        let server_port = server.local_addr().unwrap().port();
        let server_state = UdpSocketState::new((&server).into()).unwrap();
        let server_a = SocketAddr::new(ip_a.parse().unwrap(), server_port);
        let server_b = SocketAddr::new(ip_b.parse().unwrap(), server_port);
        let client = if inherited {
            let fd = std::io::stdin().as_fd().try_clone_to_owned().unwrap();
            UdpSocket::from(fd)
        } else {
            UdpSocket::bind(SocketAddr::new(client_ip.parse().unwrap(), 0)).unwrap()
        };
        assert_eq!(client.local_addr().unwrap().ip(), client_ip.parse::<IpAddr>().unwrap());
        client.set_nonblocking(true).unwrap();
        let mut pair = Pair::default();
        pair.server.addr = server_a;
        pair.server.local_ip = Some(server_a.ip());
        pair.client.addr = client.local_addr().unwrap();
        pair.client.local_ip = Some(pair.client.addr.ip());
        Self {
            pair,
            client,
            server,
            server_state,
            server_a,
            server_b,
        }
    }

    fn recv_server(&self, buf: &mut [u8]) -> io::Result<RecvMeta> {
        let mut bufs = [IoSliceMut::new(buf)];
        let mut meta = [RecvMeta::default()];
        assert_eq!(
            self.server_state
                .recv((&self.server).into(), &mut bufs, &mut meta)?,
            1
        );
        assert!(meta[0].stride > 0);
        Ok(meta[0])
    }

    fn send_server(&self, tx: &Transmit, payload: &[u8]) {
        assert_eq!(tx.segment_size, None);
        let datagram = quinn_udp::Transmit {
            destination: tx.destination,
            ecn: None,
            contents: payload,
            segment_size: None,
            src_ip: tx.src_ip,
        };
        self.server_state
            .try_send((&self.server).into(), &datagram)
            .unwrap();
    }

    fn pump(&mut self) {
        let now = Instant::now();
        self.pair.time = now;
        let a = self.server_a;
        let remote = self.client.local_addr().unwrap();
        self.pair.client.drive(now, a);
        for (tx, payload) in self.pair.client.outbound.drain(..) {
            assert_eq!(tx.destination, a);
            assert_eq!(self.client.send_to(&payload, a).unwrap(), payload.len());
        }
        let mut buf = [0u8; 65536];
        loop {
            match self.recv_server(&mut buf) {
                Ok(meta) => {
                    assert_eq!(meta.addr, remote);
                    assert_eq!(meta.dst_ip, Some(a.ip()));
                    self.pair.server.local_ip = meta.dst_ip;
                    for packet in buf[..meta.len].chunks(meta.stride) {
                        self.pair
                            .server
                            .inbound
                            .push_back((now, None, BytesMut::from(packet)));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        self.pair.server.drive(now, remote);
        let outgoing: Vec<_> = self.pair.server.outbound.drain(..).collect();
        for (tx, payload) in outgoing {
            assert_eq!(tx.destination, remote);
            assert_eq!(tx.src_ip, Some(a.ip()));
            self.send_server(&tx, &payload);
        }
        loop {
            match self.client.recv_from(&mut buf) {
                Ok((n, from)) => {
                    assert_eq!(from, a);
                    self.pair
                        .client
                        .inbound
                        .push_back((now, None, BytesMut::from(&buf[..n])));
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("client recv: {e}"),
            }
        }
    }

    /// Route the client's fixed logical peer through a selectable physical
    /// destination. The server still sees the same client IP:port on the wire.
    fn pump_migration(
        &mut self,
        destination: SocketAddr,
        drop_client: bool,
        accept_source: Option<IpAddr>,
        observed_sources: &mut Vec<IpAddr>,
    ) {
        let now = Instant::now();
        self.pair.time = now;
        let a = self.server_a;
        let remote = self.client.local_addr().unwrap();
        self.pair.client.drive(now, a);
        for (tx, payload) in self.pair.client.outbound.drain(..) {
            assert_eq!(tx.destination, a);
            if !drop_client {
                assert_eq!(self.client.send_to(&payload, destination).unwrap(), payload.len());
            }
        }
        let mut buf = [0u8; 65536];
        loop {
            match self.recv_server(&mut buf) {
                Ok(meta) => {
                    assert_eq!(meta.addr, remote);
                    assert!(meta.dst_ip == Some(self.server_a.ip()) || meta.dst_ip == Some(self.server_b.ip()));
                    for packet in buf[..meta.len].chunks(meta.stride) {
                        let mut scratch = Vec::new();
                        let Some(DatagramEvent::ConnectionEvent(ch, event)) = self.pair.server.endpoint.handle(
                            now, meta.addr, meta.dst_ip, None, BytesMut::from(packet), &mut scratch,
                        ) else {
                            panic!("expected an established server connection");
                        };
                        self.pair.server_conn_mut(ch).handle_event(event);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        self.pair.server.drive(now, remote);
        let outgoing: Vec<_> = self.pair.server.outbound.drain(..).collect();
        for (tx, payload) in outgoing {
            assert_eq!(tx.destination, remote);
            assert!(tx.src_ip == Some(self.server_a.ip()) || tx.src_ip == Some(self.server_b.ip()));
            self.send_server(&tx, &payload);
        }
        loop {
            match self.client.recv_from(&mut buf) {
                Ok((n, from)) => {
                    assert!(from == self.server_a || from == self.server_b);
                    observed_sources.push(from.ip());
                    if accept_source.is_none_or(|expected| expected == from.ip()) {
                        self.pair.client.inbound.push_back((now, None, BytesMut::from(&buf[..n])));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("client recv: {e}"),
            }
        }
    }

    fn handshake(&mut self) -> (ConnectionHandle, ConnectionHandle) {
        let client = self.pair.begin_connect(client_config());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.pump();
            if let Some((&server, conn)) = self.pair.server.connections.iter().next() {
                if !conn.is_handshaking() && !self.pair.client_conn_mut(client).is_handshaking() {
                    assert_eq!(self.pair.server.assert_accept(), server);
                    break;
                }
            }
            assert!(Instant::now() < deadline, "real UDP handshake timed out");
            thread::sleep(StdDuration::from_millis(1));
        }
        let server = *self.pair.server.connections.keys().next().unwrap();
        for _ in 0..30 {
            self.pump();
            thread::sleep(StdDuration::from_millis(1));
        }
        assert!(!self.pair.client_conn_mut(client).is_closed());
        assert!(!self.pair.server_conn_mut(server).is_closed());
        (client, server)
    }

    fn receive_stream_bytes(
        &mut self,
        server: ConnectionHandle,
        stream: StreamId,
        expected: &[u8],
        offset: u64,
        accept: bool,
    ) {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut accepted = !accept;
        loop {
            self.pump();
            if !accepted {
                if let Some(id) = self.pair.server_streams(server).accept(Dir::Bi) {
                    assert_eq!(id, stream);
                    accepted = true;
                }
            }
            if accepted {
                let mut recv = self.pair.server_recv(server, stream);
                let mut chunks = recv.read(true).unwrap();
                let result = chunks.next(usize::MAX);
                let _ = chunks.finalize();
                match result {
                    Ok(Some(chunk)) => {
                        assert_eq!(chunk.offset, offset);
                        assert_eq!(chunk.bytes.as_ref(), expected);
                        return;
                    }
                    Err(ReadError::Blocked) => {}
                    other => panic!("unexpected stream read: {other:?}"),
                }
            }
            assert!(Instant::now() < deadline, "real UDP stream timed out");
            thread::sleep(StdDuration::from_millis(1));
        }
    }

    fn receive_client_bytes(
        &mut self,
        client: ConnectionHandle,
        stream: StreamId,
        expected: &[u8],
        offset: u64,
    ) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            self.pump();
            let mut recv = self.pair.client_recv(client, stream);
            let mut chunks = recv.read(true).unwrap();
            let result = chunks.next(usize::MAX);
            let _ = chunks.finalize();
            match result {
                Ok(Some(chunk)) => {
                    assert_eq!(chunk.offset, offset);
                    assert_eq!(chunk.bytes.as_ref(), expected);
                    return;
                }
                Err(ReadError::Blocked) => {}
                other => panic!("unexpected client stream read: {other:?}"),
            }
            assert!(Instant::now() < deadline, "real UDP reply stream timed out");
            thread::sleep(StdDuration::from_millis(1));
        }
    }
}

fn real_socket_path_response(use_b: bool, ipv6: bool) {
    let _guard = subscribe();
    let mut rig = RealSockets::new(ipv6);
    let (client, server) = rig.handshake();
    let a = rig.server_a;
    let b = rig.server_b;
    let client_addr = rig.client.local_addr().unwrap();
    let dest = if use_b { b } else { a };
    let stream = rig.pair.client_streams(client).open(Dir::Bi).unwrap();
    assert_eq!(
        rig.pair.client_send(client, stream).write(b"before").unwrap(),
        6
    );
    rig.receive_stream_bytes(server, stream, b"before", 0, true);
    assert_eq!(rig.pair.server_send(server, stream).write(b"ack").unwrap(), 3);
    rig.receive_client_bytes(client, stream, b"ack", 0);
    assert_eq!(rig.pair.server_conn_mut(server).remote_address(), client_addr);
    assert_eq!(rig.pair.server_conn_mut(server).local_ip(), Some(a.ip()));
    let tx_challenge_before = rig.pair.client_conn_mut(client).stats().frame_tx.path_challenge;
    let rx_challenge_before = rig.pair.server_conn_mut(server).stats().frame_rx.path_challenge;
    let tx_response_before = rig.pair.server_conn_mut(server).stats().frame_tx.path_response;
    let rx_response_before = rig.pair.client_conn_mut(client).stats().frame_rx.path_response;
    rig.pair.client_conn_mut(client).repro_queue_path_challenge();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 65536];
    let mut received_count = 0;
    loop {
        let now = Instant::now();
        rig.pair.client.drive(now, a);
        for (tx, payload) in rig.pair.client.outbound.drain(..) {
            assert_eq!(tx.destination, a);
            assert_eq!(rig.client.send_to(&payload, dest).unwrap(), payload.len());
        }
        loop {
            match rig.recv_server(&mut buf) {
                Ok(meta) => {
                    assert_eq!(meta.addr, client_addr);
                    assert_eq!(meta.dst_ip, Some(dest.ip()));
                    for packet in buf[..meta.len].chunks(meta.stride) {
                        received_count += 1;
                        let mut send_buf = Vec::new();
                        let event = rig
                            .pair
                            .server
                            .endpoint
                            .handle(
                                now,
                                meta.addr,
                                meta.dst_ip,
                                None,
                                BytesMut::from(packet),
                                &mut send_buf,
                            )
                            .expect("established real UDP datagram");
                        let DatagramEvent::ConnectionEvent(ch, event) = event else {
                            panic!("expected established connection event");
                        };
                        assert_eq!(ch, server);
                        rig.pair.server_conn_mut(ch).handle_event(event);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("challenge recv: {e}"),
            }
        }
        if rig.pair.server_conn_mut(server).stats().frame_rx.path_challenge > rx_challenge_before {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "authenticated PATH_CHALLENGE not received"
        );
        thread::sleep(StdDuration::from_millis(1));
    }
    assert_eq!(
        rig.pair.client_conn_mut(client).stats().frame_tx.path_challenge,
        tx_challenge_before + 1
    );
    assert_eq!(
        rig.pair.server_conn_mut(server).stats().frame_rx.path_challenge,
        rx_challenge_before + 1
    );
    assert_eq!(rig.pair.server_conn_mut(server).remote_address(), client_addr);

    let deadline = Instant::now() + Duration::from_secs(3);
    let (response_tx, response_payload) = loop {
        let now = Instant::now();
        let mut payload = Vec::new();
        let result = rig.pair.server_conn_mut(server).poll_transmit(now, 1, &mut payload);
        if let Some(tx) = result {
            if rig.pair.server_conn_mut(server).stats().frame_tx.path_response > tx_response_before {
                break (tx, payload);
            }
            rig.send_server(&tx, &payload);
        } else {
            assert!(Instant::now() < deadline, "PATH_RESPONSE not emitted");
            thread::sleep(StdDuration::from_millis(1));
        }
    };
    assert_eq!(
        rig.pair.server_conn_mut(server).stats().frame_tx.path_response,
        tx_response_before + 1
    );
    assert_eq!(response_tx.destination, client_addr);
    let intended_src = response_tx.src_ip.expect("response source");
    rig.send_server(&response_tx, &response_payload);
    let deadline = Instant::now() + Duration::from_secs(3);
    let observed_src = loop {
        match rig.client.recv_from(&mut buf) {
            Ok((n, from)) => {
                let mut output = Vec::new();
                let now = Instant::now();
                // The harness changes the physical destination behind the client. Present the
                // original peer to Quinn as a NAT would, while retaining `from` for the actual
                // source-address assertion below.
                if let Some(DatagramEvent::ConnectionEvent(ch, event)) = rig.pair.client.endpoint.handle(
                    now,
                    a,
                    Some(client_addr.ip()),
                    None,
                    BytesMut::from(&buf[..n]),
                    &mut output,
                ) {
                    assert_eq!(ch, client);
                    rig.pair.client_conn_mut(ch).handle_event(event);
                    if rig.pair.client_conn_mut(client).stats().frame_rx.path_response > rx_response_before {
                        break from;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "client did not receive authentic PATH_RESPONSE"
                );
                thread::sleep(StdDuration::from_millis(1));
            }
            Err(e) => panic!("response recv: {e}"),
        }
    };
    assert_eq!(
        rig.pair.client_conn_mut(client).stats().frame_rx.path_response,
        rx_response_before + 1
    );
    assert!(!rig.pair.client_conn_mut(client).is_closed());
    assert!(!rig.pair.server_conn_mut(server).is_closed());
    assert_eq!(
        observed_src.ip(),
        intended_src,
        "kernel observed source must match Quinn's selection"
    );
    assert_eq!(
        observed_src.ip(),
        dest.ip(),
        "PATH_RESPONSE must use the real receiving destination IP"
    );
    assert_eq!(rig.pair.client_send(client, stream).write(b"after").unwrap(), 5);
    rig.receive_stream_bytes(server, stream, b"after", 6, false);
    assert_eq!(rig.pair.server_send(server, stream).write(b"done").unwrap(), 4);
    rig.receive_client_bytes(client, stream, b"done", 3);
    println!(
        "REAL_SOCKET_1082 handshake=ok client={} server_a={} server_b={} destination={} received_datagrams={} challenge_rx_delta=1 response_tx_delta=1 response_rx_delta=1 quinn_src={} actual_src={} connected=true stream_client=6+5 stream_server=3+4",
        client_addr, a, b, dest, received_count, intended_src, observed_src
    );
}

fn real_socket_local_migration(ipv6: bool, fail_validation: bool, fail_mtu_validation: bool) {
    let _guard = subscribe();
    let mut rig = RealSockets::new(ipv6);
    let (client, server) = rig.handshake();
    let a = rig.server_a;
    let b = rig.server_b;
    let remote = rig.client.local_addr().unwrap();
    let stream = rig.pair.client_streams(client).open(Dir::Bi).unwrap();
    assert_eq!(rig.pair.client_send(client, stream).write(b"before").unwrap(), 6);
    rig.receive_stream_bytes(server, stream, b"before", 0, true);
    assert_eq!(rig.pair.server_send(server, stream).write(b"ack").unwrap(), 3);
    rig.receive_client_bytes(client, stream, b"ack", 0);
    assert_eq!(rig.pair.client_send(client, stream).write(b"move").unwrap(), 4);

    let mut observed = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    while rig.pair.server_conn_mut(server).test_local_path_candidate().is_none() {
        rig.pump_migration(b, false, None, &mut observed);
        assert!(Instant::now() < deadline, "new local path was not probed");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert_eq!(rig.pair.server_conn_mut(server).remote_address(), remote);
    assert_eq!(rig.pair.server_conn_mut(server).local_ip(), Some(a.ip()));

    if fail_mtu_validation {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !rig.pair.server_conn_mut(server).test_local_path_candidate().is_some_and(|candidate| candidate.0) {
            rig.pump_migration(b, false, None, &mut observed);
            assert!(Instant::now() < deadline, "short challenge was not validated");
            thread::sleep(StdDuration::from_millis(1));
        }
    }
    if fail_validation || fail_mtu_validation {
        let deadline = Instant::now() + Duration::from_secs(10);
        while rig.pair.server_conn_mut(server).test_local_path_candidate().is_some() {
            // No client datagram reaches the candidate path, including responses
            // to the server's PATH_CHALLENGE.
            rig.pump_migration(b, true, None, &mut observed);
            assert!(Instant::now() < deadline, "failed path did not fall back");
            thread::sleep(StdDuration::from_millis(1));
        }
        assert_eq!(rig.pair.server_conn_mut(server).local_ip(), Some(a.ip()));
    } else {
        let deadline = Instant::now() + Duration::from_secs(10);
        while rig.pair.server_conn_mut(server).local_ip() != Some(b.ip()) {
            rig.pump_migration(b, false, None, &mut observed);
            assert!(Instant::now() < deadline, "new local path did not validate");
            thread::sleep(StdDuration::from_millis(1));
        }
        assert_eq!(rig.pair.server_conn_mut(server).test_path_validation_state(), (true, false));
        assert_eq!(rig.pair.server_conn_mut(server).local_ip(), Some(b.ip()));
    }
    assert_eq!(rig.pair.client.local_ip, Some(remote.ip()));
    assert_eq!(rig.pair.server_conn_mut(server).remote_address(), remote);
    assert!(!rig.pair.server_conn_mut(server).is_closed());

    // Consume the bytes that triggered migration, then prove the same stream
    // still works after validation or fallback. Only packets from the selected
    // server source are delivered to the client for the latter assertion.
    {
        let mut recv = rig.pair.server_recv(server, stream);
        let mut chunks = recv.read(true).unwrap();
        let chunk = chunks.next(usize::MAX).unwrap().unwrap();
        assert_eq!(chunk.offset, 6);
        assert_eq!(chunk.bytes.as_ref(), b"move");
        let _ = chunks.finalize();
    }
    let selected = if fail_validation || fail_mtu_validation { a } else { b };
    let before_reply = observed.len();
    assert_eq!(rig.pair.server_send(server, stream).write(b"after").unwrap(), 5);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        rig.pump_migration(selected, false, Some(selected.ip()), &mut observed);
        let mut recv = rig.pair.client_recv(client, stream);
        let mut chunks = recv.read(true).unwrap();
        let result = chunks.next(usize::MAX);
        let _ = chunks.finalize();
        match result {
            Ok(Some(chunk)) => {
                assert_eq!(chunk.offset, 3);
                assert_eq!(chunk.bytes.as_ref(), b"after");
                break;
            }
            Err(ReadError::Blocked) => {}
            other => panic!("unexpected client stream read: {other:?}"),
        }
        assert!(Instant::now() < deadline, "post-migration reply timed out");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert!(observed[before_reply..].contains(&selected.ip()));
    println!(
        "REAL_SOCKET_LOCAL_MIGRATION mode={} client={} old={} candidate={} final={} actual_reply_source={} stream=before+move+after connected=true",
        if fail_validation { "fallback" } else if fail_mtu_validation { "mtu_fallback" } else { "validated" },
        remote, a, b, selected, selected.ip()
    );
}

fn real_socket_cid_exhaustion_recovery(ipv6: bool) {
    let _guard = subscribe();
    let mut rig = RealSockets::new(ipv6);
    let (client, server) = rig.handshake();
    let a = rig.server_a;
    let b = rig.server_b;
    let remote = rig.client.local_addr().unwrap();
    let stream = rig.pair.client_streams(client).open(Dir::Bi).unwrap();
    assert_eq!(rig.pair.client_send(client, stream).write(b"before").unwrap(), 6);
    rig.receive_stream_bytes(server, stream, b"before", 0, true);
    assert_eq!(rig.pair.server_send(server, stream).write(b"ack").unwrap(), 3);
    rig.receive_client_bytes(client, stream, b"ack", 0);

    let last = rig.pair.server_conn_mut(server).test_keep_one_spare_cid();
    rig.pair.client_conn_mut(client).ping();
    let mut observed = Vec::new();
    let discard: IpAddr = if ipv6 { "2001:db8::1" } else { "192.0.2.1" }.parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while rig.pair.server_conn_mut(server).test_local_path_candidate().is_none_or(|x| x.4 == 0) {
        // Receive the candidate probes on actual sockets but withhold them
        // from the client so no response or CID retirement is processed yet.
        rig.pump_migration(b, false, Some(discard), &mut observed);
        assert!(Instant::now() < deadline, "candidate CID was not used");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert!(observed.contains(&b.ip()));
    assert_eq!(rig.pair.server_conn_mut(server).test_local_candidate_cid(), Some(last.id));

    rig.pair.client_conn_mut(client).test_reissue_cid_with_retirement(last);
    rig.pair.client_conn_mut(client).ping();
    let retired_before = rig.pair.server_conn_mut(server).stats().frame_tx.retire_connection_id;
    let deadline = Instant::now() + Duration::from_secs(8);
    while rig.pair.server_conn_mut(server).test_remote_cids().0 != last.id {
        rig.pump_migration(a, false, Some(a.ip()), &mut observed);
        assert!(Instant::now() < deadline, "peer retirement was not processed");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert_eq!(rig.pair.server_conn_mut(server).local_ip(), Some(a.ip()));
    assert_eq!(rig.pair.server_conn_mut(server).remote_address(), remote);
    assert!(rig.pair.server_conn_mut(server).test_remote_cids().1.is_none());
    assert!(rig.pair.server_conn_mut(server).test_active_cid_used_on_another_path());
    assert!(rig.pair.server_conn_mut(server).stats().frame_tx.retire_connection_id > retired_before,
        "the peer must receive a retirement to replenish its CID pool");

    let before_reply = observed.len();
    assert_eq!(rig.pair.server_send(server, stream).write(b"after").unwrap(), 5);
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        rig.pump_migration(a, false, Some(a.ip()), &mut observed);
        let mut recv = rig.pair.client_recv(client, stream);
        let mut chunks = recv.read(true).unwrap();
        let result = chunks.next(usize::MAX);
        let _ = chunks.finalize();
        match result {
            Ok(Some(chunk)) => {
                assert_eq!(chunk.offset, 3);
                assert_eq!(chunk.bytes.as_ref(), b"after");
                break;
            }
            Err(ReadError::Blocked) => {}
            other => panic!("unexpected client stream read: {other:?}"),
        }
        assert!(Instant::now() < deadline, "CID exhaustion stalled the stream");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert!(observed[before_reply..].contains(&a.ip()));
    let deadline = Instant::now() + Duration::from_secs(8);
    while rig.pair.server_conn_mut(server).test_remote_cids().0 == last.id {
        rig.pump_migration(a, false, Some(a.ip()), &mut observed);
        assert!(Instant::now() < deadline, "replacement CID did not restore isolation");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert_eq!(rig.pair.client_send(client, stream).write(b"resume").unwrap(), 6);
    rig.receive_stream_bytes(server, stream, b"resume", 6, false);
    assert!(!rig.pair.client_conn_mut(client).is_closed());
    assert!(!rig.pair.server_conn_mut(server).is_closed());
    println!(
        "REAL_SOCKET_CID_RECOVERY client={} old={} candidate={} fallback_source={} retired=true replacement=true stream=before+after+resume connected=true",
        remote, a, b, a.ip()
    );
}

#[test]
fn real_socket_1082_cid_exhaustion_nat_rebinding() {
    let _guard = subscribe();
    let mut rig = RealSockets::new(false);
    let (client, server) = rig.handshake();
    let a = rig.server_a;
    let b = rig.server_b;
    let old_remote = rig.client.local_addr().unwrap();
    let stream = rig.pair.client_streams(client).open(Dir::Bi).unwrap();
    assert_eq!(rig.pair.client_send(client, stream).write(b"before").unwrap(), 6);
    rig.receive_stream_bytes(server, stream, b"before", 0, true);
    assert_eq!(rig.pair.server_send(server, stream).write(b"ack").unwrap(), 3);
    rig.receive_client_bytes(client, stream, b"ack", 0);

    let last = rig.pair.server_conn_mut(server).test_keep_one_spare_cid();
    let old_cid = rig.pair.server_conn_mut(server).test_remote_cids().0;
    rig.pair.client_conn_mut(client).ping();
    let mut observed = Vec::new();
    let discard: IpAddr = "192.0.2.1".parse().unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    while rig.pair.server_conn_mut(server).test_local_path_candidate().is_none_or(|x| x.4 == 0) {
        rig.pump_migration(b, false, Some(discard), &mut observed);
        assert!(Instant::now() < deadline, "candidate CID was not used");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert!(observed.contains(&b.ip()));
    assert_eq!(rig.pair.server_conn_mut(server).test_local_candidate_cid(), Some(last.id));

    let replacement = UdpSocket::bind(SocketAddr::new(old_remote.ip(), 0)).unwrap();
    replacement.set_nonblocking(true).unwrap();
    let new_remote = replacement.local_addr().unwrap();
    assert_ne!(new_remote.port(), old_remote.port());
    let _old_socket = std::mem::replace(&mut rig.client, replacement);
    rig.pair.client.addr = new_remote;
    rig.pair.client_conn_mut(client).ping();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut buf = [0u8; 65536];
    while rig.pair.server_conn_mut(server).remote_address() != new_remote {
        let now = Instant::now();
        rig.pair.time = now;
        rig.pair.client.drive(now, a);
        for (_, payload) in rig.pair.client.outbound.drain(..) {
            assert_eq!(rig.client.send_to(&payload, a).unwrap(), payload.len());
        }
        loop {
            match rig.recv_server(&mut buf) {
                Ok(meta) => {
                    assert_eq!(meta.addr, new_remote);
                    assert_eq!(meta.dst_ip, Some(a.ip()));
                    for packet in buf[..meta.len].chunks(meta.stride) {
                        let mut scratch = Vec::new();
                        let Some(DatagramEvent::ConnectionEvent(ch, event)) = rig.pair.server.endpoint.handle(
                            now, meta.addr, meta.dst_ip, None, BytesMut::from(packet), &mut scratch,
                        ) else {
                            panic!("rebound packet must route to the connection");
                        };
                        rig.pair.server_conn_mut(ch).handle_event(event);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("server recv: {e}"),
            }
        }
        assert!(Instant::now() < deadline, "rebound source port was not detected");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert_eq!(rig.pair.server_conn_mut(server).local_ip(), Some(a.ip()));
    assert_eq!(rig.pair.server_conn_mut(server).test_remote_cids().0, old_cid);
    rig.pair.server_conn_mut(server).ping();
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut active_sent = false;
    while !active_sent {
        let now = Instant::now();
        rig.pair.time = now;
        rig.pair.server.drive(now, new_remote);
        let packets: Vec<_> = rig.pair.server.outbound.drain(..).collect();
        for (tx, payload) in packets {
            assert!(tx.destination == old_remote || tx.destination == new_remote);
            assert_eq!(tx.src_ip, Some(a.ip()));
            rig.send_server(&tx, &payload);
            active_sent |= tx.destination == new_remote;
        }
        assert!(Instant::now() < deadline, "rebound path stalled after CID exhaustion");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert_eq!(rig.pair.server_send(server, stream).write(b"after").unwrap(), 5);
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        rig.pump_migration(a, false, Some(a.ip()), &mut observed);
        let mut recv = rig.pair.client_recv(client, stream);
        let mut chunks = recv.read(true).unwrap();
        let result = chunks.next(usize::MAX);
        let _ = chunks.finalize();
        match result {
            Ok(Some(chunk)) => {
                assert_eq!(chunk.offset, 3);
                assert_eq!(chunk.bytes.as_ref(), b"after");
                break;
            }
            Err(ReadError::Blocked) => {}
            other => panic!("unexpected rebound stream read: {other:?}"),
        }
        assert!(Instant::now() < deadline, "rebound stream stalled");
        thread::sleep(StdDuration::from_millis(1));
    }
    assert!(!rig.pair.client_conn_mut(client).is_closed());
    assert!(!rig.pair.server_conn_mut(server).is_closed());
    println!(
        "REAL_SOCKET_CID_REBIND old_client={} new_client={} old={} candidate={} cid_preserved=true stream=before+after connected=true",
        old_remote, new_remote, a, b
    );
}

#[test]
fn real_socket_1082_same_destination_control() {
    real_socket_path_response(false, false);
}

#[test]
fn real_socket_1082_changed_destination() {
    real_socket_path_response(true, false);
}

#[test]
#[ignore = "requires fd00:1082::1/::2/::3 in an isolated network namespace"]
fn real_socket_1082_ipv6_multihomed() {
    real_socket_path_response(false, true);
    real_socket_path_response(true, true);
}

#[test]
fn real_socket_1082_local_migration() {
    real_socket_local_migration(false, false, false);
}

#[test]
fn real_socket_1082_local_migration_fallback() {
    real_socket_local_migration(false, true, false);
}

#[test]
fn real_socket_1082_local_migration_mtu_fallback() {
    real_socket_local_migration(false, false, true);
}

#[test]
fn real_socket_1082_cid_exhaustion_recovery() {
    real_socket_cid_exhaustion_recovery(false);
}

#[test]
#[ignore = "requires fd00:1082::1/::2/::3 in an isolated network namespace"]
fn real_socket_1082_ipv6_cid_exhaustion_recovery() {
    real_socket_cid_exhaustion_recovery(true);
}

#[test]
#[ignore = "requires fd00:1082::1/::2/::3 in an isolated network namespace"]
fn real_socket_1082_ipv6_local_migration_and_fallback() {
    real_socket_local_migration(true, false, false);
    real_socket_local_migration(true, true, false);
    real_socket_local_migration(true, false, true);
}

// Each case runs in a separate process because stdin holds one UDP socket in
// the peer namespace. The launcher configures IPv4/IPv6 on the veth pair.
macro_rules! veth_migration_test {
    ($name:ident, $ipv6:expr, $fail:expr, $fail_mtu:expr) => {
        #[test]
        #[ignore = "requires a UDP socket inherited from a separate network namespace"]
        fn $name() {
            assert!(std::env::var_os("QUINN_TEST_INHERITED_UDP").is_some());
            real_socket_local_migration($ipv6, $fail, $fail_mtu);
        }
    };
}

veth_migration_test!(real_socket_1082_veth_ipv4_migration, false, false, false);
veth_migration_test!(real_socket_1082_veth_ipv4_fallback, false, true, false);
veth_migration_test!(real_socket_1082_veth_ipv4_mtu_fallback, false, false, true);
veth_migration_test!(real_socket_1082_veth_ipv6_migration, true, false, false);
veth_migration_test!(real_socket_1082_veth_ipv6_fallback, true, true, false);
veth_migration_test!(real_socket_1082_veth_ipv6_mtu_fallback, true, false, true);

#[test]
#[ignore = "requires a UDP socket inherited from a separate network namespace"]
fn real_socket_1082_veth_ipv4_response() {
    assert!(std::env::var_os("QUINN_TEST_INHERITED_UDP").is_some());
    real_socket_path_response(true, false);
}

#[test]
#[ignore = "requires a UDP socket inherited from a separate network namespace"]
fn real_socket_1082_veth_ipv6_response() {
    assert!(std::env::var_os("QUINN_TEST_INHERITED_UDP").is_some());
    real_socket_path_response(true, true);
}

#[test]
#[ignore = "requires a UDP socket inherited from a separate network namespace"]
fn real_socket_1082_veth_ipv4_cid_exhaustion_recovery() {
    assert!(std::env::var_os("QUINN_TEST_INHERITED_UDP").is_some());
    real_socket_cid_exhaustion_recovery(false);
}

#[test]
#[ignore = "requires a UDP socket inherited from a separate network namespace"]
fn real_socket_1082_veth_ipv6_cid_exhaustion_recovery() {
    assert!(std::env::var_os("QUINN_TEST_INHERITED_UDP").is_some());
    real_socket_cid_exhaustion_recovery(true);
}

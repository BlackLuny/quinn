use super::*;
use std::{
    io::{self, IoSliceMut},
    net::UdpSocket,
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
        let (listen, ip_a, ip_b, client_ip) = if ipv6 {
            ("[::]:0", "fd00:1082::1", "fd00:1082::2", "fd00:1082::3")
        } else {
            ("0.0.0.0:0", "127.0.0.1", "127.0.0.2", "127.0.0.3")
        };
        let server = UdpSocket::bind(listen).unwrap();
        let server_port = server.local_addr().unwrap().port();
        let server_state = UdpSocketState::new((&server).into()).unwrap();
        let server_a = SocketAddr::new(ip_a.parse().unwrap(), server_port);
        let server_b = SocketAddr::new(ip_b.parse().unwrap(), server_port);
        let client = UdpSocket::bind(SocketAddr::new(client_ip.parse().unwrap(), 0)).unwrap();
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

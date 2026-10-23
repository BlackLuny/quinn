use super::*;

/// Receive the authenticated migration packet without polling a transmit. A real
/// driver can observe an already-expired loss timer between these two operations.
fn receive_only(pair: &mut Pair, server_ch: ConnectionHandle) {
    let mut buf = Vec::new();
    while let Some((time, ecn, packet)) = pair.server.inbound.pop_front() {
        let event = pair.server.endpoint.handle(
            time, pair.client.addr, pair.server.local_ip, ecn, packet, &mut buf,
        ).expect("established connection datagram");
        let DatagramEvent::ConnectionEvent(ch, event) = event else {
            panic!("migration must use the existing connection");
        };
        assert_eq!(ch, server_ch);
        pair.server_conn_mut(ch).handle_event(event);
    }
}

#[test]
fn migration_rearms_loss_timer_for_new_path() {
    let _guard = subscribe();
    let mut pair = Pair::default();
    let (client, server) = pair.connect();
    pair.drive();
    pair.server_conn_mut(server).ping();
    pair.drive_server();
    assert!(pair.server_conn_mut(server).bytes_in_flight() > 0);
    let old_deadline = pair.server_conn_mut(server).poll_timeout().unwrap();
    pair.client.inbound.clear(); // Leave the old path's probe unacknowledged.

    pair.client.addr = "127.0.0.2:4567".parse().unwrap();
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    receive_only(&mut pair, server);
    assert_eq!(pair.server_conn_mut(server).remote_address(), pair.client.addr);
    assert_eq!(pair.server_conn_mut(server).bytes_in_flight(), 0);
    // No packet has been sent on the fresh path. The old path's PTO must not
    // run with this path's empty in-flight counters (nor emit a handshake probe).
    pair.server_conn_mut(server).handle_timeout(old_deadline);
    assert!(!pair.server_conn_mut(server).is_closed());
}

#[test]
fn migration_local_ip_follows_path_and_fallback() {
    let _guard = subscribe();
    let v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    for (old_ip, new_ip) in [(v4, v6), (v6, v4)] {
        let mut pair = Pair::default();
        pair.client.addr = SocketAddr::new(old_ip, pair.client.addr.port());
        pair.server.local_ip = Some(old_ip);
        let (client, server) = pair.connect();
        pair.drive();
        let old_remote = pair.client.addr;
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));

        pair.client.addr = SocketAddr::new(new_ip, old_remote.port());
        pair.server.local_ip = Some(new_ip);
        pair.client_conn_mut(client).ping();
        pair.drive_client();
        let (received_at, ecn, valid_packet) = pair.server.inbound.front().unwrap().clone();
        let mut corrupt = valid_packet.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1; // Preserve routing, fail packet authentication.
        let mut scratch = Vec::new();
        let Some(DatagramEvent::ConnectionEvent(_, event)) = pair.server.endpoint.handle(
            received_at, pair.client.addr, Some(new_ip), ecn, corrupt, &mut scratch,
        ) else { panic!("existing CID must route the corrupt packet"); };
        pair.server_conn_mut(server).handle_event(event);
        assert_eq!(pair.server_conn_mut(server).remote_address(), old_remote);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip), "unauthenticated metadata must not change the source");
        receive_only(&mut pair, server);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(new_ip));
        // A replay on the old tuple must not undo the authenticated path change.
        let Some(DatagramEvent::ConnectionEvent(_, replay)) = pair.server.endpoint.handle(
            received_at, old_remote, Some(old_ip), ecn, valid_packet, &mut scratch,
        ) else { panic!("existing CID must route the replay"); };
        pair.server_conn_mut(server).handle_event(replay);
        assert_eq!(pair.server_conn_mut(server).remote_address(), pair.client.addr);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(new_ip));
        let mut buf = Vec::new();
        let mut old_probe = false;
        let mut new_probe = false;
        let now = pair.time;
        while let Some(tx) = pair.server_conn_mut(server).poll_transmit(now, 1, &mut buf) {
            if tx.destination == old_remote {
                assert_eq!(tx.src_ip, Some(old_ip), "old-path challenge source");
                old_probe = true;
            } else {
                assert_eq!(tx.destination, pair.client.addr);
                assert_eq!(tx.src_ip, Some(new_ip), "active-path source");
                new_probe = true;
            }
            buf.clear(); // Drop the probes so validation will time out.
        }
        assert!(old_probe && new_probe);
        for _ in 0..200 {
            if pair.server_conn_mut(server).remote_address() == old_remote { break; }
            let deadline = pair.server_conn_mut(server).poll_timeout().unwrap();
            pair.time = pair.time.max(deadline);
            pair.drive_server();
            pair.client.inbound.clear();
        }
        assert_eq!(pair.server_conn_mut(server).remote_address(), old_remote);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip), "fallback restores local and remote together");
        // Resume the old path and prove it can deliver new traffic after fallback.
        pair.client.addr = old_remote;
        pair.server.local_ip = Some(old_ip);
        let pings = pair.client_conn_mut(client).stats().frame_rx.ping;
        pair.server_conn_mut(server).ping();
        pair.drive();
        assert!(pair.client_conn_mut(client).stats().frame_rx.ping > pings);
        assert!(!pair.server_conn_mut(server).is_closed());
    }
}

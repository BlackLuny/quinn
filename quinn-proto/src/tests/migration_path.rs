use super::*;

/// Receive the authenticated migration packet without polling a transmit. A real
/// driver can observe an already-expired loss timer between these two operations.
fn receive_only(pair: &mut Pair, server_ch: ConnectionHandle) {
    let mut buf = Vec::new();
    while let Some((time, ecn, packet)) = pair.server.inbound.pop_front() {
        let event = pair
            .server
            .endpoint
            .handle(
                time,
                pair.client.addr,
                pair.server.local_ip,
                ecn,
                packet,
                &mut buf,
            )
            .expect("established connection datagram");
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
    assert_eq!(
        pair.server_conn_mut(server).remote_address(),
        pair.client.addr
    );
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
            received_at,
            pair.client.addr,
            Some(new_ip),
            ecn,
            corrupt,
            &mut scratch,
        ) else {
            panic!("existing CID must route the corrupt packet");
        };
        pair.server_conn_mut(server).handle_event(event);
        assert_eq!(pair.server_conn_mut(server).remote_address(), old_remote);
        assert_eq!(
            pair.server_conn_mut(server).local_ip(),
            Some(old_ip),
            "unauthenticated metadata must not change the source"
        );
        receive_only(&mut pair, server);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(new_ip));
        // A replay on the old tuple must not undo the authenticated path change.
        let Some(DatagramEvent::ConnectionEvent(_, replay)) = pair.server.endpoint.handle(
            received_at,
            old_remote,
            Some(old_ip),
            ecn,
            valid_packet,
            &mut scratch,
        ) else {
            panic!("existing CID must route the replay");
        };
        pair.server_conn_mut(server).handle_event(replay);
        assert_eq!(
            pair.server_conn_mut(server).remote_address(),
            pair.client.addr
        );
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
            if pair.server_conn_mut(server).remote_address() == old_remote {
                break;
            }
            let deadline = pair.server_conn_mut(server).poll_timeout().unwrap();
            pair.time = pair.time.max(deadline);
            pair.drive_server();
            pair.client.inbound.clear();
        }
        assert_eq!(pair.server_conn_mut(server).remote_address(), old_remote);
        assert_eq!(
            pair.server_conn_mut(server).local_ip(),
            Some(old_ip),
            "fallback restores local and remote together"
        );
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

#[test]
fn local_destination_challenge_preserves_active_path_and_rejects_replay() {
    let _guard = subscribe();
    let v4a: IpAddr = "127.0.0.1".parse().unwrap();
    let v4b: IpAddr = "127.0.0.2".parse().unwrap();
    let v6: IpAddr = "::1".parse().unwrap();

    for (old_ip, received_ip) in [(v4a, v4a), (v4a, v4b), (v4a, v6), (v6, v4a)] {
        let mut pair = Pair::default();
        pair.client.addr = "127.0.0.3:4567".parse().unwrap();
        pair.server.local_ip = Some(old_ip);
        let (client, server) = pair.connect();
        pair.drive();
        let remote = pair.client.addr;
        let before_rx = pair.server_conn_mut(server).stats().frame_rx.path_challenge;
        let before_tx = pair.server_conn_mut(server).stats().frame_tx.path_response;

        pair.client_conn_mut(client).repro_queue_path_challenge();
        pair.drive_client();
        let (time, ecn, packet) = pair.server.inbound.front().unwrap().clone();
        let mut corrupted = packet.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let mut scratch = Vec::new();
        let Some(DatagramEvent::ConnectionEvent(ch, event)) = pair.server.endpoint.handle(
            time, remote, Some(received_ip), ecn, corrupted, &mut scratch,
        ) else {
            panic!("corrupted packet must route to the existing connection");
        };
        assert_eq!(ch, server);
        pair.server_conn_mut(ch).handle_event(event);
        assert_eq!(pair.server_conn_mut(server).stats().frame_rx.path_challenge, before_rx);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));

        pair.server.local_ip = Some(received_ip);
        receive_only(&mut pair, server);
        assert_eq!(pair.server_conn_mut(server).stats().frame_rx.path_challenge, before_rx + 1);
        assert_eq!(pair.server_conn_mut(server).remote_address(), remote);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));

        // A valid ciphertext replayed with different local metadata must not
        // enqueue a second response or move the active path.
        let Some(DatagramEvent::ConnectionEvent(ch, event)) = pair.server.endpoint.handle(
            time, remote, Some(old_ip), ecn, packet, &mut scratch,
        ) else {
            panic!("replay must route to the existing connection");
        };
        assert_eq!(ch, server);
        pair.server_conn_mut(ch).handle_event(event);
        assert_eq!(pair.server_conn_mut(server).stats().frame_rx.path_challenge, before_rx + 1);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));

        let now = pair.time;
        let mut buf = Vec::new();
        let mut response = None;
        while let Some(tx) = pair.server_conn_mut(server).poll_transmit(now, 1, &mut buf) {
            if pair.server_conn_mut(server).stats().frame_tx.path_response > before_tx {
                response = Some(tx);
                break;
            }
            buf.clear();
        }
        let response = response.expect("authenticated challenge must be answered");
        assert_eq!(response.destination, remote);
        assert_eq!(response.src_ip, Some(received_ip));
        assert_eq!(pair.server_conn_mut(server).stats().frame_tx.path_response, before_tx + 1);

        // A probe does not promote the receiving address. Ordinary traffic
        // continues on the previously active path.
        let before_ping = pair.server_conn_mut(server).stats().frame_tx.ping;
        pair.server_conn_mut(server).ping();
        buf.clear();
        let later = now + Duration::from_secs(1);
        let ping = loop {
            let tx = pair.server_conn_mut(server).poll_transmit(later, 1, &mut buf)
                .expect("active path must remain sendable");
            if pair.server_conn_mut(server).stats().frame_tx.ping > before_ping {
                break tx;
            }
            buf.clear();
        };
        assert_eq!(ping.destination, remote);
        assert_eq!(ping.src_ip, Some(old_ip));
        assert!(!pair.server_conn_mut(server).is_closed());
    }
}

#[test]
fn short_off_path_challenge_does_not_amplify() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    for (new_remote, unvalidated) in [(false, false), (true, false), (false, true)] {
        let mut pair = Pair::default();
        pair.client.addr = "127.0.0.3:4567".parse().unwrap();
        pair.server.local_ip = Some(old_ip);
        let (client, server) = pair.connect();
        pair.drive();
        let old_remote = pair.client.addr;
        let remote = if new_remote { "127.0.0.4:4568".parse().unwrap() } else { old_remote };
        if unvalidated {
            pair.server_conn_mut(server).test_set_unvalidated_path_bytes(1000, 3000);
        }
        let now = pair.time;
        let before_rx = pair.server_conn_mut(server).stats().frame_rx.path_challenge;
        let before_tx = pair.server_conn_mut(server).stats().frame_tx.path_response;
        let mut challenge = Vec::new();
        let tx = pair.client_conn_mut(client).test_short_path_challenge(now, &mut challenge);
        assert_eq!(tx.size, challenge.len());
        assert!(challenge.len() < 400, "test requires less than 400 received bytes");

        let mut scratch = Vec::new();
        let Some(DatagramEvent::ConnectionEvent(ch, event)) = pair.server.endpoint.handle(
            now, remote, Some(new_ip), None, BytesMut::from(challenge.as_slice()), &mut scratch,
        ) else {
            panic!("short challenge must route to the existing connection");
        };
        assert_eq!(ch, server);
        pair.server_conn_mut(ch).handle_event(event);
        assert_eq!(pair.server_conn_mut(server).stats().frame_rx.path_challenge, before_rx + 1);
        let mut output = Vec::new();
        let response = loop {
            let tx = pair.server_conn_mut(server).poll_transmit(now, 1, &mut output)
                .expect("short challenge should fit a bounded response");
            if pair.server_conn_mut(server).stats().frame_tx.path_response > before_tx {
                break tx;
            }
            output.clear();
        };
        assert_eq!(response.destination, remote);
        assert_eq!(response.src_ip, Some(new_ip));
        assert!(response.size <= challenge.len() * 3);
        assert!(response.size < 1200, "a short challenge cannot fund padding to 1200");
        assert_eq!(pair.server_conn_mut(server).remote_address(), old_remote);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
        if unvalidated {
            let (received, sent) = pair.server_conn_mut(server).test_path_bytes();
            assert_eq!(sent, 3000 + response.size as u64);
            assert!(sent <= received * 3);
        }
        assert!(!pair.server_conn_mut(server).is_closed());
    }
}

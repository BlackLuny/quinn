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
fn same_remote_local_destination_migrates_and_falls_back() {
    let _guard = subscribe();
    let v4a: IpAddr = "127.0.0.1".parse().unwrap();
    let v4b: IpAddr = "127.0.0.2".parse().unwrap();
    let v6: IpAddr = "::1".parse().unwrap();
    for (old_ip, new_ip) in [(v4a, v4b), (v4a, v6), (v6, v4a)] {
        let mut pair = Pair::default();
        pair.client.addr = "127.0.0.3:4567".parse().unwrap();
        pair.server.local_ip = Some(old_ip);
        let (client, server) = pair.connect();
        pair.drive();
        let remote = pair.client.addr;

        pair.client_conn_mut(client).ping();
        pair.drive_client();
        let (time, ecn, original) = pair.server.inbound.front().unwrap().clone();
        let mut corrupted = original.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let mut scratch = Vec::new();
        let Some(DatagramEvent::ConnectionEvent(ch, event)) = pair.server.endpoint.handle(
            time, remote, Some(new_ip), ecn, corrupted, &mut scratch,
        ) else {
            panic!("corrupted packet must route to the existing connection");
        };
        pair.server_conn_mut(ch).handle_event(event);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
        pair.server.local_ip = Some(new_ip);
        receive_only(&mut pair, server);
        assert_eq!(pair.server_conn_mut(server).remote_address(), remote);
        assert_eq!(
            pair.server_conn_mut(server).local_ip(), Some(old_ip),
            "the active path must remain in use until the new path validates"
        );
        assert!(pair.server_conn_mut(server).test_local_path_candidate().is_some(),
            "a fresh authenticated non-probing packet must start validation");
        let candidate_cid = pair.server_conn_mut(server).test_local_candidate_cid().unwrap();
        assert_ne!(pair.server_conn_mut(server).test_remote_cids().0, candidate_cid);
        let Some(DatagramEvent::ConnectionEvent(ch, replay)) = pair.server.endpoint.handle(
            time, remote, Some(old_ip), ecn, original, &mut scratch,
        ) else {
            panic!("replayed packet must route to the existing connection");
        };
        pair.server_conn_mut(ch).handle_event(replay);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
        assert!(pair.server_conn_mut(server).test_local_path_candidate().is_some());

        // Drop both probes and all subsequent packets so validation must time out.
        let mut old_probe = false;
        let mut new_probe = false;
        let mut buf = Vec::new();
        let now = pair.time;
        while let Some(tx) = pair.server_conn_mut(server).poll_transmit(now, 1, &mut buf) {
            assert_eq!(tx.destination, remote);
            old_probe |= tx.src_ip == Some(old_ip);
            new_probe |= tx.src_ip == Some(new_ip);
            buf.clear();
        }
        assert!(old_probe && new_probe, "both the active and candidate paths must be probed");
        for _ in 0..200 {
            assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
            if pair.server_conn_mut(server).test_local_path_candidate().is_none() {
                break;
            }
            let deadline = pair.server_conn_mut(server).poll_timeout().unwrap();
            pair.time = pair.time.max(deadline);
            pair.drive_server();
            pair.client.inbound.clear();
        }
        assert_eq!(pair.server_conn_mut(server).remote_address(), remote);
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
        assert!(pair.server_conn_mut(server).test_local_path_candidate().is_none());
        assert_ne!(pair.server_conn_mut(server).test_remote_cids().1, Some(candidate_cid),
            "a CID used on an abandoned path must not be reused on another path");
        pair.server.local_ip = Some(old_ip);
        let pings = pair.client_conn_mut(client).stats().frame_rx.ping;
        pair.server_conn_mut(server).ping();
        pair.drive();
        assert!(pair.client_conn_mut(client).stats().frame_rx.ping > pings);
        assert!(!pair.server_conn_mut(server).is_closed());
    }
}

#[test]
fn same_remote_local_destination_validates_and_keeps_stream() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    let remote = pair.client.addr;
    let stream = pair.client_streams(client).open(Dir::Bi).unwrap();
    assert_eq!(pair.client_send(client, stream).write(b"new path").unwrap(), 8);
    pair.drive_client();
    let received_len = pair.server.inbound.front().unwrap().2.len();
    assert!(received_len * 3 < 1200, "the first packet must require a short probe");
    pair.server.local_ip = Some(new_ip);
    receive_only(&mut pair, server);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    let before = pair.server_conn_mut(server).stats().frame_tx.path_challenge;
    pair.drive_server();
    let candidate = pair.server_conn_mut(server).test_local_path_candidate().unwrap();
    assert_eq!((candidate.0, candidate.1, candidate.2), (false, false, true),
        "the first short challenge must retain the need for an MTU probe");
    assert!(candidate.4 <= candidate.3 * 3);
    pair.drive();
    assert_eq!(pair.server_conn_mut(server).remote_address(), remote);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(new_ip));
    assert_eq!(pair.server_conn_mut(server).test_path_validation_state(), (true, false));
    assert!(pair.server_conn_mut(server).test_local_path_candidate().is_none());
    assert!(pair.server_conn_mut(server).stats().frame_tx.path_challenge >= before + 3,
        "old-path and short probes must be followed by a full-size challenge");
    assert_eq!(pair.server_streams(server).accept(Dir::Bi), Some(stream));
    let mut recv = pair.server_recv(server, stream);
    let mut chunks = recv.read(true).unwrap();
    let chunk = chunks.next(usize::MAX).unwrap().unwrap();
    assert_eq!(chunk.bytes.as_ref(), b"new path");
    let _ = chunks.finalize();
    assert!(!pair.server_conn_mut(server).is_closed());
}

#[test]
fn repeated_local_path_failures_preserve_connection_and_cid_capacity() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    for round in 0..6 {
        pair.client_conn_mut(client).ping();
        pair.drive_client();
        pair.server.local_ip = Some(new_ip);
        receive_only(&mut pair, server);
        assert!(pair.server_conn_mut(server).test_local_path_candidate().is_some(),
            "candidate {round} needs a usable spare CID");
        for _ in 0..200 {
            if pair.server_conn_mut(server).test_local_path_candidate().is_none() {
                break;
            }
            pair.drive_server();
            pair.client.inbound.clear();
            if pair.server_conn_mut(server).test_local_path_candidate().is_none() {
                break;
            }
            let deadline = pair.server_conn_mut(server).poll_timeout().unwrap();
            pair.time = pair.time.max(deadline);
        }
        assert!(pair.server_conn_mut(server).test_local_path_candidate().is_none());
        assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
        pair.server.local_ip = Some(old_ip);
        pair.client.inbound.clear();
        pair.drive(); // Deliver CID retirements and peer replacements on A.
        assert!(!pair.server_conn_mut(server).is_closed(), "round {round}");
        assert!(!pair.client_conn_mut(client).is_closed(), "round {round}");
    }
}

#[test]
fn same_remote_local_path_has_its_own_amplification_budget() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    pair.server.local_ip = Some(new_ip);
    receive_only(&mut pair, server);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    let mut output = Vec::new();
    let now = pair.time;
    while let Some(tx) = pair.server_conn_mut(server).poll_transmit(now, 16, &mut output) {
        if tx.src_ip == Some(new_ip) {
            let candidate = pair.server_conn_mut(server).test_local_path_candidate().unwrap();
            assert!(candidate.4 <= candidate.3 * 3, "new path exceeded its amplification budget");
        }
        output.clear();
    }
    let before = pair.server_conn_mut(server).test_local_path_candidate().unwrap();
    pair.client_conn_mut(client).repro_queue_path_challenge();
    pair.drive_client();
    pair.server.local_ip = Some(old_ip);
    receive_only(&mut pair, server);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    assert_eq!(pair.server_conn_mut(server).test_local_path_candidate().unwrap(), before,
        "old-path packets cannot fund the new path");
    let response_before = pair.server_conn_mut(server).stats().frame_tx.path_response;
    let later = now + Duration::from_secs(1);
    loop {
        output.clear();
        let tx = pair.server_conn_mut(server).poll_transmit(later, 1, &mut output)
            .expect("old-path response should not need new-path budget");
        if pair.server_conn_mut(server).stats().frame_tx.path_response > response_before {
            assert_eq!(tx.src_ip, Some(old_ip));
            assert_eq!(pair.server_conn_mut(server).test_local_path_candidate().unwrap(), before);
            break;
        }
    }
}

#[test]
fn missing_local_metadata_does_not_move_active_path() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    for (previous, received) in [(Some(old_ip), None), (None, Some(old_ip))] {
        let mut pair = Pair::default();
        pair.client.addr = "127.0.0.3:4567".parse().unwrap();
        pair.server.local_ip = previous;
        let (client, server) = pair.connect();
        pair.drive();
        pair.client_conn_mut(client).ping();
        pair.drive_client();
        pair.server.local_ip = received;
        receive_only(&mut pair, server);
        assert_eq!(pair.server_conn_mut(server).local_ip(), previous);
    }
}

#[test]
fn reordered_old_path_packet_does_not_cancel_new_candidate() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default_with_deterministic_pns();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    let (_, old_ecn, old_packet) = pair.server.inbound.pop_front().unwrap();
    pair.time += Duration::from_millis(50);
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    let (_, new_ecn, new_packet) = pair.server.inbound.pop_front().unwrap();
    let before = pair.server_conn_mut(server).stats().frame_rx.ping;
    let now = pair.time;
    let remote = pair.client.addr;
    let mut scratch = Vec::new();
    for (ip, ecn, packet) in [(new_ip, new_ecn, new_packet), (old_ip, old_ecn, old_packet)] {
        let Some(DatagramEvent::ConnectionEvent(ch, event)) = pair.server.endpoint.handle(
            now, remote, Some(ip), ecn, packet, &mut scratch,
        ) else {
            panic!("authenticated packet must route to the existing connection");
        };
        pair.server_conn_mut(ch).handle_event(event);
    }
    assert_eq!(pair.server_conn_mut(server).stats().frame_rx.ping, before + 2);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    assert!(pair.server_conn_mut(server).test_local_path_candidate().is_some(),
        "an older non-probing packet must not cancel the newer candidate");
}

#[test]
fn local_migration_waits_for_an_unused_peer_cid() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    pair.server_conn_mut(server).test_exhaust_spare_cids();
    assert!(pair.server_conn_mut(server).test_remote_cids().1.is_none());
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    pair.server.local_ip = Some(new_ip);
    receive_only(&mut pair, server);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    assert!(pair.server_conn_mut(server).test_local_path_candidate().is_none());
    assert!(!pair.server_conn_mut(server).is_closed());
}

#[test]
fn local_candidate_cid_is_not_reused_if_peer_retires_active_cid() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    pair.server.local_ip = Some(new_ip);
    receive_only(&mut pair, server);
    let used = pair.server_conn_mut(server).test_local_candidate_cid().unwrap();
    let now = pair.time;
    let mut output = Vec::new();
    let tx = pair.server_conn_mut(server).poll_transmit(now, 1, &mut output)
        .expect("candidate challenge");
    assert_eq!(tx.src_ip, Some(new_ip));
    assert!(pair.server_conn_mut(server).test_local_path_candidate().unwrap().4 > 0);

    let retire_prior_to = pair.server_conn_mut(server).active_rem_cid_seq() + 1;
    pair.time += Duration::from_secs(1);
    let later = pair.time;
    pair.client_conn_mut(client).rotate_local_cid(retire_prior_to, later);
    pair.drive_client();
    pair.server.local_ip = Some(old_ip);
    receive_only(&mut pair, server);
    output.clear();
    let tx = pair.server_conn_mut(server).poll_transmit(later, 1, &mut output);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    assert!(pair.server_conn_mut(server).test_local_path_candidate().is_none());
    if pair.server_conn_mut(server).test_remote_cids().0 == used {
        assert!(tx.is_none());
        assert!(pair.server_conn_mut(server).test_blocked_local_cid());
    } else {
        assert!(!pair.server_conn_mut(server).test_blocked_local_cid());
    }
    assert!(!pair.server_conn_mut(server).is_closed());
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
        let active_cid = pair.server_conn_mut(server).test_remote_cids().0;

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
        let response_cid = &buf[1..1 + active_cid.len()];
        if received_ip == old_ip {
            assert_eq!(response_cid, &active_cid[..]);
        } else {
            assert_ne!(response_cid, &active_cid[..], "different local paths need different CIDs");
        }

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
fn local_path_probe_without_spare_cid_does_not_reuse_active_cid() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let new_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    pair.server_conn_mut(server).test_exhaust_spare_cids();
    assert!(pair.server_conn_mut(server).test_remote_cids().1.is_none());
    let before = pair.server_conn_mut(server).stats().frame_tx.path_response;

    pair.client_conn_mut(client).repro_queue_path_challenge();
    pair.drive_client();
    pair.server.local_ip = Some(new_ip);
    receive_only(&mut pair, server);
    let mut buf = Vec::new();
    let now = pair.time;
    while let Some(tx) = pair.server_conn_mut(server).poll_transmit(now, 1, &mut buf) {
        assert_ne!(tx.src_ip, Some(new_ip), "no CID is available for the new path");
        buf.clear();
    }
    assert_eq!(pair.server_conn_mut(server).stats().frame_tx.path_response, before);
    assert_eq!(pair.server_conn_mut(server).local_ip(), Some(old_ip));
    assert!(!pair.server_conn_mut(server).is_closed());
}

#[test]
fn local_probe_on_third_path_does_not_use_candidate_cid() {
    let _guard = subscribe();
    let old_ip: IpAddr = "127.0.0.1".parse().unwrap();
    let candidate_ip: IpAddr = "127.0.0.2".parse().unwrap();
    let third_ip: IpAddr = "127.0.0.4".parse().unwrap();
    let mut pair = Pair::default();
    pair.client.addr = "127.0.0.3:4567".parse().unwrap();
    pair.server.local_ip = Some(old_ip);
    let (client, server) = pair.connect();
    pair.drive();
    pair.client_conn_mut(client).ping();
    pair.drive_client();
    pair.server.local_ip = Some(candidate_ip);
    receive_only(&mut pair, server);
    let candidate_cid = pair.server_conn_mut(server).test_local_candidate_cid().unwrap();

    let now = pair.time;
    let mut challenge = Vec::new();
    pair.client_conn_mut(client).test_short_path_challenge(now, &mut challenge);
    let remote = pair.client.addr;
    let mut scratch = Vec::new();
    let Some(DatagramEvent::ConnectionEvent(ch, event)) = pair.server.endpoint.handle(
        now, remote, Some(third_ip), None, BytesMut::from(challenge.as_slice()), &mut scratch,
    ) else {
        panic!("third-path challenge must route to the existing connection");
    };
    pair.server_conn_mut(ch).handle_event(event);
    let before = pair.server_conn_mut(server).stats().frame_tx.path_response;
    let mut buf = Vec::new();
    let response = loop {
        let tx = pair.server_conn_mut(server).poll_transmit(now, 1, &mut buf)
            .expect("third-path response should be sendable");
        if pair.server_conn_mut(server).stats().frame_tx.path_response > before {
            break tx;
        }
        buf.clear();
    };
    assert_eq!(response.src_ip, Some(third_ip));
    assert_ne!(&buf[1..1 + candidate_cid.len()], &candidate_cid[..]);
    assert_eq!(pair.server_conn_mut(server).test_local_candidate_cid(), Some(candidate_cid));
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

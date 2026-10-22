package discover

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/FusionFoundation/efsn/v5/crypto"
)

type restartFindnodeResult struct {
	nodes []*Node
	err   error
}

func TestRestartSparseFindnodeReplies(t *testing.T) {
	for _, mode := range []string{"one_valid", "two_packets", "invalid_only", "no_reply"} {
		t.Run(mode, func(t *testing.T) {
			test := newUDPTest(t)
			defer test.table.Close()
			remote := PubkeyID(&test.remotekey.PublicKey)
			if err := test.table.db.updateLastPingReceived(remote, time.Now()); err != nil {
				t.Fatal(err)
			}
			result := make(chan restartFindnodeResult, 1)
			go func() {
				nodes, err := test.udp.findnode(remote, test.remoteaddr, testTarget)
				result <- restartFindnodeResult{nodes: nodes, err: err}
			}()
			test.waitPacketOut(func(p *findnode) {})
			peer := restartCacheNode(t, 1)
			peer.IP = net.IP{10, 0, 1, 16}
			wantCount := 0
			wantError := errTimeout
			if mode != "no_reply" {
				if mode == "invalid_only" {
					peer.UDP = 17
				} else {
					wantCount = 1
					wantError = nil
				}
				test.packetIn(nil, neighborsPacket, &neighbors{Expiration: futureExp, Nodes: []rpcNode{nodeToRPC(peer)}})
			}
			if mode == "two_packets" {
				second := restartCacheNode(t, 2)
				second.IP = net.IP{10, 0, 1, 17}
				test.packetIn(nil, neighborsPacket, &neighbors{Expiration: futureExp, Nodes: []rpcNode{nodeToRPC(second)}})
				wantCount = 2
			}
			select {
			case received := <-result:
				if len(received.nodes) != wantCount || received.err != wantError {
					t.Fatalf("neighbors=%d err=%v; want neighbors=%d err=%v", len(received.nodes), received.err, wantCount, wantError)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("findnode did not finish")
			}
		})
	}
}

func TestRestartSparseReplyDoesNotPenalizePeer(t *testing.T) {
	test := newUDPTest(t)
	defer test.table.Close()
	remote := PubkeyID(&test.remotekey.PublicKey)
	if err := test.table.db.updateLastPingReceived(remote, time.Now()); err != nil {
		t.Fatal(err)
	}
	peer := restartCacheNode(t, 1)
	peer.IP = net.IP{10, 0, 1, 16}
	result := make(chan []*Node, 1)
	go test.table.findnode(NewNode(remote, test.remoteaddr.IP, uint16(test.remoteaddr.Port), 40408), testTarget, result)
	test.waitPacketOut(func(p *findnode) {})
	test.packetIn(nil, neighborsPacket, &neighbors{Expiration: futureExp, Nodes: []rpcNode{nodeToRPC(peer)}})
	select {
	case received := <-result:
		if len(received) != 1 || received[0].String() != peer.String() {
			t.Fatal("valid neighbor was not returned")
		}
		if failures := test.table.db.findFails(remote); failures != 0 {
			t.Fatalf("valid sparse reply penalized responding peer: failures=%d", failures)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("table lookup did not finish")
	}
}

func restartCacheNode(t *testing.T, number int) *Node {
	t.Helper()
	key, err := crypto.HexToECDSA(fmt.Sprintf("%064x", number))
	if err != nil {
		t.Fatal(err)
	}
	return NewNode(PubkeyID(&key.PublicKey), net.IPv4(127, 0, 0, byte(number+1)), 40408, 40408)
}

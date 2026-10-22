package discover

import (
	"net"
	"testing"
	"time"
)

func TestRestartDiscoveryRejectsSelf(t *testing.T) {
	for _, mode := range []string{"neighbors", "ping", "replacement", "empty_lookup_refresh"} {
		t.Run(mode, func(t *testing.T) {
			identity := restartCacheNode(t, 1)
			tab, err := newTable(newPingRecorder(), identity.ID, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40408}, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(tab.db.close)
			close(tab.initDone)
			self := NewNode(identity.ID, net.IPv4(172, 0, 1, 9), 40409, 40409)
			bucket := tab.bucket(self.sha)
			if mode == "replacement" {
				for i := 0; i < bucketSize; i++ {
					n := restartCacheNode(t, i+2)
					n.sha = self.sha
					bucket.entries = append(bucket.entries, n)
				}
			}
			if mode == "ping" {
				tab.addThroughPing(self)
			} else {
				tab.add(self)
			}
			if mode == "empty_lookup_refresh" {
				done := make(chan []*Node, 1)
				go func() { done <- tab.Lookup(identity.ID) }()
				select {
				case request := <-tab.refreshReq:
					close(request)
				case nodes := <-done:
					t.Fatalf("self contact suppressed empty-table refresh: %v", nodes)
				case <-time.After(time.Second):
					t.Fatal("lookup did not request refresh")
				}
				select {
				case nodes := <-done:
					if len(nodes) != 0 {
						t.Fatalf("empty refresh returned contacts: %v", nodes)
					}
				case <-time.After(time.Second):
					t.Fatal("lookup did not finish after refresh")
				}
			}
			if hasNode(bucket.entries, identity.ID) || hasNode(bucket.replacements, identity.ID) || tab.ips.String() != "{}" {
				t.Fatalf("own identity admitted or reserved an address: entries=%d replacements=%d ips=%s", len(bucket.entries), len(bucket.replacements), tab.ips.String())
			}
		})
	}
}

func hasNode(nodes []*Node, id NodeID) bool {
	for _, n := range nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

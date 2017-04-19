package host

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/NebulousLabs/Sia/encoding"
	"github.com/NebulousLabs/Sia/modules"
)

// blockingPortForward is a dependency set that causes the host port forward
// call at startup to block for 10 seconds, simulating the amount of blocking
// that can occur in production.
//
// blockingPortForward will also cause managedClearPort to always return an
// error.
type blockingPortForward struct {
	productionDependencies
}

// disrupt will cause the port forward call to block for 10 seconds, but still
// complete normally. disrupt will also cause managedClearPort to return an
// error.
func (blockingPortForward) disrupt(s string) bool {
	// Return an error when clearing the port.
	if s == "managedClearPort return error" {
		return true
	}

	// Block during port forwarding.
	if s == "managedForwardPort" {
		time.Sleep(time.Second * 3)
	}
	return false
}

// TestPortFowardBlocking checks that the host does not accidentally call a
// write on a closed logger due to a long-running port forward call.
func TestPortForwardBlocking(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()
	ht, err := newMockHostTester(blockingPortForward{}, "TestPortForwardBlocking")
	if err != nil {
		t.Fatal(err)
	}

	// The close operation would previously fail here because of improper
	// thread control regarding upnp and shutdown.
	err = ht.Close()
	if err != nil {
		t.Fatal(err)
	}

	// The trailing sleep is needed to catch the previously existing error
	// where the host was not shutting down correctly. Currently, the extra
	// sleep does nothing, but in the regression a logging panic would occur.
	time.Sleep(time.Second * 4)
}

// TestHostWorkingStatus checks that the host properly updates its working
// state
func TestHostWorkingStatus(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()
	ht, err := newHostTester(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer ht.Close()

	if ht.host.WorkingStatus() != modules.HostWorkingStatusChecking {
		t.Fatal("expected working state to initially be modules.HostWorkingStatusChecking")
	}

	// Simulate some setting calls, and see if the host picks up on it.
	atomic.AddUint64(&ht.host.atomicSettingsCalls, workingStatusThreshold+1)
	time.Sleep(workingStatusFirstCheck + time.Second)
	if ht.host.WorkingStatus() != modules.HostWorkingStatusWorking {
		t.Fatal("expected host working status to be modules.HostWorkingStatusWorking after incrementing status calls")
	}

	// No more settings calls, host should believe it is not working now.
	time.Sleep(workingStatusFrequency + time.Second)
	if ht.host.WorkingStatus() != modules.HostWorkingStatusNotWorking {
		t.Fatal("expected host working status to be modules.HostWorkingStatusNotWorking after waiting workingStatusFrequency with no settings calls")
	}

	// Simulate some setting calls, and see if the host picks up on it.
	atomic.AddUint64(&ht.host.atomicSettingsCalls, workingStatusThreshold+1)
	time.Sleep(workingStatusFirstCheck + time.Second)
	if ht.host.WorkingStatus() != modules.HostWorkingStatusNotWorking {
		t.Fatal("expected host working status to be modules.HostWorkingStatusWorking after incrementing status calls")
	}
	time.Sleep(workingStatusFrequency - workingStatusFirstCheck)
	if ht.host.WorkingStatus() != modules.HostWorkingStatusWorking {
		t.Fatal("expected host working status to be modules.HostWorkingStatusWorking after incrementing status calls")
	}
}

// TestHostConnectabilityStatus checks that the host properly updates its connectable
// state
func TestHostConnectabilityStatus(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}
	t.Parallel()

	ht, err := newHostTester(t.Name())

	// create a peer for the check to run on
	peer, err := newHostTester(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	ht, err := newHostTester(t.Name() + "-peer")
	if err != nil {
		t.Fatal(err)
	}
	defer ht.Close()

	err = ht.gateway.Connect(peer.gateway.Address())
	if err != nil {
		t.Fatal(err)
	}

	if ht.host.ConnectabilityStatus() != modules.HostConnectabilityStatusChecking {
		t.Fatal("expected connectability state to initially be ConnectablityStateChecking")
	}
	time.Sleep(connectabilityCheckFirstWait + time.Second)
	if ht.host.ConnectabilityStatus() != modules.HostConnectabilityStatusConnectable {
		t.Fatal("expected connectability state to be modules.HostConnectabilityStatusConnectable")
	}
}

// TestHostConnectabilityStatusAdversarialCallers verifies that an adversary
// cannot abuse the host status check, using nodes to connect scan arbitrary
// hosts.
func TestHostConnectabilityStatusAdversarialCallers(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	evilpeer, err := newHostTester(t.Name() + "-evilpeer")
	if err != nil {
		t.Fatal(err)
	}
	defer evilpeer.Close()

	host, err := newHostTester(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()

	err = evilpeer.gateway.Connect(host.gateway.Address())
	if err != nil {
		t.Fatal(err)
	}

	evilCheckHostRPC := func(conn modules.PeerConn) error {
		defer conn.Close()

		err = encoding.WriteObject(conn, "google.com:80")
		if err != nil {
			return err
		}

		var status modules.HostConnectabilityStatus
		err = encoding.ReadObject(conn, &status, 256)
		if err != nil {
			return err
		}

		if status != "" {
			t.Fatal("status checked on external domain")
		}

		return nil
	}

	err = evilpeer.gateway.RPC(host.gateway.Address(), "CheckHost", evilCheckHostRPC)
	if err == nil {
		t.Fatal("expected malicious CheckHost call to fail")
	}
}

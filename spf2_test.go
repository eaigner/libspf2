package libspf2

import (
	"net"
	"testing"
)

func TestIPv4(t *testing.T) {
	var err error

	s := NewServer()
	defer s.Free()

	goodReq := NewRequest(s)
	defer goodReq.Free()

	err = goodReq.SetIPv4Addr("173.194.39.150")
	if err != nil {
		t.Fatal(err)
	}

	err = goodReq.SetEnvFrom("bob@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	goodResp, err := goodReq.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer goodResp.Free()

	res := goodResp.Result()
	if res != SPFResultPASS {
		t.Fatal(res)
	}
	if s := res.String(); s != "pass" {
		t.Fatal(s)
	}

	badReq := NewRequest(s)
	defer badReq.Free()

	err = badReq.SetIPv4Addr("192.168.1.1")
	if err != nil {
		t.Fatal(err)
	}

	err = badReq.SetEnvFrom("bob@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	badResp, err := badReq.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer badResp.Free()

	res = badResp.Result()
	if res == SPFResultPASS {
		t.Fatal(res)
	}

	if s := res.String(); s == "pass" {
		t.Fatal(s)
	}
}

func TestIPv6(t *testing.T) {
	var err error
	var ip net.IP

	s := NewServer()
	defer s.Free()

	req := NewRequest(s)
	defer req.Free()

	ip = net.ParseIP("2404:6800:4003:803::1006")
	err = req.SetIPAddr(ip)
	if err != nil {
		t.Fatal(err)
	}

	err = req.SetEnvFrom("alice@gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := req.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Free()

	res := resp.Result()
	if res != SPFResultPASS {
		t.Fatal(res)
	}
	if s := res.String(); s != "pass" {
		t.Fatal(s)
	}
}

func TestHeloDom(t *testing.T) {
	var err error

	s := NewServer()
	defer s.Free()

	req := NewRequest(s)
	defer req.Free()

	err = req.SetIPv4Addr("173.194.39.150")
	if err != nil {
		t.Fatal(err)
	}

	err = req.SetHeloDom("gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := req.Query()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Free()

	res := resp.Result()
	if res != SPFResultPASS {
		t.Fatal(res)
	}
	if s := res.String(); s != "pass" {
		t.Fatal(s)
	}
}

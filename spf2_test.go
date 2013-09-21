package libspf2

import (
	"testing"
)

func TestSpf2(t *testing.T) {
	s := NewServer()
	defer s.Free()

	req := NewRequest(s)
	defer req.Free()

	err := req.SetIPv4Addr("173.194.39.150")
	if err != nil {
		t.Fatal(err)
	}
	err = req.SetEnvFrom("gmail.com")
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

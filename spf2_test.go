package libspf2

import (
	"testing"
)

func TestSpf2(t *testing.T) {
	c := NewClient()
	defer c.Free()

	req := newRequest(c)
	defer req.Free()

	err := req.setIPv4Addr("173.194.39.150")
	if err != nil {
		t.Fatal(err)
	}
	err = req.setEnvFrom("gmail.com")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := req.query()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.free()

	res := resp.result()
	if res != SPFResultPASS {
		t.Fatal(res)
	}
	if s := res.String(); s != "pass" {
		t.Fatal(s)
	}
}

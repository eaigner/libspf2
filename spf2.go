package libspf2

/*
#cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -lspf2
#cgo CFLAGS: -g -O2 -Wno-error -I/usr/include -I/usr/local/include

#include <stdio.h>
#include <netdb.h>
#include <spf2/spf.h>
*/
import (
	"C"
	"errors"
)

const (
	SPFResultINVALID   = Result(C.SPF_RESULT_INVALID)   // (invalid)
	SPFResultPASS      = Result(C.SPF_RESULT_PASS)      // pass
	SPFResultFAIL      = Result(C.SPF_RESULT_FAIL)      // fail
	SPFResultSOFTFAIL  = Result(C.SPF_RESULT_SOFTFAIL)  // softfail
	SPFResultNEUTRAL   = Result(C.SPF_RESULT_NEUTRAL)   // neutral
	SPFResultPERMERROR = Result(C.SPF_RESULT_PERMERROR) // permerror
	SPFResultTEMPERROR = Result(C.SPF_RESULT_TEMPERROR) // temperror
	SPFResultNONE      = Result(C.SPF_RESULT_NONE)      // none
)

type Client interface {
	Query(host, ip string) (Result, error)
	Close() error
}

type clientImpl struct {
	s *C.SPF_server_t
}

// NewClient creates a new SPF client.
func NewClient() Client {
	client := new(clientImpl)
	client.s = C.SPF_server_new(C.SPF_DNS_CACHE, 0)
	return client
}

func (s *clientImpl) Query(host, ip string) (Result, error) {
	if s.s == nil {
		return SPFResultINVALID, errors.New("client already closed")
	}
	req := newRequest(s)
	defer req.free()
	if err := req.setEnvFrom(host); err != nil {
		return SPFResultINVALID, err
	}
	if err := req.setIPv4Addr(ip); err != nil {
		return SPFResultINVALID, err
	}
	if resp, err := req.query(); err != nil {
		return SPFResultNONE, err
	}
	defer resp.free()
	return resp.result(), nil
}

func (s *clientImpl) Close() {
	if s.s != nil {
		C.SPF_server_free(s.s)
		s.s = nil
		return nil
	}
	return errors.New("already closed")
}

type request struct {
	s *clientImpl
	r *C.SPF_request_t
}

func newRequest(s *clientImpl) *request {
	r := new(Request)
	r.s = s
	r.r = C.SPF_request_new(s.s)
	return r
}

// SetIPv4Addr sets the sender IPv4
func (r *request) setIPv4Addr(addr string) error {
	var stat C.SPF_errcode_t
	stat = C.SPF_request_set_ipv4_str(r.r, C.CString(addr))
	if stat != C.SPF_E_SUCCESS {
		return &spfError{stat}
	}
	return nil
}

// SetEnvFrom sets the sender host
func (r *request) setEnvFrom(fromHost string) error {
	var stat C.int
	stat = C.SPF_request_set_env_from(r.r, C.CString(fromHost))
	if stat != C.int(C.SPF_E_SUCCESS) {
		return &spfError{C.SPF_errcode_t(stat)}
	}
	return nil
}

// Query starts the SPF query
func (r *Request) query() (*response, error) {
	var stat C.SPF_errcode_t
	var resp *C.SPF_response_t
	stat = C.SPF_request_query_mailfrom(r.r, &resp)
	if stat != C.SPF_E_SUCCESS {
		return nil, &spfError{stat}
	}
	return &response{resp}, nil
}

// Free the request handle
func (r *request) free() {
	if r.r != nil {
		C.SPF_request_free(r.r)
		r.r = nil
	}
}

type response struct {
	r *C.SPF_response_t
}

// Result returns the SPF validation result
func (r *response) result() result {
	return Result(C.SPF_response_result(r.r))
}

// Free frees the response handle
func (r *response) free() {
	if r.r != nil {
		C.SPF_response_free(r.r)
		r.r = nil
	}
}

type Result int

func (r Result) String() string {
	return C.GoString(C.SPF_strresult(C.SPF_result_t(r)))
}

type spfError struct {
	code C.SPF_errcode_t
}

func (e *spfError) Error() string {
	return C.GoString(C.SPF_strerror(e.code))
}

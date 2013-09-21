package libspf2

/*
#cgo LDFLAGS: -L/usr/local/lib -L/usr/lib -lspf2
#cgo CFLAGS: -g -O2 -Wno-error -I/usr/include -I/usr/local/include

#include <stdio.h>
#include <netdb.h>
#include <spf2/spf.h>
*/
import "C"

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

type Server struct {
	s *C.SPF_server_t
}

// NewServer creates a new server
func NewServer() *Server {
	srv := new(Server)
	srv.s = C.SPF_server_new(C.SPF_DNS_CACHE, 0)
	return srv
}

// Free frees the server handle
func (s *Server) Free() {
	if s.s != nil {
		C.SPF_server_free(s.s)
		s.s = nil
	}
}

type Request struct {
	s *Server
	r *C.SPF_request_t
}

// NewRequest creates a new SPF request
func NewRequest(s *Server) *Request {
	r := new(Request)
	r.s = s
	r.r = C.SPF_request_new(s.s)
	return r
}

// SetIPv4Addr sets the sender IPv4
func (r *Request) SetIPv4Addr(addr string) error {
	var stat C.SPF_errcode_t
	stat = C.SPF_request_set_ipv4_str(r.r, C.CString(addr))
	if stat != C.SPF_E_SUCCESS {
		return &spfError{stat}
	}
	return nil
}

// SetEnvFrom sets the sender host
func (r *Request) SetEnvFrom(fromHost string) error {
	var stat C.int
	stat = C.SPF_request_set_env_from(r.r, C.CString(fromHost))
	if stat != C.int(C.SPF_E_SUCCESS) {
		return &spfError{C.SPF_errcode_t(stat)}
	}
	return nil
}

// Query starts the SPF query
func (r *Request) Query() (*Response, error) {
	var stat C.SPF_errcode_t
	var resp *C.SPF_response_t
	stat = C.SPF_request_query_mailfrom(r.r, &resp)
	if stat != C.SPF_E_SUCCESS {
		return nil, &spfError{stat}
	}
	return &Response{resp}, nil
}

// Free the request handle
func (r *Request) Free() {
	if r.r != nil {
		C.SPF_request_free(r.r)
		r.r = nil
	}
}

type Response struct {
	r *C.SPF_response_t
}

// Result returns the SPF validation result
func (r *Response) Result() Result {
	return Result(C.SPF_response_result(r.r))
}

// Free frees the response handle
func (r *Response) Free() {
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

package matrix

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Libera-Chat/murdochite/bot/internal/set"
	"github.com/op/go-logging"
)

const (
	registrationEndpoint = "/_matrix/client/r0/register"
	wellKnownFileClient  = "/.well-known/matrix/client"
	wellKnownFileServer  = "/.well-known/matrix/server"

	smallLimit = 1 << 14
	bigLimit   = 1 << 16
)

// Errors returned from various bits of machinery
var (
	ErrNoExist = errors.New("requested resource does not exist")
	Err404     = errors.New("404 while getting registration") // nolint:errname // It is, you're just bad.
)

type delegateCacheEntry struct {
	target string
	time   time.Time
}

// NewScanner creates a new matrix scanner with the given logger
func NewScanner(logger *logging.Logger, cacheTimeout time.Duration) *Scanner {
	return &Scanner{
		log:                  logger,
		delegateCacheTimeout: cacheTimeout,
		delegateCache:        make(map[string]delegateCacheEntry),
		dCacheMu:             sync.Mutex{},
	}
}

// Scanner provides a frontend to scan matrix servers for bad behaviour
type Scanner struct {
	log                  *logging.Logger
	delegateCacheTimeout time.Duration
	delegateCache        map[string]delegateCacheEntry
	dCacheMu             sync.Mutex
}

// ScanServer asks the given server for its available flows, and returns whether or not any flow matched badFlows
func (m *Scanner) ScanServer(ctx context.Context, server string, badFlows []*set.StringSet) (bool, error) {
	res, err := m.ScanServerResult(ctx, server)
	if err != nil {
		return false, err
	}

	return res.AllowsUnverifiedRegistration(badFlows), nil
}

// ScanResult represents the result of a scan made using Scanner. Remarks may contain interesting (to a human)
// messages regarding the process
type ScanResult struct {
	*RegisterResult
	Homeserver   string
	Delegate     string
	DelegateType string
	Remarks      []string
}

// ScanServerResult returns a ScanResult for a given server scan, or an Error
func (m *Scanner) ScanServerResult(ctx context.Context, server string) (*ScanResult, error) {
	start := time.Now()
	outResult := &ScanResult{Homeserver: server}
	server = httpsPrefixIfNotExist(server)

	delegate, delegateType, err := m.GetServerDelegate(ctx, server)
	if err != nil {
		// TODO: Try with the original server anyway
		return nil, fmt.Errorf("could not get delegate server: %w", err)
	}

	outResult.DelegateType = delegateType

	if delegate != server {
		m.log.Debugf("homeserver %q delegates requests to %q", server, delegate)
		outResult.Delegate = delegate
	}

	if trimmed := strings.TrimRight(delegate, "/"); trimmed != delegate {
		m.log.Debugf("Stripping trailing /s from delegate")

		delegate = trimmed
	}

	registrationData, err := m.getRegistrationData(ctx, delegate)
	if err != nil {
		return nil, err
	}

	outResult.RegisterResult = registrationData

	for i, f := range registrationData.Flows {
		m.log.Debugf("\t %02d: %s", i, strings.Join(f.Stages, ", "))
	}

	if registrationData.Error != "" {
		m.log.Debugf("Error returned: %q: %s", registrationData.ErrorCode, registrationData.Error)
	} else if len(registrationData.Flows) == 0 {
		m.log.Debugf("\t xx: Has no listed registration flows?")
		m.log.Debugf("\t xx: %#v", registrationData)
		outResult.Remarks = append(outResult.Remarks, "Appears to have no registration flows")
	}

	outResult.Remarks = append(outResult.Remarks, fmt.Sprintf("Scan completed in %s", time.Since(start)))

	return outResult, nil
}

func (m *Scanner) getRegistrationData(ctx context.Context, server string) (*RegisterResult, error) {
	request, err := http.NewRequestWithContext(
		ctx, "POST", server+registrationEndpoint, strings.NewReader("{}"),
	)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}

	result, err := getClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("unable to make POST request: %w", err)
	}

	defer result.Body.Close()

	if result.StatusCode == 404 {
		return nil, Err404
	}

	data, err := io.ReadAll(io.LimitReader(result.Body, bigLimit))
	if err != nil {
		return nil, fmt.Errorf("unable to read HTTP body: %w", err)
	}

	regData := &RegisterResult{}

	if err := json.Unmarshal(data, regData); err != nil {
		// The json was somehow invalid, drop the error

		toSend := data
		if len(toSend) > 128 {
			toSend = toSend[:128]
		}

		m.log.Debugf("Bad json; Data as follows:\n\t%s", toSend)

		return nil, fmt.Errorf("could not unmarshal registration data: %w", err)
	}

	return regData, nil
}

func (m *Scanner) getDCache(name string) (delegateCacheEntry, bool) {
	m.dCacheMu.Lock()
	defer m.dCacheMu.Unlock()

	res, ok := m.delegateCache[name]

	if ok && time.Since(res.time) >= m.delegateCacheTimeout {
		// Remove it if it exists and its time is over
		delete(m.delegateCache, name)

		return delegateCacheEntry{}, false
	}

	return res, ok
}

func (m *Scanner) cacheDelegate(name, target string) string {
	m.dCacheMu.Lock()
	defer m.dCacheMu.Unlock()
	m.delegateCache[name] = delegateCacheEntry{
		target: target,
		time:   time.Now(),
	}

	return target
}

func httpsPrefixIfNotExist(s string) string {
	if !strings.HasPrefix(s, "http") {
		return "https://" + s
	}

	return s
}

// json. you're annoying. if you're going to return special errors, PLEASE make them support is
func isSyntaxError(err error) bool {
	syntaxError := &json.SyntaxError{}

	return errors.As(err, &syntaxError)
}

func errorsAre(errs, toCheck []error) bool {
outer:
	for _, err := range errs {
		for _, cerr := range toCheck {
			if errors.Is(err, cerr) {
				continue outer
			}
		}

		return false
	}

	return true
}

// GetServerDelegate returns the "real" host for a given homeserver
func (m *Scanner) GetServerDelegate(ctx context.Context, server string) (
	delegate string, delegateType string, err error,
) {
	var (
		httpClientErr error
		httpServerErr error
		srvErr        error
		result        string
	)

	clientCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	if result, httpClientErr = m.getServerDelegateHTTPClient(clientCtx, server); httpClientErr == nil {
		return m.cacheDelegate(server, httpsPrefixIfNotExist(result)), "httpClient", nil
	}

	m.log.Debugf("HTTP Error when getting server delegate /client: %q", httpClientErr)

	serverCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	if result, httpServerErr = m.getServerDelegateHTTPServer(serverCtx, server); httpServerErr == nil {
		return m.cacheDelegate(server, httpsPrefixIfNotExist(result)), "httpServer", nil
	}

	m.log.Debugf("HTTP Error when getting server delegate /server: %q", httpClientErr)

	srvCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	if result, srvErr = m.getServerDelegateSRV(srvCtx, server); srvErr == nil {
		return m.cacheDelegate(server, httpsPrefixIfNotExist(result)), "SRV", nil
	}

	m.log.Debugf("SRV Error when getting server delegate: %q", srvErr)

	// everyone errored, if its all not-found type things, return the original server
	if errorsAre([]error{httpClientErr, httpServerErr, srvErr}, []error{ErrNoExist, context.DeadlineExceeded}) {
		m.log.Debugf("request %q errored in expected ways, returning original name", server)

		return server, "", nil
	}

	if res, ok := m.getDCache(server); ok {
		m.log.Debugf("%q exists in delegate cache (%q), using that as errors occurred above", server, res.target)

		return res.target, "cached", nil
	}

	m.log.Debugf("request %q errored in unexpected ways, returning error", server)

	return server, "errored", fmt.Errorf(
		"could not find delegate: C:%w + S:%v + SRV:%v", httpClientErr, httpServerErr, srvErr.Error(),
	)
}

func (m *Scanner) fetchPathCtx(ctx context.Context, server, path string) ([]byte, error) {
	target := server + path

	m.log.Debugf("Getting %q", target)

	req, err := http.NewRequestWithContext(ctx, "GET", target, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("could not create request: %w", err)
	}

	res, err := getClient().Do(req)
	if err != nil {
		urlErr := &url.Error{}

		ok := errors.As(err, &urlErr)
		if !ok {
			return nil, fmt.Errorf("unable to execute request: %w", err)
		}

		// was this because we timed out?
		if urlErr.Timeout() {
			// yes, so assume this doesnt exist
			return nil, ErrNoExist
		}

		// we didn't timeout, but still errored, so still give the error back
		return nil, fmt.Errorf("unable to execute request: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		m.log.Debugf("non-200 response from %q: %d (%s)", target, res.StatusCode, res.Status)

		return nil, ErrNoExist
	}

	// if your response to this is larger than 16384 bytes I have very, very, VERY many questions, but will still bail
	// regardless.
	data, err := io.ReadAll(io.LimitReader(res.Body, smallLimit))
	if err != nil {
		return nil, fmt.Errorf("unable to read all data from request body: %w", err)
	}

	return data, nil
}

func (m *Scanner) getServerDelegateHTTPClient(ctx context.Context, server string) (string, error) {
	data, err := m.fetchPathCtx(ctx, server, wellKnownFileClient)
	if err != nil {
		return "", err
	}

	unmarshalled := &struct {
		Server struct {
			URI string `json:"base_url"` //nolint:tagliatelle // Its spec stuff.
		} `json:"m.homeserver"` //nolint:tagliatelle // Its spec stuff.
	}{}

	if err := json.Unmarshal(data, unmarshalled); err != nil {
		if isSyntaxError(err) {
			// Some hosts return 200 with bad json, dont let that stop us
			return "", fmt.Errorf("%w: %s", ErrNoExist, err)
		}

		return "", fmt.Errorf("unable to unmarshal JSON: %w", err)
	}

	if strings.TrimSpace(unmarshalled.Server.URI) == "" {
		return "", ErrNoExist
	}

	return unmarshalled.Server.URI, nil
}

func (m *Scanner) getServerDelegateHTTPServer(ctx context.Context, server string) (string, error) {
	data, err := m.fetchPathCtx(ctx, server, wellKnownFileServer)
	if err != nil {
		return "", err
	}

	unmarshalled := &struct {
		URI string `json:"m.server"` //nolint:tagliatelle // Its spec stuff.
	}{}

	if err := json.Unmarshal(data, unmarshalled); err != nil {
		if isSyntaxError(err) {
			// Some hosts return 200 with bad json, dont let that stop us
			return "", fmt.Errorf("%w: %s", ErrNoExist, err)
		}
		return "", fmt.Errorf("unable to unmarshal JSON: %w", err)
	}

	if strings.TrimSpace(unmarshalled.URI) == "" {
		return "", ErrNoExist
	}

	return unmarshalled.URI, nil
}

// Check if the SRV record exists
func (m *Scanner) getServerDelegateSRV(ctx context.Context, server string) (string, error) {
	u, err := url.Parse(server)
	if err != nil {
		return "", fmt.Errorf("could not parse %q as URL: %w", server, err)
	}

	_, addrs, err := net.DefaultResolver.LookupSRV(ctx, "matrix", "tcp", u.Hostname())
	if err != nil {
		if len(addrs) == 0 {
			// Yes this kills the other error.
			return "", fmt.Errorf("%w: %s", ErrNoExist, fmt.Errorf("unable to lookup SRV: %w (%+[1]v)", err))
		}

		// In this case there was at least one valid SRV response, use that, but log the error
		m.log.Debugf("Got some bad records when looking up SRV for %q: %s (%+[2]v)", server, err)
	}

	if len(addrs) == 0 {
		return net.JoinHostPort(addrs[0].Target, strconv.Itoa(int(addrs[0].Port))), nil
	}

	return "", ErrNoExist
}

// RegisterResult is the json blob returned from the registration endpoint
type RegisterResult struct {
	Session string `json:"session"`
	Flows   []struct {
		Stages []string `json:"stages"`
	} `json:"flows"`

	Error     string `json:"error"`
	ErrorCode string `json:"errcode"`
}

func stageMatchesAny(stage []string, toCheck ...*set.StringSet) bool {
	stageSet := set.New(stage...)

	for _, tc := range toCheck {
		if tc.Difference(stageSet).Length() == 0 {
			return true
		}
	}

	return false
}

// AllowsUnverifiedRegistration returns whether or not this result allows for unverified registration based on
// the passed list of bad flow sets
func (r *RegisterResult) AllowsUnverifiedRegistration(badflows []*set.StringSet) bool {
	for _, flow := range r.Flows {
		if stageMatchesAny(flow.Stages, badflows...) {
			return true
		}
	}

	return false
}

func getClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // its intentional
		},
	}
}

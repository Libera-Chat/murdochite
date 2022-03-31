package bot

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
	registrationEndpoint = "/_matrix/client/v3/register"
	wellKnownFile        = "/.well-known/matrix/server"

	smallLimit = 1 << 14
	bigLimit   = 1 << 16
)

var (
	log        = logging.MustGetLogger("matrix")
	errNoExist = errors.New("requested resource does not exist")
)

type delegateCacheEntry struct {
	target string
	time   time.Time
}

// NewMatrixScanner creates a new matrix scanner with the given logger
func NewMatrixScanner(logger *logging.Logger, cacheTimeout time.Duration) *MatrixScanner {
	return &MatrixScanner{
		log:                  logger,
		delegateCacheTimeout: cacheTimeout,
		delegateCache:        make(map[string]delegateCacheEntry),
		dCacheMu:             sync.Mutex{},
	}
}

// MatrixScanner provides a frontend to scan matrix servers for bad behaviour
type MatrixScanner struct {
	log                  *logging.Logger
	delegateCacheTimeout time.Duration
	delegateCache        map[string]delegateCacheEntry
	dCacheMu             sync.Mutex
}

// ScanServer asks the given server for its available flows, and returns whether or not any flow matched badFlows
func (m *MatrixScanner) ScanServer(ctx context.Context, server string, badFlows []*set.StringSet) (bool, error) {
	server = httpsPrefixIfNotExist(server)

	delegate, err := m.GetServerDelegate(ctx, server)
	if err != nil {
		// TODO: Try with the original server anyway
		return false, fmt.Errorf("could not get delegate server: %w", err)
	}

	if delegate != server {
		m.log.Debugf("homeserver %q delegates requests to %q", server, delegate)
	}

	registrationData, err := m.getRegistrationData(ctx, delegate)
	if err != nil {
		return false, err
	}

	for i, f := range registrationData.Flows {
		log.Debugf("\t %02d: %s", i, strings.Join(f.Stages, ", "))
	}

	if registrationData.Error != "" {
		log.Debugf("Error returned: %q: %s", registrationData.ErrorCode, registrationData.Error)
	} else if len(registrationData.Flows) == 0 {
		log.Debugf("\t xx: Has no listed registration flows?")
		log.Debugf("\t xx: %#v", registrationData)
	}

	return registrationData.allowsUnverifiedRegistration(badFlows), nil
}

func (m *MatrixScanner) getRegistrationData(ctx context.Context, server string) (*registerResult, error) {
	request, err := http.NewRequestWithContext(
		ctx, "POST", server+registrationEndpoint, strings.NewReader(("{}")),
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
		return nil, err404
	}

	data, err := io.ReadAll(io.LimitReader(result.Body, bigLimit))
	if err != nil {
		return nil, fmt.Errorf("unable to read HTTP body: %w", err)
	}

	regData := &registerResult{}

	if err := json.Unmarshal(data, regData); err != nil {
		// The json was somehow invalid, drop the error

		toSend := data
		if len(toSend) > 128 {
			toSend = toSend[:128]
		}

		log.Debugf("Bad json; Data as follows:\n\t%s", toSend)

		return nil, fmt.Errorf("could not unmarshal registration data: %w", err)
	}

	return regData, nil
}

func (m *MatrixScanner) getDCache(name string) (delegateCacheEntry, bool) {
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

func (m *MatrixScanner) cacheDelegate(name, target string) string {
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

// GetServerDelegate returns the "real" host for a given homeserver
func (m *MatrixScanner) GetServerDelegate(ctx context.Context, server string) (string, error) {
	result, httpErr := m.getServerDelegateHTTP(ctx, server)
	if httpErr == nil {
		return m.cacheDelegate(server, httpsPrefixIfNotExist(result)), nil
	}

	m.log.Debugf("HTTP Error when getting server delegate: %q", httpErr)

	result, srvErr := m.getServerDelegateSRV(ctx, server)
	if srvErr == nil {
		return m.cacheDelegate(server, httpsPrefixIfNotExist(result)), nil
	}

	m.log.Debugf("SRV Error when getting server delegate: %q", srvErr)

	// Both errored. We're gonna return our own error unless BOTH responses are errNoExist
	if errors.Is(httpErr, errNoExist) && errors.Is(srvErr, errNoExist) {
		return server, nil // Neither of these existed, thus the correct host is the original one
	}

	if res, ok := m.getDCache(server); ok {
		m.log.Debugf("%q exists in delegate cache (%q), using that as errors occurred above", server, res.target)

		return res.target, nil
	}

	return server, fmt.Errorf("could not find delegate: %w + %v", httpErr, srvErr.Error())
}

func (m *MatrixScanner) getServerDelegateHTTP(ctx context.Context, server string) (string, error) {
	target := server + wellKnownFile

	m.log.Debugf("Getting %q", target)

	req, err := http.NewRequestWithContext(ctx, "GET", target, http.NoBody)
	if err != nil {
		return "", fmt.Errorf("could not create request: %w", err)
	}

	res, err := getClient().Do(req)
	if err != nil {
		urlErr := &url.Error{}

		ok := errors.As(err, &urlErr)
		if !ok {
			return "", fmt.Errorf("unable to execute request: %w", err)
		}

		// was this because we timed out?
		if urlErr.Timeout() {
			// yes, so assume this doesnt exist
			return "", errNoExist
		}

		// we didn't timeout, but still errored, so still give the error back
		return "", fmt.Errorf("unable to execute request: %w", err)
	}

	defer res.Body.Close()

	if res.StatusCode != 200 {
		m.log.Debugf("non-200 response from %q: %d (%s)", target, res.StatusCode, res.Status)

		return "", errNoExist
	}

	// if your response to this is larger than 16384 bytes I have very, very, VERY many questions, but will still bail
	// regardless.
	data, err := io.ReadAll(io.LimitReader(res.Body, smallLimit))
	if err != nil {
		return "", fmt.Errorf("unable to read all data from request body: %w", err)
	}

	unmarshalled := &struct {
		Server string `json:"m.server"` //nolint:tagliatelle // Its spec stuff.
	}{}

	if err := json.Unmarshal(data, unmarshalled); err != nil {
		return "", fmt.Errorf("unable to unmarshal JSON: %w", err)
	}

	return unmarshalled.Server, nil
}

// Check if the SRV record exists
func (*MatrixScanner) getServerDelegateSRV(ctx context.Context, server string) (string, error) {
	_, addrs, err := net.LookupSRV("matrix", "tcp", server)
	if err != nil {
		// Yes this kills the other error.
		return "", fmt.Errorf("%w: %s", errNoExist, fmt.Errorf("unable to lookup SRV: %w", err))
	}

	if len(addrs) == 0 {
		return net.JoinHostPort(addrs[0].Target, strconv.Itoa(int(addrs[0].Port))), nil
	}

	return "", errNoExist
}

type registerResult struct {
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

func (r *registerResult) allowsUnverifiedRegistration(badflows []*set.StringSet) bool {
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

var err404 = errors.New("404 while getting registration")

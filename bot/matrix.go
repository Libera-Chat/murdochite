package bot

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"awesome-dragon.science/go/murdochite/bot/internal/set"
	"github.com/op/go-logging"
)

const (
	registrationEndpoint = "/_matrix/client/v3/register"
	wellKnownFile        = "/.well-known/matrix/server"

	smallLimit = 1 << 14
	bigLimit   = 1 << 16
)

var log = logging.MustGetLogger("matrix")

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

// returns true if the homeserver allows unverified registration
func badHomeServer(ctx context.Context, location string, badFlows []*set.StringSet) (bool, error) {
	regData, err := getRegistrationData(ctx, location)
	if err != nil {
		return false, err
	}

	log.Debugf("Homeserver at %s has the following flows:", location)

	for i, f := range regData.Flows {
		log.Debugf("\t %02d: %s", i, strings.Join(f.Stages, ", "))
	}

	return regData.allowsUnverifiedRegistration(badFlows), nil
}

var err404 = errors.New("404 while getting registration")

func getRegistrationData(ctx context.Context, location string) (*registerResult, error) {
	if !strings.HasPrefix(location, "http") {
		location = "https://" + location
	}

	realHomeserverLocation, err := getHomeserverLocation(ctx, location)
	if err != nil {
		return nil, fmt.Errorf("unable to get homeserver's true location: %w", err)
	}

	log.Debugf("Real location: %q", realHomeserverLocation)

	req, err := http.NewRequestWithContext(
		ctx, "POST", realHomeserverLocation+registrationEndpoint, strings.NewReader("{}"),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create request: %w", err)
	}

	res, err := getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("unable to make POST request: %w", err)
	}

	if res.StatusCode == 404 {
		return nil, err404
	}

	defer res.Body.Close()

	data, err := io.ReadAll(io.LimitReader(res.Body, bigLimit))
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

func getHomeserverLocation(ctx context.Context, location string) (string, error) {
	log.Debugf("Getting %q\n", location+wellKnownFile)

	request, err := http.NewRequestWithContext(ctx, "GET", location+wellKnownFile, http.NoBody)
	if err != nil {
		return "", err
	}

	result, err := getClient().Do(request)
	if err != nil {
		urlErr := &url.Error{}

		ok := errors.As(err, &urlErr)
		if !ok {
			return "", err
		}

		// was this because we timed out?
		if urlErr.Timeout() {
			// yes, so assume this doesnt exist
			return location, nil
		}
		// we didnt timeout, but still errored, so still give the error back
		return "", err
	}

	defer result.Body.Close()

	if result.StatusCode != 200 {
		log.Debugf("Assuming %q has no well known for location", location)

		return location, nil
	}

	// if your response to this is larger than 16384 bytes I have very, very, VERY many questions, but will still bail
	// regardless.
	data, err := io.ReadAll(io.LimitReader(result.Body, smallLimit))
	if err != nil {
		return "", err
	}

	unmarshalled := &struct {
		Server string `json:"m.server"`
	}{}

	if err := json.Unmarshal(data, unmarshalled); err != nil {
		return "", err
	}

	return "https://" + unmarshalled.Server, nil
}

package bot

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"

	"awesome-dragon.science/go/mls/bot/internal/set"
	"github.com/op/go-logging"
)

const (
	registrationEndpoint = "/_matrix/client/v3/register"
	wellKnownFile        = "/.well-known/matrix/server"

	smallLimit = 1 << 14
	bigLimit   = 1 << 16
)

var checks = []*set.StringSet{
	set.New("m.login.dummy"),
	set.New("m.login.dummy", "m.login.recaptcha"),
}

var log = logging.MustGetLogger("matrix")

type registerResult struct {
	Session string `json:"session"`
	Flows   []struct {
		Stages []string `json:"stages"`
	} `json:"flows"`
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

func (r *registerResult) allowsUnverifiedRegistration() bool {
	for _, flow := range r.Flows {
		if stageMatchesAny(flow.Stages, checks...) {
			return true
		}
	}

	return false
}

// returns true if the homeserver allows unverified registration
func badHomeServer(ctx context.Context, location string) (bool, error) {
	if !strings.HasPrefix(location, "http") {
		location = "https://" + location
	}

	realHomeserverLocation, err := getHomeserverLocation(ctx, location)
	if err != nil {
		return false, err
	}

	log.Debugf("Real location: %q", realHomeserverLocation)

	req, err := http.NewRequestWithContext(
		ctx, "POST", realHomeserverLocation+registrationEndpoint, strings.NewReader("{}"),
	)
	if err != nil {
		return false, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	data, err := io.ReadAll(io.LimitReader(res.Body, bigLimit))
	if err != nil {
		return false, err
	}

	log.Debugf("Resulting data: %q", string(data))

	regData := &registerResult{}

	if err := json.Unmarshal(data, regData); err != nil {
		// The json was somehow invalid, drop the error
		return false, err
	}

	log.Debugf("Unmarshalled: %v", regData)

	return regData.allowsUnverifiedRegistration(), nil
}

func getHomeserverLocation(ctx context.Context, location string) (string, error) {
	log.Debugf("Getting %q\n", location+wellKnownFile)

	request, err := http.NewRequestWithContext(ctx, "GET", location+wellKnownFile, nil)
	if err != nil {
		return "", err
	}

	result, err := http.DefaultClient.Do(request)
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

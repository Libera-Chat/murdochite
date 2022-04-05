package bot

import (
	"errors"
	"fmt"
	"strings"
)

// ActionConfig represents a config for an action
type ActionConfig struct {
	Type         string `toml:"type"`
	Message      string `toml:"message"`
	Duration     int    `toml:"duration"`
	IgnoreSASLed bool   `toml:"ignore_sasl"`
}

func (a ActionConfig) String() string {
	return fmt.Sprintf("%q: Duration: %d | IgnoreSASL: %t | Msg: %q", a.Type, a.Duration, a.IgnoreSASLed, a.Message)
}

func userIsSASL(accountName string) bool {
	return accountName != "*"
}

// ErrInvalidActionConfig is returned when an action config is invalid
var ErrInvalidActionConfig = errors.New("invalid action config")

// GetAction returns an Action for the given config, or an error
func GetAction(config ActionConfig) (Action, error) {
	if config.Type == "" {
		return nil, fmt.Errorf("%w: empty type", ErrInvalidActionConfig)
	}

	if strings.TrimSpace(config.Message) == "" {
		return nil, fmt.Errorf("%w: cannot have empty message", ErrInvalidActionConfig)
	}

	if config.Duration == 0 {
		return nil, fmt.Errorf("%w: cannot have 0 minutes as duration", ErrInvalidActionConfig)
	}

	switch strings.ToLower(config.Type) {
	case "kline":
		return KLineAction{ActionConfig: config}, nil
	case "xline":
		return XLineAction{ActionConfig: config}, nil
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidActionConfig, config.Type)
	}
}

// ErrOnlyMatchScannedUser is returned from any action that will ignore non-scanned users
var ErrOnlyMatchScannedUser = errors.New("acts on scanned users only")

// Action is any action that can be taken on a scanned user.
type Action interface {
	Execute(nick, ident, host, ip, realname, homeserver, account string, userWasScanned bool) ([]string, error)
	fmt.Stringer
}

// KLineAction klines a given user@host
type KLineAction struct {
	ActionConfig
}

// Execute implements the Action interface
func (k KLineAction) Execute(_, ident, _, ip, _, _, account string, userWasScanned bool) ([]string, error) {
	if k.IgnoreSASLed && userIsSASL(account) {
		return nil, nil
	}

	if ident == "" {
		return nil, errors.New("invalid ident") //nolint:goerr113 // I dont want a specific error here
	}

	var mask string
	if len(ident) > 0 && ident[0] == '~' {
		mask = "*@" + ip
	} else {
		mask = ident + "@" + ip
	}

	return []string{fmt.Sprintf("KLINE %d %s :%s", k.Duration, mask, k.Message)}, nil
}

// XLineAction X-Lines the homeserver on which a user sits
type XLineAction struct {
	ActionConfig
}

// Execute implements the Action interface
func (x XLineAction) Execute(_, _, _, _, _, homeserver, account string, userWasScanned bool) ([]string, error) {
	if !userWasScanned {
		return nil, ErrOnlyMatchScannedUser
	}

	if x.IgnoreSASLed && userIsSASL(account) {
		return nil, nil
	}

	if homeserver == "" {
		return nil, fmt.Errorf("refusing to ban empty homeserver: %w", ErrInvalidHSName)
	}

	if strings.EqualFold(strings.TrimSpace(homeserver), "matrix.org") {
		return nil, fmt.Errorf("refusing to ban matrix.org: %w", ErrInvalidHSName)
	}

	target := generateXLineTarget(homeserver)

	command := fmt.Sprintf("XLINE %d %s :%s", x.Duration, target, x.Message)

	return []string{command}, nil
}

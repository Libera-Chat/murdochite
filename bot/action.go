package bot

import (
	"errors"
	"fmt"
	"strings"
	"text/template"
)

// ActionArgs contains all the info passed to action implementations
type ActionArgs struct {
	Nick           string
	Ident          string
	Host           string
	Account        string
	IP             string
	RealName       string
	HomeServer     string
	UserWasScanned bool

	Log func(message string)
}

// ActionConfig represents a config for an action
type ActionConfig struct {
	Type         string `toml:"type"`
	Message      string `toml:"message"`
	Duration     int    `toml:"duration"`
	IgnoreSASLed bool   `toml:"ignore_sasl"`
	Enabled_     bool   `toml:"enabled"` //nolint:revive // Its a backing value, and has to be exported
}

func (a ActionConfig) String() string {
	return fmt.Sprintf(
		"%q: Duration: %d | IgnoreSASL: %t | Msg: %q  | Enabled: %t",
		a.Type,
		a.Duration,
		a.IgnoreSASLed,
		a.Message,
		a.Enabled_,
	)
}

func userIsSASL(accountName string) bool {
	return accountName != "*"
}

// Enabled returns whether or not this action is enabled
func (a *ActionConfig) Enabled() bool { return a.Enabled_ }

// Toggle toggles the enabled state on this Action
func (a *ActionConfig) Toggle() { a.Enabled_ = !a.Enabled_ }

// ErrInvalidActionConfig is returned when an action config is invalid
var ErrInvalidActionConfig = errors.New("invalid action config")

// GetAction returns an Action for the given config, or an error
func GetAction(config ActionConfig) (Action, error) { //nolint:ireturn // Its a fetch function
	if config.Type == "" {
		return nil, fmt.Errorf("%w: empty type", ErrInvalidActionConfig)
	}

	if strings.TrimSpace(config.Message) == "" {
		return nil, fmt.Errorf("%w: cannot have empty message", ErrInvalidActionConfig)
	}

	switch strings.ToLower(config.Type) {
	case "kline":
		return &KLineAction{ActionConfig: config}, nil

	case "xline":
		return &XLineAction{ActionConfig: config}, nil

	case "warn":
		return newWarnAction(config)

	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrInvalidActionConfig, config.Type)
	}
}

// ErrOnlyMatchScannedUser is returned from any action that will ignore non-scanned users
var ErrOnlyMatchScannedUser = errors.New("acts on scanned users only")

// Action is any action that can be taken on a scanned user.
type Action interface {
	Execute(args *ActionArgs) ([]string, error)
	Enabled() bool
	Toggle()
	fmt.Stringer
}

// KLineAction klines a given user@host
type KLineAction struct {
	ActionConfig
}

// Execute implements the Action interface
func (k KLineAction) Execute(args *ActionArgs) ([]string, error) {
	if k.IgnoreSASLed && userIsSASL(args.Account) {
		return nil, nil
	}

	if args.Ident == "" {
		return nil, errors.New("invalid ident") //nolint:goerr113 // I dont want a specific error here
	}

	var mask string
	if len(args.Ident) > 0 && args.Ident[0] == '~' {
		mask = "*@" + args.IP
	} else {
		mask = args.Ident + "@" + args.IP
	}

	return []string{fmt.Sprintf("KLINE %d %s :%s", k.Duration, mask, k.Message)}, nil
}

// XLineAction X-Lines the homeserver on which a user sits
type XLineAction struct {
	ActionConfig
}

// Execute implements the Action interface
func (x XLineAction) Execute(args *ActionArgs) ([]string, error) {
	if !args.UserWasScanned {
		return nil, ErrOnlyMatchScannedUser
	}

	if x.IgnoreSASLed && userIsSASL(args.Account) {
		return nil, nil
	}

	if args.HomeServer == "" {
		return nil, fmt.Errorf("refusing to ban empty homeserver: %w", ErrInvalidHSName)
	}

	if strings.EqualFold(strings.TrimSpace(args.HomeServer), "matrix.org") {
		return nil, fmt.Errorf("refusing to ban matrix.org: %w", ErrInvalidHSName)
	}

	target := generateXLineTarget(args.HomeServer)

	command := fmt.Sprintf("XLINE %d %s :%s", x.Duration, target, x.Message)

	return []string{command}, nil
}

func newWarnAction(config ActionConfig) (*WarnAction, error) {
	templ, err := template.New("warn_action_message").Parse(config.Message)
	if err != nil {
		return nil, fmt.Errorf("cannot parse config for warn action: %w", err)
	}

	templ.Funcs(template.FuncMap{
		"generateXLineTarget": generateXLineTarget,
		"generateKlineTarget": func(ident, host string) string {
			if len(ident) > 0 && ident[0] != '~' {
				return fmt.Sprintf("%s@%s", ident, host)
			}

			return fmt.Sprintf("*@%s", host)
		},
	})

	return &WarnAction{
		ActionConfig: config,
		template:     templ,
	}, nil
}

// WarnAction works by using a go format template to set what information is sent to the bots log channel
type WarnAction struct {
	ActionConfig
	template *template.Template
}

// Execute Implements Action
func (w *WarnAction) Execute(args *ActionArgs) ([]string, error) {
	buf := &strings.Builder{}
	if err := w.template.Execute(buf, args); err != nil {
		return nil, fmt.Errorf("could not execute template: %w", err)
	}

	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		args.Log(line)
	}

	return nil, nil
}

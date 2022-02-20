package bot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"awesome-dragon.science/go/irc/client"
	"awesome-dragon.science/go/irc/connection"
	"awesome-dragon.science/go/irc/event"
	"awesome-dragon.science/go/irc/event/chatcommand"
	"awesome-dragon.science/go/irc/event/function"
	"awesome-dragon.science/go/irc/event/irccommand"
	"awesome-dragon.science/go/irc/event/multi"
	"awesome-dragon.science/go/irc/event/servernotice"
	"awesome-dragon.science/go/irc/numerics"
	"awesome-dragon.science/go/irc/oper"
	operperm "awesome-dragon.science/go/irc/permissions/oper"
	"awesome-dragon.science/go/murdochite/bot/internal/set"
	"github.com/op/go-logging"
)

type scanState int

const (
	scanInProgress scanState = iota
	scanComplete
)

//nolint:gochecknoglobals // They're constants but go being go
var (
	//nolint:lll // cant be made shorter
	snoteRe  = regexp.MustCompile(`^\*{3} Notice -- Client connecting: (?P<nick>\S+) \((?P<ident>[^@]+)@(?P<host>[^)]+)\) \[(?P<ip>\S+)\] \{(?P<class>[^}]+)\} <(?P<account>[^>]+)> \[(?P<gecos>.*)\]$`)
	nickLoc  = snoteRe.SubexpIndex("nick")
	identLoc = snoteRe.SubexpIndex("ident")
	hostLoc  = snoteRe.SubexpIndex("host")
	// accountLog = snoteRe.SubexpIndex("account")
	ipLoc    = snoteRe.SubexpIndex("ip")
	gecosLoc = snoteRe.SubexpIndex("gecos")

	matrixRange = func() *net.IPNet {
		_, out, err := net.ParseCIDR("2001:470:69fc:105::/64")
		if err != nil {
			panic(err)
		}

		return out
	}()
)

type scanResult struct {
	state      scanState
	homeserver string
	scanTime   time.Time
	isOpenReg  bool
	resultWait chan struct{}
}

type Config struct {
	Connection connection.Config `toml:"connection"`

	Nick             string     `toml:"nick"`
	Ident            string     `toml:"ident"`
	Realname         string     `toml:"realname"`
	ServerPassword   string     `toml:"server_password"`
	ScanTimeoutHours int        `toml:"scan_timeout_hours"`
	BadFlows         [][]string `toml:"bad_flows"`
	LogChannel       string     `toml:"log_channel"`

	OperKeyPath   string `toml:"oper_key_path"`
	OperKeyPasswd string `toml:"oper_key_passwd"`
	OperName      string `toml:"oper_name"`

	NSUser   string `toml:"ns_user"`
	NSPasswd string `toml:"ns_passwd"`

	XLineDuration int    `toml:"xline_duration"`
	XlineMessage  string `toml:"xline_message"`

	Version string `toml:"-"`
}

type Bot struct {
	irc        *client.Client
	config     *Config
	ircLogChan string
	log        *logging.Logger

	mu       sync.Mutex
	cache    map[string]*scanResult
	badFlows []*set.StringSet

	// Handlers
	multiHandler   *multi.Handler
	ircHandler     *irccommand.Handler
	snoteHandler   *servernotice.Handler
	commandHandler *chatcommand.Handler

	ShouldRestart bool
}

// New creates a new bot instance.
func New(config *Config, log *logging.Logger) *Bot {
	badflows := []*set.StringSet{}

	for _, f := range config.BadFlows {
		badflows = append(badflows, set.New(f...))
	}

	if config.XLineDuration == 0 {
		config.XLineDuration = 60 * 24 * 30 // 1 month
	}

	if config.XlineMessage == "" {
		config.XlineMessage = "Your homeserver appears to allow unverified registration."
	}

	b := &Bot{
		irc: client.New(&client.Config{
			Connection:     config.Connection,
			ServerPassword: config.ServerPassword,
			Nick:           config.Nick,
			Username:       config.Ident,
			Realname:       config.Realname,
			SASLUsername:   config.NSUser,
			SASLPassword:   config.NSPasswd,
			RequestedCapabilities: []string{
				"sasl", "account-tag", "solanum.chat/identify-msg", "solanum.chat/oper", "solanum.chat/realhost",
			},
		}),
		ircLogChan: config.LogChannel,
		log:        log,
		cache:      make(map[string]*scanResult),
		badFlows:   badflows,
		config:     config,
	}

	if b.config.ScanTimeoutHours == 0 {
		b.config.ScanTimeoutHours = 1
	}

	b.setupHandlers()
	b.setupCommands()

	return b
}

func (b *Bot) setupHandlers() {
	b.multiHandler = &multi.Handler{}
	b.ircHandler = &irccommand.Handler{}     // for general stuff
	b.snoteHandler = &servernotice.Handler{} // to handle server notices

	b.snoteHandler.RegisterCallback(b.onSnote)

	b.multiHandler.AddHandlers(b.ircHandler, b.snoteHandler)
	b.multiHandler.AddHandlers(function.FuncHandler(func(msg *event.Message) error {
		if msg.Raw.Command != numerics.PRIVMSG {
			return nil
		}

		if msg.Raw.Params[0] != msg.CurrentNick {
			return nil
		}

		b.logToChannelf("PV: %s %s", msg.SourceUser.Mask(), msg.Raw.Params[len(msg.Raw.Params)-1])

		return nil
	}))

	b.irc.SetMessageHandler(b.multiHandler)
}

func (b *Bot) onSnote(d *servernotice.SnoteData) error {
	match := snoteRe.FindStringSubmatch(d.Message)
	if match == nil {
		return nil
	}

	ip := net.ParseIP(match[ipLoc])
	if ip == nil {
		// b.log.Warningf("Unable to parse %q as an IP address", ip)

		return nil
	}

	if !matrixRange.Contains(ip) {
		// Not a matrix conn
		return nil
	}

	go b.onMatrixConnection(
		match[nickLoc], match[identLoc], match[hostLoc], match[ipLoc], match[gecosLoc],
	)

	return nil
}

func (b *Bot) setupCommands() {
	b.commandHandler = &chatcommand.Handler{
		Prefix:      "~",
		MessageFunc: b.irc.SendNotice,
		PermissionHandler: &operperm.Handler{
			Opers: []operperm.Oper{
				{
					Name:        "*",
					Permissions: []string{"bot.admin", "bot.scan", "bot.status"},
				},
			},
		},
	}

	_ = b.commandHandler.AddCommand(
		"shutdown",
		"shutdown the bot",
		[]string{"bot.admin"},
		-1,
		func(a *chatcommand.Argument) error {
			b.Stop(a.ArgString())

			return nil
		},
	)

	_ = b.commandHandler.AddCommand(
		"scan", "Check the given homeserver for unverified registration", []string{"bot.scan"}, 1, b.manualScan,
	)

	_ = b.commandHandler.AddCommand(
		"Status", "Return general status about the bot", []string{"bot.status"}, -1, b.statuscmd,
	)

	_ = b.commandHandler.AddCommand("togglerawlog", "toggle console raw log", []string{"bot.admin"}, 0, b.toggleRawLog)
	_ = b.commandHandler.AddCommand("restart", "restarts the bot", []string{"bot.admin"}, 0, b.restartCmd)

	b.multiHandler.AddHandlers(b.commandHandler)
}

// Run starts the bot and connects it to IRC
func (b *Bot) Run(ctx context.Context) {
	go func() {
		if err := (b.irc.Run(ctx)); err != nil {
			b.log.Errorf("Error from client.Run: %s", err)
		}
	}()

	<-b.ircHandler.WaitFor(numerics.RPL_WELCOME)

	go b.cacheLoop(b.irc.DoneChan())

	if err := b.oper(); err != nil {
		b.log.Fatalf("Could not oper up: %s", err)
	}

	_ = b.irc.WriteIRC("JOIN", b.ircLogChan)

	b.irc.WaitForExit()
}

func (b *Bot) oper() error {
	c, err := oper.NewChallenge(b.config.OperKeyPath, b.config.OperKeyPasswd)
	if err != nil {
		return fmt.Errorf("could not create CHALLENGE: %w", err)
	}

	sh := &irccommand.SimpleHandler{}

	b.multiHandler.AddHandlers(sh)
	defer b.multiHandler.RemoveHandler(sh)

	if err := c.DoChallenge(sh, b.irc.WriteIRC, b.config.OperName); err != nil {
		return fmt.Errorf("could not oper: %w", err)
	}

	return nil
}

func (b *Bot) homeServerState(homeserver string) (*scanResult, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	lowered := strings.ToLower(homeserver)

	res, ok := b.cache[lowered]
	if !ok {
		newResult := &scanResult{
			homeserver: homeserver,
			state:      scanInProgress,
			resultWait: make(chan struct{}),
		}

		b.cache[lowered] = newResult

		return newResult, true
	}

	return res, false
}

func (b *Bot) logToChannelf(format string, args ...interface{}) {
	b.logToChannel(fmt.Sprintf(format, args...))
}

func (b *Bot) logToChannel(msg string) {
	if err := b.irc.SendMessage(b.ircLogChan, msg); err != nil {
		b.log.Errorf("Unable to log %q to %q: %s", msg, b.ircLogChan, err)
	}
}

func (b *Bot) onMatrixConnection(nick, ident, host, ip, realname string) {
	userLog := fmt.Sprintf("%s!%s@%s (%s | %s)", nick, ident, host, ip, realname)
	b.log.Infof("New matrix connection: %s", userLog)

	hs := realnameToHomeserver(realname)

	if hs == "" {
		b.log.Errorf("Could not convert %q to homeserver name", realname)
		b.logToChannelf("ERR: Invalid homeserver in realname %q (for %s)", realname, userLog)

		return
	}

	scanResult, newlyCreated := b.homeServerState(hs)
	if newlyCreated {
		// this was created for us, and thus we need to do a scan
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		b.log.Infof("Scanning homeserver %q...", hs)
		res, err := b.scan(ctx, hs)

		defer close(scanResult.resultWait)

		if err != nil {
			b.log.Errorf("Could not scan homeserver %q: %s", hs, err)

			if !errors.Is(err, err404) {
				go b.logToChannelf("ERR: Homeserver %q errored while scanning: %s", hs, err)
			}

			res = false
		}

		scanResult.isOpenReg = res
		scanResult.scanTime = time.Now()
		scanResult.state = scanComplete
	} else {
		b.log.Debugf("scan already exists for %q", hs)
	}

	if scanResult.state == scanInProgress {
		b.log.Debugf("Scan for %q already in progress, waiting", hs)
		<-scanResult.resultWait
	}

	if scanResult.isOpenReg {
		b.log.Infof("Homeserver %q is bad (from user %s)", hs, userLog)
		b.logToChannelf(
			"BAD: Matrix homeserver %q allows for unverified registration (based on connecting user %s)",
			hs,
			userLog,
		)

		b.xlineHomeserver(hs)
	} else {
		b.log.Infof("Homeserver %q is safe (or errored) (from user %s)", hs, userLog)
	}
}

func (b *Bot) checkCaches() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for name, c := range b.cache {
		if c.state == scanComplete && time.Since(c.scanTime) >= time.Hour*time.Duration(b.config.ScanTimeoutHours) {
			delete(b.cache, name)
		}
	}
}

func (b *Bot) cacheLoop(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			b.checkCaches()
		case <-stop:
			return
		}
	}
}

func (b *Bot) scan(ctx context.Context, homeserver string) (bool, error) {
	return badHomeServer(ctx, homeserver, b.badFlows)
}

func (b *Bot) xlineHomeserver(hs string) {
	b.log.Infof("X-Lining homeserver %s", hs)
}

func xlineEscape(s string) string {
	out := strings.Builder{}
	/*[08:31:40] * xline :The <gecos> field contains certain special characters:
	[08:31:40] * xline :  ? - Match any single character
	[08:31:40] * xline :  * - Many any characters
	[08:31:40] * xline :  @ - Match any letter [A-Za-z]
	[08:31:40] * xline :  # - Match any digit [0-9] */
	for _, r := range s {
		switch r {
		case '\\', '?', '*', '@', '#':
			out.WriteRune('\\')
			out.WriteRune(r)

		case ' ':
			out.WriteRune('\\')
			out.WriteRune('s')

		default:
			out.WriteRune(r)
		}
	}

	return out.String()
}

func realnameToHomeserver(realname string) string {
	// this is started in a goroutine, so we dont return anything here
	if realname == "" || realname[0] != '@' {
		return ""
	}

	if !strings.Contains(realname, ":") {
		return ""
	}

	split := strings.Split(realname, ":")

	return split[len(split)-1]
}

func (b *Bot) Stop(message string) {
	b.irc.Stop(message)
}

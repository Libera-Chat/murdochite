package bot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
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
	"github.com/Libera-Chat/murdochite/bot/internal/set"
	"github.com/Libera-Chat/murdochite/bot/internal/util"
	"github.com/op/go-logging"
)

type scanState int

const (
	scanInProgress scanState = iota
	scanComplete
	scanDroppedFromCache
)

//nolint:gochecknoglobals // They're constants but go being go
var (
	//nolint:lll // cant be made shorter
	snoteRe    = regexp.MustCompile(`^\*{3} Notice -- Client connecting: (?P<nick>\S+) \((?P<ident>[^@]+)@(?P<host>[^)]+)\) \[(?P<ip>\S+)\] \{(?P<class>[^}]+)\} <(?P<account>[^>]+)> \[(?P<gecos>.*)\]$`)
	nickLoc    = snoteRe.SubexpIndex("nick")
	identLoc   = snoteRe.SubexpIndex("ident")
	hostLoc    = snoteRe.SubexpIndex("host")
	accountLoc = snoteRe.SubexpIndex("account")
	ipLoc      = snoteRe.SubexpIndex("ip")
	gecosLoc   = snoteRe.SubexpIndex("gecos")
)

type ScanResult struct {
	state      scanState
	homeserver string
	scanTime   time.Time
	isOpenReg  bool
	resultWait chan struct{}
	// TODO: store the error on this struct for the log and later inspection
}

func (s *ScanResult) String() string {
	switch s.state {
	case scanInProgress:
		return fmt.Sprintf("Homeserver %q is currently being scanned", s.homeserver)

	case scanComplete:
		status := "allows unverified registration"
		if !s.isOpenReg {
			status = "does not allow unverified registration"
		}

		return fmt.Sprintf(
			"Homeserver %q was scanned at %s and %s", s.homeserver, s.scanTime.Format(time.RFC3339Nano), status,
		)

	case scanDroppedFromCache:
		return fmt.Sprintf("Homeserver %q is dropped from the cache and is unsafe to use.", s.homeserver)

	default:
		return "uninitialised scanResult? please report a bug."
	}
}

// IRCString is like String() but may include IRC formatting
func (s *ScanResult) IRCString() string {
	switch s.state {
	case scanInProgress:
		return fmt.Sprintf("Homeserver \x02%q\x02 is currently being scanned", s.homeserver)

	case scanComplete:
		status := "\x02allows unverified registration\x02"
		if !s.isOpenReg {
			status = "does \x02not\x02 allow unverified registration"
		}

		return fmt.Sprintf(
			"Homeserver \x02%q\x02 was scanned at \x02%s\x02 and %s", s.homeserver, s.scanTime.Format(time.RFC3339Nano), status,
		)

	case scanDroppedFromCache:
		return fmt.Sprintf("Homeserver \x02%q\x02 is dropped from the cache and is unsafe to use.", s.homeserver)

	default:
		return "\x02\x01D\x01Euninitialised scanResult? please report a bug.\x02\x01D\x01E"
	}
}

type Config struct {
	Connection connection.Config `toml:"connection"`

	Nick               string     `toml:"nick"`
	Ident              string     `toml:"ident"`
	Realname           string     `toml:"realname"`
	ServerPassword     string     `toml:"server_password"`
	ScanTimeoutHours   int        `toml:"scan_timeout_hours"`
	BadFlows           [][]string `toml:"bad_flows"`
	LogChannel         string     `toml:"log_channel"`
	VerboseLogChannel  string     `toml:"verbose_log_channel"`
	VerboseRedirectREs []string   `toml:"verbose_redirect"`

	OperKeyPath   string `toml:"oper_key_path"`
	OperKeyPasswd string `toml:"oper_key_passwd"`
	OperName      string `toml:"oper_name"`

	NSUser   string `toml:"ns_user"`
	NSPasswd string `toml:"ns_passwd"`

	Actions    []ActionConfig `toml:"actions"`
	LogOnly    bool           `toml:"log_only"`
	ScanRanges []string       `toml:"scan_ranges"`

	Version string `toml:"-"`
}

type Bot struct {
	irc            *client.Client
	config         *Config
	ircLogChan     string
	ircVLogChan    string
	redirectLogREs []*regexp.Regexp
	log            *logging.Logger

	mu            sync.Mutex
	cache         map[string]*ScanResult
	badFlows      []*set.StringSet
	matrixScanner *MatrixScanner
	scanRanges    []*net.IPNet
	actions       []Action

	// Handlers
	multiHandler   *multi.Handler
	ircHandler     *irccommand.Handler
	snoteHandler   *servernotice.Handler
	commandHandler *chatcommand.Handler

	ShouldRestart bool
}

// New creates a new bot instance.
func New(config *Config, log *logging.Logger) (*Bot, error) {
	badflows := []*set.StringSet{}

	for _, f := range config.BadFlows {
		badflows = append(badflows, set.New(f...))
	}

	if len(config.Actions) == 0 {
		return nil, fmt.Errorf("no actions enabled")
	}

	actions := make([]Action, len(config.Actions))

	for i, ac := range config.Actions {
		a, err := GetAction(ac)
		if err != nil {
			return nil, fmt.Errorf("could not create action %d: %w", i, err)
		}

		actions[i] = a
	}

	if config.VerboseLogChannel == "" {
		config.VerboseLogChannel = config.LogChannel
	}

	redirectRes := make([]*regexp.Regexp, len(config.VerboseRedirectREs))

	for i, v := range config.VerboseRedirectREs {
		res, err := regexp.Compile(v)
		if err != nil {
			return nil, fmt.Errorf("could not compile regexp %q: %w", v, err)
		}

		redirectRes[i] = res
	}

	scanRanges := []*net.IPNet{}

	if len(config.ScanRanges) == 0 {
		return nil, errors.New("no ranges to scan provided") //nolint:goerr113 // main error
	}

	for _, v := range config.ScanRanges {
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("unable to parse %q as a range: %w", v, err)
		}

		scanRanges = append(scanRanges, n)
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
		ircLogChan:     config.LogChannel,
		ircVLogChan:    config.VerboseLogChannel,
		redirectLogREs: redirectRes,
		log:            log,
		cache:          make(map[string]*ScanResult),
		matrixScanner:  NewMatrixScanner(logging.MustGetLogger("mtrx-scan"), time.Hour*24),
		badFlows:       badflows,
		config:         config,
		scanRanges:     scanRanges,
		actions:        actions,
	}

	if b.config.ScanTimeoutHours == 0 {
		b.config.ScanTimeoutHours = 1
	}

	b.setupHandlers()
	b.setupCommands()

	return b, nil
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
		return nil
	}

	isInRange := false

	for _, r := range b.scanRanges {
		if r.Contains(ip) {
			isInRange = true

			break
		}
	}

	if !isInRange {
		// not a matched conn
		return nil
	}

	go b.onMatrixConnection(
		match[nickLoc], match[identLoc], match[hostLoc], match[ipLoc], match[gecosLoc], match[accountLoc],
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
	_ = b.commandHandler.AddCommand(
		"getcache",
		"get the given homeservers from the cache, if they exist\n"+
			"If no homeserver is provided, the entire cache is dumped",
		[]string{"bot.status"},
		-1,
		b.getCache,
	)

	_ = b.commandHandler.AddCommand(
		"dropcache",
		"drop entries from the cache. If you want to drop the entire cache, use \x02DROPCACHE ALL\x02",
		[]string{"bot.admin"},
		-1,
		b.dropCache,
	)

	_ = b.commandHandler.AddCommand(
		"toggleaction",
		"Toggle teeth -- Note that for X-Line actions this does NOT affect cached hosts",
		[]string{"bot.admin"},
		0,
		b.toggleActions,
	)

	_ = b.commandHandler.AddCommand(
		"dumpstack",
		"Debug command -- dumps the stack of all goroutines to the log",
		[]string{"bot.admin"},
		0,
		func(a *chatcommand.Argument) error {
			stack := util.Stack()
			b.log.Info(string(stack))

			a.Reply("Stack traces of all goroutines dumped to chat")

			return nil
		},
	)

	_ = b.commandHandler.AddCommand(
		"scannedranges", "lists the source ranges that are scanned", []string{"bot.admin"}, 0, b.cmdScannedRanges,
	)

	_ = b.commandHandler.AddCommand("listactions", "list all enabled actions", []string{"bot.admin"}, 0, b.cmdListActions)

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
	b.log.Info("Connected")

	go b.cacheLoop(b.irc.DoneChan())

	b.log.Info("Attempting to oper")

	if err := b.oper(); err != nil {
		b.log.Fatalf("Could not oper up: %s", err)
	}

	b.log.Info("Opered, joining channels")
	_ = b.irc.WriteIRC("JOIN", b.ircLogChan)
	_ = b.irc.WriteIRC("JOIN", b.ircVLogChan)

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

func (b *Bot) homeServerState(homeserver string) (*ScanResult, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	lowered := strings.ToLower(homeserver)

	res, ok := b.cache[lowered]
	if !ok {
		newResult := &ScanResult{
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
	// Just in case.
	msg = strings.ReplaceAll(msg, "\r", "\\r")
	msg = strings.ReplaceAll(msg, "\n", "\\n")

	targetLogChan := b.ircLogChan

	for _, re := range b.redirectLogREs {
		if re.MatchString(msg) {
			targetLogChan = b.ircVLogChan

			break
		}
	}

	if err := b.irc.SendMessageChunked(targetLogChan, msg); err != nil {
		b.log.Errorf("Unable to log %q to %q: %s", msg, b.ircLogChan, err)
	}
}

func (b *Bot) logToVerboseChannelf(format string, args ...interface{}) {
	b.logToVerboseChannel(fmt.Sprintf(format, args...))
}

func (b *Bot) logToVerboseChannel(msg string) {
	if b.config.VerboseLogChannel == "" {
		log.Warningf("Unable to verbose log message as channel is not configured: %q", msg)
		return
	}

	if err := b.irc.SendMessageChunked(b.config.VerboseLogChannel, msg); err != nil {
		b.log.Errorf("unable to log %q to %q: %s", msg, b.config.VerboseLogChannel, err)
	}
}

var (
	ErrInvalidHSName   = errors.New("invalid homeserver name")
	ErrHSNameTruncated = errors.New("homeserver name appears truncated")
	ErrBadRealname     = errors.New("realname does not match expected pattern")
)

func (b *Bot) logBadRealname(err error, realname, userLog string) {
	b.log.Errorf("Unable to convert %q to homeserver name: %s", realname, err)

	switch {
	case errors.Is(err, ErrBadRealname):
		b.logToVerboseChannelf("ERR: Realname appears invalid: %s (for %s)", err, userLog)

	case errors.Is(err, ErrInvalidHSName):
		b.logToVerboseChannelf("ERR: Invalid homeserver in realname %q (for %s)", realname, userLog)

	case errors.Is(err, ErrHSNameTruncated):
		b.logToVerboseChannelf("ERR: Homeserver in realname %q appears truncated (for %s)", realname, userLog)

	default:
		b.logToChannelf("ERR: %s: %q (for %s)", err, realname, userLog)
	}
}

func (b *Bot) onMatrixConnection(nick, ident, host, ip, realname, account string) {
	userLog := fmt.Sprintf("%s!%s@%s (%s | %s | %s)", nick, ident, host, ip, realname, account)
	b.log.Infof("New matrix connection: %s", userLog)

	hs, err := b.realnameToHomeserver(realname)
	if err != nil {
		b.logBadRealname(err, realname, userLog)

		return
	}

	if hs == "" {
		b.log.Criticalf("Invalid homeserver name returned from homeserverToRealname! source was %q", userLog)
		b.logToChannel("CRIT: homeserverToRealname returned an empty string and nil error! A_Dragon fix this")
		return
	}

	result, userWasScanned, err := b.getCacheOrScan(hs)
	if err != nil {
		switch {
		case errors.Is(err, err404):
		case errors.Is(err, context.DeadlineExceeded):
			b.logToChannelf("ERR: Homeserver %q (for %s) timed out while scanning", hs, userLog)
		default:
			b.logToChannelf("ERR: Homeserver %q (for %s) errored while scanning: %s", hs, userLog, err)
		}
	}
	// The state may have changed here if it was dropped from the caches

	// XXX: There is a race condition here, where it can be dropped from a cache
	// XXX: but *after* this check. I dont think its problematic enough to
	// XXX: warrant actually fixing, but the fix would be a mutex on the obj
	if result.state == scanDroppedFromCache {
		b.log.Noticef("Scan for %q was dropped from cache. Aborting checks", hs)

		return
	}

	if result.isOpenReg {
		b.log.Infof("Homeserver %q is bad (from user %s)", hs, userLog)
		b.logToChannelf(
			"BAD: Matrix homeserver %q allows for unverified registration (based on connecting user %s)", hs, userLog,
		)

		if err := b.executeActions(nick, ident, host, ip, realname, hs, account, userWasScanned); err != nil {
			b.log.Errorf("could not execute actions: %s", err)
			b.logToChannelf("ERR: Unable to execute actions: %s", err)
		}

		return
	}

	b.log.Infof("Homeserver %q is safe (or errored) (from user %s)", hs, userLog)
}

func (b *Bot) executeActions(nick, ident, host, ip, realname, homeserver, account string, userWasScanned bool) error {
	commands := []string{}

	for i, a := range b.actions {
		c, err := a.Execute(nick, ident, host, ip, realname, homeserver, account, userWasScanned)
		if err != nil {
			if errors.Is(err, ErrOnlyMatchScannedUser) {
				continue
			}

			return fmt.Errorf("could not execute action %d: %w", i, err)
		}

		commands = append(commands, c...)
	}

	for _, c := range commands {
		if b.config.LogOnly {
			b.logToChannelf("WOULD ISSUE: %s", c)
		} else {
			if _, err := b.irc.WriteString(c); err != nil {
				log.Errorf("couldnt write command: %s", err)
				b.logToChannelf("ERR: unable to execute %q: %s", c, err)
			}
		}
	}

	return nil
}

func (b *Bot) getCacheOrScan(hs string) (scanResult *ScanResult, shouldXLine bool, err error) {
	scanResult, newlyCreated := b.homeServerState(hs)

	if !newlyCreated {
		b.log.Debugf("Scan already exists for %q", hs)

		waited := false

		if scanResult.state == scanInProgress {
			b.log.Debugf("Scan in progress for %q. Waiting...", hs)
			<-scanResult.resultWait

			waited = true
		}

		// if we didnt wait, then this was in the cache but wasn't scanned right this second,
		// and thus we should X-Line it

		return scanResult, !waited, nil
	}

	// this was created for us, and thus we need to do a scan
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()

	b.log.Infof("Scanning homeserver %q...", hs)
	isUnverifiedReg, err := b.scan(ctx, hs)

	defer close(scanResult.resultWait)

	scanResult.isOpenReg = isUnverifiedReg
	scanResult.scanTime = time.Now()
	scanResult.state = scanComplete

	if err != nil {
		b.log.Errorf("Could not scan homeserver %q: %s", hs, err)

		scanResult.isOpenReg = false

		return scanResult, false, err
	}

	return scanResult, true, nil
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
	return b.matrixScanner.ScanServer(ctx, homeserver, b.badFlows)
}

func generateXLineTarget(homeserver string) string {
	return `\@*:` + xlineEscape(strings.TrimSpace(homeserver))
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

func (b *Bot) realnameToHomeserver(realname string) (string, error) {
	if realname == "" || realname[0] != '@' {
		return "", fmt.Errorf("%w: realname is empty or does not begin with an @", ErrBadRealname)
	}

	if !strings.Contains(realname, ":") {
		return "", fmt.Errorf("%w: realname does not contain a colon", ErrBadRealname)
	}

	if len(realname) >= 48 {
		b.logToChannelf("WARN: Suspicious realname length of %d: %q. Dropping", len(realname), realname)

		return "", fmt.Errorf("%w: length of %d", ErrHSNameTruncated, len(realname))
	}

	split := strings.Split(realname, ":")
	possible := split[len(split)-1]

	if !strings.Contains(possible, ".") {
		return "", fmt.Errorf("%w: no dot in URL", ErrInvalidHSName)
	}

	if _, err := url.Parse(possible); err != nil {
		return "", fmt.Errorf("%w: realname doesnt pass sanity checks: %s", ErrInvalidHSName, err)
	}

	return possible, nil
}

// Stop stops the bot.
func (b *Bot) Stop(message string) {
	b.irc.Stop(message)
}

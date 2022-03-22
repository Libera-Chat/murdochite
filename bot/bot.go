package bot

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"runtime/debug"
	"strconv"
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

type ScanResult struct {
	state      scanState
	homeserver string
	scanTime   time.Time
	isOpenReg  bool
	resultWait chan struct{}
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

	XLineDuration int    `toml:"xline_duration"`
	XlineMessage  string `toml:"xline_message"`
	LogOnly       bool   `toml:"log_only"`

	Version string `toml:"-"`
}

type Bot struct {
	irc            *client.Client
	config         *Config
	ircLogChan     string
	ircVLogChan    string
	redirectLogREs []*regexp.Regexp
	log            *logging.Logger

	mu       sync.Mutex
	cache    map[string]*ScanResult
	badFlows []*set.StringSet

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

	if config.XLineDuration == 0 {
		config.XLineDuration = 60 * 24 * 30 // 1 month
	}

	if config.XlineMessage == "" {
		config.XlineMessage = "Your homeserver appears to allow unverified registration."
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
		badFlows:       badflows,
		config:         config,
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
		"togglexline",
		"toggle X-Lining of bad hosts -- Note that this does \x02MAY NOT\x02 affect cached hosts. "+
			"A `DROPCACHE ALL` may be helpful after enabling X-Lines, in the case that cached hosts are not being hit",
		[]string{"bot.admin"},
		0,
		b.toggleXline,
	)

	_ = b.commandHandler.AddCommand(
		"dumpstack",
		"Debug command -- dumps the stack of all goroutines to the log",
		[]string{"bot.admin"},
		0,
		func(*chatcommand.Argument) error {
			stack := util.Stack()
			b.log.Info(stack)

			return nil
		},
	)

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

	if err := b.irc.SendMessage(targetLogChan, msg); err != nil {
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

	result, xlineAllowed, err := b.getCacheOrScan(hs)
	if err != nil && !errors.Is(err, err404) {
		b.logToChannelf("ERR: Homeserver %q (for %s) errored while scanning: %s", hs, userLog, err)
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
			"BAD: Matrix homeserver %q allows for unverified registration (based on connecting user %s)",
			hs,
			userLog,
		)

		if xlineAllowed {
			b.xlineHomeserver(hs)
		}

		return
	}

	b.log.Infof("Homeserver %q is safe (or errored) (from user %s)", hs, userLog)
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
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
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
	return badHomeServer(ctx, homeserver, b.badFlows)
}

func (b *Bot) xlineHomeserver(hs string) {
	b.log.Infof("X-Lining homeserver %s", hs)
	target := generateXLineTarget(hs)

	if hs == "" {
		b.logToChannelf("REFUSING TO BAN EMPTY HOMESERVER! A_DRAGON FIX YOUR SHIT")

		b.log.Critical("refusing to ban empty homeserver")
		debug.PrintStack()
		return
	}

	if b.config.LogOnly {
		b.logToChannelf("Would issue: XLINE %d %s :%s", b.config.XLineDuration, target, b.config.XlineMessage)

		return
	}

	if strings.EqualFold(strings.TrimSpace(hs), "matrix.org") {
		b.logToChannelf("Refusing to X-Line matrix.org")

		return
	}

	if err := b.irc.WriteIRC("XLINE", strconv.Itoa(b.config.XLineDuration), target, b.config.XlineMessage); err != nil {
		b.log.Errorf("Could not write X-LINE: %s", err)
		b.logToChannelf("Could not write X-Line: %s", err)
	}
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

// Stop stops the bot.
func (b *Bot) Stop(message string) {
	b.irc.Stop(message)
}

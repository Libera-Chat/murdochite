package bot

import (
	"context"
	"runtime"
	"sort"
	"strings"
	"time"

	"awesome-dragon.science/go/irc/event/chatcommand"
)

func (b *Bot) manualScan2(a *chatcommand.Argument) error {
	logChanF := func(s string, a ...interface{}) { b.logToChannelf("MANUAL: "+s, a...) }
	hs := strings.TrimSpace(a.Arguments[0])

	b.logToChannelf("%s requested a manual scan of %q...", a.Event.SourceUser.Canonical(), hs)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
		defer cancel()

		res, err := b.matrixScanner.ScanServerResult(ctx, hs)
		if err != nil {
			logChanF("Errored while scanning: %s", err)

			return
		}

		logChanF("Homeserver \x02%s\x02 results follow...", hs)
		defer logChanF("End of results for \x02%s\x02", hs)

		if res.Homeserver != res.Delegate && res.Delegate != "" {
			logChanF("Homeserver delegates requests to %q (sourced from %s)", res.Delegate, res.DelegateType)
		}

		if res.AllowsUnverifiedRegistration(b.badFlows) {
			logChanF("Allows Unverified registration")
			logChanF("/quote XLINE 1440 %s :Your homeserver appears to allow unverified registration.", generateXLineTarget(hs))
		}

		if res.ErrorCode == "M_FORBIDDEN" {
			logChanF("Reports that registration is disabled")
		} else if res.ErrorCode != "" {
			logChanF("Returned an error: %q -- %q", res.ErrorCode, res.Error)
		}

		for i, flow := range res.Flows {
			logChanF("Flow \x02%02d\x02: %s", i, strings.Join(flow.Stages, ", "))
		}

		for i, remark := range res.Remarks {
			logChanF("Remark \x02%02d\x02: %s", i, remark)
		}
	}()

	return nil
}

type botStatus struct {
	cacheSize       int
	scansInProgress int
	completedScans  int
	goodScans       int
	badScans        int
	unknownScans    int
}

func (b *Bot) scanStatus() botStatus {
	b.mu.Lock()
	cacheSize := len(b.cache)
	inProgress := 0
	completed := 0

	good, bad, unknown := 0, 0, 0

	for _, v := range b.cache {
		switch v.state {
		case scanInProgress:
			inProgress++

		case scanComplete:
			completed++

			if v.isOpenReg {
				bad++
			} else {
				good++
			}

		case scanDroppedFromCache:
			unknown++

		default:
			b.log.Warningf("Unknown scan status %d -- %#v", v.state, v)
			unknown++
		}
	}
	defer b.mu.Unlock()

	return botStatus{
		cacheSize:       cacheSize,
		scansInProgress: inProgress,
		completedScans:  completed,
		goodScans:       good,
		badScans:        bad,
		unknownScans:    unknown,
	}
}

func (b *Bot) statuscmd(a *chatcommand.Argument) error {
	status := b.scanStatus()

	a.Replyf(
		"Bot status: Version \x02%s\x02 | \x02%d\x02 goroutines | \x02%d\x02 cached homeservers | "+
			"\x02%d\x02 scans in progress | \x02%d\x02 scans completed (G: %d | B: %d | U: %d) |"+
			" cache entries cleared after \x02%d\x02 hours | Actions loaded: %d | Actions enabled: %t",
		b.config.Version,
		runtime.NumGoroutine(),
		status.cacheSize,
		status.scansInProgress,
		status.completedScans,
		status.goodScans,
		status.badScans,
		status.unknownScans,
		b.config.ScanTimeoutHours,
		len(b.actions),
		!b.config.LogOnly,
	)

	return nil
}

func (b *Bot) toggleRawLog(a *chatcommand.Argument) error {
	b.log.Infof("Raw log toggled by %s", a.SourceUser().Mask())
	b.logToChannelf("Raw log toggled by %s", a.SourceUser().Mask())
	b.irc.ToggleRawLog()
	return nil
}

func (b *Bot) restartCmd(*chatcommand.Argument) error {
	b.ShouldRestart = true
	b.Stop("Restarting...")
	return nil
}

func (b *Bot) getCache(a *chatcommand.Argument) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(a.Arguments) == 0 {
		keys := make([]string, 0, len(b.cache))
		for k := range b.cache {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			a.Replyf("cache: %s", b.cache[k].IRCString())
		}
	}

	for _, name := range a.Arguments {
		res, exists := b.cache[name]
		if !exists {
			a.Replyf("cache: %s does not exist in the cache", name)

			continue
		}

		a.Replyf("cache: %s", res.IRCString())
	}

	return nil
}

func (b *Bot) dropCache(a *chatcommand.Argument) error {
	if len(a.Arguments) == 0 {
		a.Reply("Refusing to drop entire cache. use DROPCACHE ALL if you want this. If not see HELP DROPCACHE")
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	toDrop := []string{}

	if len(a.Arguments) == 1 && strings.EqualFold(a.Arguments[0], "all") {
		for k := range b.cache {
			toDrop = append(toDrop, strings.ToLower(k))
		}
	} else {
		for _, name := range a.Arguments {
			toDrop = append(toDrop, strings.ToLower(name))
		}
	}

	for _, name := range toDrop {
		match, exists := b.cache[name]
		if !exists {
			a.Replyf("\x02%q\x02 does not exist in the cache", name)

			continue
		}

		a.Replyf("Removing \x02%s\x02 from the cache! (%s)", name, match.IRCString())
		delete(b.cache, name)

		match.state = scanDroppedFromCache
		select {
		case <-match.resultWait:
			// This can only happen if resultWait is closed, so dont close it again
		default:
			close(match.resultWait)
		}
	}

	return nil
}

func strIf(t, f string, v bool) string {
	if v {
		return t
	}

	return f
}

func (b *Bot) toggleAction(a *chatcommand.Argument) error {
	name := strings.ToLower(a.Arguments[0])
	res, ok := b.actions[name]

	if !ok {
		a.Replyf("Unknown action %q", name)
		return nil
	}

	b.logToChannelf("%s{%s} Has %s action %s", a.SourceUser().Mask(), a.SourceUser().OperName, strIf(
		"\x02ENABLED\x02",
		"\x02DISABLED\x02",
		res.Enabled(),
	), res)

	res.Toggle()

	return nil
}

func (b *Bot) cmdScannedRanges(a *chatcommand.Argument) error {
	s := []string{}
	for _, r := range b.scanRanges {
		s = append(s, r.String())
	}

	a.Replyf("Scanned ranges: %s", strings.Join(s, ", "))

	return nil
}

func (b *Bot) cmdListActions(a *chatcommand.Argument) error {
	for name, action := range b.actions {
		a.Replyf("Action %s: %s", name, action)
	}

	return nil
}

package bot

import (
	"context"
	"runtime"
	"sort"
	"strings"
	"time"

	"awesome-dragon.science/go/irc/event/chatcommand"
)

func (b *Bot) manualScan(a *chatcommand.Argument) error {
	hs := strings.TrimSpace(a.Arguments[0])
	b.logToChannelf("%s requested a manual scan of %q...", a.SourceUser().Name, hs)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
		defer cancel()

		hs = httpsPrefixIfNotExist(hs)

		delegate, err := b.matrixScanner.GetServerDelegate(ctx, hs)
		if err == nil {
			b.logToChannelf(
				"MANUAL: Note that requested hs %q has delegated stuff to %q, try scanning that?", hs, delegate,
			)
		}

		res, err := b.matrixScanner.getRegistrationData(ctx, hs)
		if err != nil {
			b.logToChannelf("Error while performing manual scan: %s", err)

			return
		}

		b.logToChannelf("MANUAL: Homeserver \x02%q\x02 results follow...", hs)

		if res.allowsUnverifiedRegistration(b.badFlows) {
			b.logToChannelf("MANUAL: Allows unverified registration")
			b.logToChannelf(
				"MANUAL: /quote XLINE 1440 %s :Message Here",
			)
		}

		if res.ErrorCode == "M_FORBIDDEN" {
			b.logToChannelf(
				"MANUAL: Reports that registration is forbidden! (\x02%q\x02: \x02%q\x02)", res.ErrorCode, res.Error,
			)
		} else if res.ErrorCode != "" {
			b.logToChannelf("MANUAL: Error from server: %q: %q", res.ErrorCode, res.Error)
		}

		for i, flow := range res.Flows {
			b.logToChannelf("MANUAL: Flow %d:  %s", i, strings.Join(flow.Stages, ", "))
		}

		b.logToChannelf("MANUAL: end of results for \x02%q\x02", hs)
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
			" cache entries cleared after \x02%d\x02 hours | Xlines enabled: %t",
		b.config.Version,
		runtime.NumGoroutine(),
		status.cacheSize,
		status.scansInProgress,
		status.completedScans,
		status.goodScans,
		status.badScans,
		status.unknownScans,
		b.config.ScanTimeoutHours,
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

func (b *Bot) toggleXline(a *chatcommand.Argument) error {
	newSetting := !b.config.LogOnly

	// if newSetting is FALSE, we've got teeth

	state := "\x02ENABLED\x02"
	if newSetting {
		state = "\x02DISABLED\x02"
	}

	a.Replyf("Setting X-Lines is now %s!", state)
	b.logToChannelf("%s (oper %q) has %s Xlines", a.SourceUser().Mask(), a.SourceUser().OperName, state)

	b.config.LogOnly = newSetting

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

// TODO: bbolt db for hit counts, to store longterm information

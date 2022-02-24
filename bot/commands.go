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

		res, err := getRegistrationData(ctx, hs)
		if err != nil {
			b.logToChannelf("Error while performing manual scan: %s", err)

			return
		}

		b.logToChannelf("MANUAL: Homeserver \x02%q\x02 results follow...", hs)

		if res.allowsUnverifiedRegistration(b.badFlows) {
			b.logToChannelf("MANUAL: Allows unverified registration")
			b.logToChannelf(
				"MANUAL: /quote XLINE %d %s :%s", b.config.XLineDuration, generateXLineTarget(hs), b.config.XlineMessage,
			)
		}

		for i, flow := range res.Flows {
			b.logToChannelf("MANUAL: Flow %d:  %s", i, strings.Join(flow.Stages, ", "))
		}

		_, _ = res, err
	}()

	return nil
}

func (b *Bot) scanStatus() (cacheSize, inProgress, completed, good, bad int) {
	b.mu.Lock()
	cacheSize = len(b.cache)
	inProgress = 0
	completed = 0

	good, bad = 0, 0

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
		}
	}
	defer b.mu.Unlock()

	return cacheSize, inProgress, completed, good, bad
}

func (b *Bot) statuscmd(a *chatcommand.Argument) error {
	cacheSize, progress, completed, good, bad := b.scanStatus()

	a.Replyf(
		"Bot status: Version \x02%s\x02 | \x02%d\x02 goroutines | \x02%d\x02 cached homeservers | "+
			"\x02%d\x02 scans in progress | \x02%d\x02 scans completed (G: %d | B: %d) |"+
			" cache entries cleared after \x02%d\x02 hours",
		b.config.Version, runtime.NumGoroutine(), cacheSize, progress, completed, good, bad, b.config.ScanTimeoutHours,
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

func (b *Bot) dropCache(a *chatcommand.Argument) error { //nolint:unparam // fits an interface
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
		close(match.resultWait)
	}

	return nil
}

// TODO: bbolt db for hit counts, to store longterm information

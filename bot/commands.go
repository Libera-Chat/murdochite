package bot

import (
	"context"
	"runtime"
	"strings"
	"time"

	"awesome-dragon.science/go/irc/event/chatcommand"
)

func (b *Bot) manualScan(a *chatcommand.Argument) error {
	hs := strings.TrimSpace(a.Arguments[0])
	b.logToChannelf("%s requested a manual scan of %q...", a.SourceUser.Name, hs)

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
		}

		for _, flow := range res.Flows {
			b.logToChannelf("MANUAL: %s", strings.Join(flow.Stages, ", "))
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
	b.log.Infof("Raw log toggled by %s", a.SourceUser.Mask())
	b.logToChannelf("Raw log toggled by %s", a.SourceUser.Mask())
	b.irc.ToggleRawLog()
	return nil
}

func (b *Bot) restartCmd(*chatcommand.Argument) error {
	b.ShouldRestart = true
	b.Stop("Restarting...")
	return nil
}

// TODO: getcache, dropcache

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

func (b *Bot) scanStatus() (cacheSize, inProgress, completed int) {
	b.mu.Lock()
	cacheSize = len(b.cache)
	inProgress = 0
	completed = 0

	for _, v := range b.cache {
		switch v.state {
		case scanInProgress:
			inProgress++
		case scanComplete:
			completed++
		}
	}
	defer b.mu.Unlock()

	return cacheSize, inProgress, completed
}

func (b *Bot) statuscmd(a *chatcommand.Argument) error {
	cacheSize, progress, completed := b.scanStatus()

	a.Replyf(
		"Bot status: \x02%d\x02 goroutines | \x02%d\x02 cached homeservers | "+
			"\x02%d\x02 scans in progress | \x02%d\x02 scans completed | cache entries cleared after \x02%d\x02 hours",
		runtime.NumGoroutine(), cacheSize, progress, completed, b.config.ScanTimeoutHours,
	)

	return nil
}

func (b *Bot) toggleRawLog(a *chatcommand.Argument) error {
	b.log.Infof("Raw log toggled by %s", a.SourceUser.Mask())
	b.logToChannelf("Raw log toggled by %s", a.SourceUser.Mask())
	b.irc.ToggleRawLog()
	return nil
}

// TODO: getcache, dropcache

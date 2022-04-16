# Murdochite

Murdochite scans incoming Matrix connections and verifies that they do not allow
unverified registration.

## Building

Generally it's suggested to set the version when building: 
`go build go build -ldflags="-X main.Version='$(git rev-parse --short HEAD)'" -trimpath -o murdochite main.go`

## Usage

Murdochite has a builtin help system that will allow you to get information on most commands, `help [command]` is the
easy way to get access to that.

### Simple Usage

Once connected, murdochite will pretty much just do its own thing, logging things and executing configured actions.

If you want to manually scan something, use the `scan` command. Results are sent to the bots log channel.
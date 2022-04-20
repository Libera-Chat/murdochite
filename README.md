# Murdochite

Murdochite scans incoming Matrix connections and verifies that they do not allow
unverified registration.

## Building

Generally it's suggested to set the version when building:
`go build go build -ldflags="-X main.Version='$(git rev-parse --short HEAD)'" -trimpath -o murdochite main.go`

## Usage

Murdochite has a builtin help system that will allow you to get information on
most commands, `help [command]` is the easy way to get access to that.

### Simple Usage

Once connected, murdochite will pretty much just do its own thing,
logging things and executing configured actions.

If you want to manually scan something, use the `scan` command.
Results are sent to the bots log channel.

## Configuration

Murdochite uses a toml file in its working directory for configuration.
You can find an example config in `config.example.toml`.

### Actions

Murdochite has three action types, all of which share a standard configuration
| Name          |   Type   | Description                                                |
| :------------ | :------: | :--------------------------------------------------------- |
| `type`        | `string` | The type of action to use                                  |
| `message`     | `string` | The message to be passed along for this action (see below) |
| `duration`    |  `int`   | The number of things enacted by this action (see below)    |
| `ignore_sasl` |  `bool`  | Whether or not to skip SASLed users (ie, dont ban them)    |
| `enabled`     |  `bool`  | Startup enable state of this action                        |


#### X-Line action (`xline`)

The X-Line action sets an X-Line on `*\@homeserver.tld`. Which effectively
disables use of this homeserver entirely.

#### K-Line action (`kline`)

The K-Line action sets a K-Line on the connecting user's IP.
This is slightly nicer than the X-Line action as it allows already connected
users (or users that use SASL) though.

#### Warn action (`warn`)

The Warn action allows you to log a message to the log channel when a connecting
user is coming from an unverified server. 
It uses [golang templates](https://golang.org/pkg/text/template/) in its `message`.

There are two special functions available to the template,
`generateKLineTarget(ident, host)` and `generateXLineTarget(homeserver_name)`.
These generate sane targets for the connecting user.

when executing the template, `.` is a combination of the `ActionArgs` and
`ActionConfig` structs, with all fields available.

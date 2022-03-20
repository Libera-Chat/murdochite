# Murdochite

Murdochite scans incoming Matrix connections and verifies that they do not allow
unverified registration.

## Building

Generally it's suggested to set the version when building: 
`go build go build -ldflags="-X main.Version='$(git rev-parse --short HEAD)'" -trimpath -o murdochite main.go`
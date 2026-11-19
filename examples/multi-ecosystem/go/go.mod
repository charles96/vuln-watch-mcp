module example.com/demo

go 1.21

toolchain go1.21.3

require (
	github.com/gin-gonic/gin v1.7.0
	golang.org/x/net v0.10.0 // indirect
	example.com/internal v0.0.0
)

replace example.com/internal => ../internal

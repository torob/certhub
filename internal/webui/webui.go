package webui

import (
	"embed"
	"io/fs"
)

//go:embed assets
var embedded embed.FS

func FS() fs.FS {
	sub, err := fs.Sub(embedded, "assets")
	if err != nil {
		panic(err)
	}
	return sub
}

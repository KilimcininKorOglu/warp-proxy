package web

import "embed"

// templates holds the panel HTML templates.
//
//go:embed templates/*.html
var templates embed.FS

package frontend

import "embed"

//go:embed index.html style.css app.js guestgate.ico
var Assets embed.FS

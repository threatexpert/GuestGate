package frontend

import "embed"

//go:embed index.html style.css app.js activity.js exit-confirmation.js guestgate.ico
var Assets embed.FS

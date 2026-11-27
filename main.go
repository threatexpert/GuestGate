package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	winoptions "github.com/wailsapp/wails/v2/pkg/options/windows"
	"golang.org/x/sys/windows"

	"guestgate/frontend"
	"guestgate/internal/desktop"
	"guestgate/internal/gateway"
)

// Keep the public Wails binding at window.go.main.App.
type App struct{ *desktop.App }

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--manager" {
		if err := gateway.ServeManager(os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--worker" {
		if err := gateway.RunWorker(); err != nil {
			fmt.Println("错误 ·", err)
			os.Exit(1)
		}
		return
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		exe, e := os.Executable()
		if e != nil {
			return
		}
		file, _ := windows.UTF16PtrFromString(exe)
		verb, _ := windows.UTF16PtrFromString("runas")
		windows.ShellExecute(0, verb, file, nil, nil, windows.SW_SHOWNORMAL)
		return
	}
	ui, shutdown := desktop.NewApp()
	app := &App{ui}
	class := fmt.Sprintf("GuestGate.Main.%d", os.Getpid())
	var firstShow sync.Once
	err := wails.Run(&options.App{
		Title: "GuestGate", Width: 640, Height: 440, StartHidden: true,
		Windows:     &winoptions.Options{WindowClassName: class},
		AssetServer: &assetserver.Options{Assets: frontend.Assets}, Bind: []interface{}{app},
		OnDomReady: func(ctx context.Context) { firstShow.Do(func() { desktop.ShowStartupWindow(ctx, class) }) },
		OnShutdown: func(context.Context) { shutdown() },
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

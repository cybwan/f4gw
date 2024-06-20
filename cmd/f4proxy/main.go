package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"

	"github.com/cybwan/f4gw/pkg/bpf/proxy"
	"github.com/cybwan/f4gw/pkg/logger"
)

var (
	flags = pflag.NewFlagSet(`flomesh-f4proxy`, pflag.ExitOnError)
	log   = logger.New("flomesh-f4proxy")
)

var (
	cfg string
)

func init() {
	flags.StringVarP(&cfg, "conf", "c", "proxy.json", "FSM mesh name")
}

func main() {
	if err := flags.Parse(os.Args); err != nil {
		log.Fatal().Msg(err.Error())
	}

	cfgFile, err := os.Open(cfg)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	bytes, bytesErr := io.ReadAll(cfgFile)
	if bytesErr != nil {
		log.Fatal().Msg(bytesErr.Error())
	}

	f4proxyCfg := new(proxy.F4ProxyConfig)
	err = json.Unmarshal(bytes, f4proxyCfg)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	bytes, err = json.MarshalIndent(f4proxyCfg, ``, `  `)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	fmt.Println(string(bytes))

	f4proxy := new(proxy.F4Proxy)
	f4proxy.Init()
	defer f4proxy.Close()

	for _, ingress := range f4proxyCfg.Ingress {
		f4proxy.AttachIngressBPF(ingress.LinkName)
	}

	workDuration, err := time.ParseDuration(f4proxyCfg.WorkDuration)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	if workDuration == time.Duration(0) {
		workDuration = time.Duration(1<<63 - 1)
	}
	quitTimer := time.NewTimer(workDuration)
	defer quitTimer.Stop()

	sigCh := make(chan os.Signal, 5)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGCHLD, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	log.Info().Msg("Press Ctrl-C to exit and remove the program")
	select {
	case <-sigCh:
	case <-quitTimer.C:
		return
	}
}

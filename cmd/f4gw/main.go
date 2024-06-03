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

	"github.com/cybwan/f4gw/pkg/bpf/gateway"
	"github.com/cybwan/f4gw/pkg/logger"
)

var (
	flags = pflag.NewFlagSet(`flomesh-f4gw`, pflag.ExitOnError)
	log   = logger.New("flomesh-f4gw")
)

var (
	cfg string
)

func init() {
	flags.StringVarP(&cfg, "conf", "c", "gw.json", "FSM mesh name")
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

	f4gwCfg := new(gateway.F4GwConfig)
	err = json.Unmarshal(bytes, f4gwCfg)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	bytes, err = json.MarshalIndent(f4gwCfg, ``, `  `)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	fmt.Println(string(bytes))

	f4gw := new(gateway.F4Gw)
	f4gw.Init()
	defer f4gw.Close()

	for _, ingress := range f4gwCfg.Ingress {
		f4gw.AttachIngressBPF(ingress.LinkName)
	}

	for _, egress := range f4gwCfg.Egress {
		f4gw.AttachEgressBPF(egress.ViaLinkName)
		if err = f4gw.ApplyNatLB(
			egress.TargetProto,
			egress.TargetAddr,
			egress.TargetPort,
			egress.ViaLinkName,
			egress.ViaLinkAddr,
			egress.Backends); err != nil {
			log.Fatal().Msg(err.Error())
		}
	}

	workDuration, err := time.ParseDuration(f4gwCfg.WorkDuration)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}
	if workDuration == time.Duration(0) {
		workDuration = time.Duration(^int64(0))
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

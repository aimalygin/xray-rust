// Run only inside the exact module checkout via check-xhttp-download-oracle.sh.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/splithttp"
	"os"
)

type fixtureCase struct {
	Name       string          `json:"name"`
	Stream     json.RawMessage `json:"stream"`
	GoAccept   bool            `json:"goAccept"`
	RustAccept bool            `json:"rustAccept"`
	Download   *struct {
		Address string
		Port    uint32
		Path    string
		Host    string
	} `json:"download"`
}

func run() error {
	if len(os.Args) == 3 && os.Args[1] == "bridge" {
		return bridge(os.Args[2])
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var f struct {
		XrayCoreCommit string
		Cases          []fixtureCase
	}
	if err = json.Unmarshal(raw, &f); err != nil {
		return err
	}
	if f.XrayCoreCommit != "5ca6f4b7d4dc20a881d4330e498892697627ec0c" {
		return fmt.Errorf("wrong reference commit")
	}
	for _, c := range f.Cases {
		var config conf.StreamConfig
		err := json.Unmarshal(c.Stream, &config)
		if err != nil {
			if !c.GoAccept {
				continue
			}
			return fmt.Errorf("%s decode: %w", c.Name, err)
		}
		built, err := config.Build()
		if (err == nil) != c.GoAccept {
			return fmt.Errorf("%s build acceptance: %v", c.Name, err)
		}
		if err != nil || !c.RustAccept {
			continue
		}
		effective, err := built.GetEffectiveTransportSettings()
		if err != nil {
			return err
		}
		x := effective.(*splithttp.Config)
		if c.Download == nil {
			if x.DownloadSettings != nil {
				return fmt.Errorf("%s: unexpected download", c.Name)
			}
			continue
		}
		d := x.DownloadSettings
		if d == nil || d.Address.AsAddress().String() != c.Download.Address || d.Port != c.Download.Port {
			return fmt.Errorf("%s: download destination mismatch", c.Name)
		}
		effective, err = d.GetEffectiveTransportSettings()
		if err != nil {
			return err
		}
		dx := effective.(*splithttp.Config)
		if dx.Path != c.Download.Path || dx.Host != c.Download.Host {
			return fmt.Errorf("%s: download identity mismatch", c.Name)
		}
	}
	fmt.Printf("XHTTP download configuration oracle: %d cases passed\n", len(f.Cases))
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

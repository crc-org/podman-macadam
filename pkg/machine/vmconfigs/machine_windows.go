package vmconfigs

import (
	"github.com/containers/podman/v5/pkg/machine/define"
	"github.com/containers/podman/v5/pkg/machine/env"
)

func getPipe(name string) *define.VMFile {
	pipeName := env.WithToolPrefix(name)
	return &define.VMFile{Path: `\\.\pipe\` + pipeName}
}

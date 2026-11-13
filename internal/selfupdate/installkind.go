// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

package selfupdate

import "os"

// InstallKind is how this gateway was installed, which decides how it is
// upgraded: a container's image belongs to whatever started the container.
type InstallKind uint8

const (
	// InstallOther is a binary started by hand, or anything not recognised.
	InstallOther InstallKind = iota
	// InstallSystemd is a systemd service.
	InstallSystemd
	// InstallContainer is a container outside Kubernetes.
	InstallContainer
	// InstallKubernetes is a pod.
	InstallKubernetes
)

// The marks each kind leaves. Kubernetes sets its service variables in every
// pod; Docker and Podman each leave a file at the root; systemd sets
// INVOCATION_ID for every unit it starts.
const (
	envKubernetes  = "KUBERNETES_SERVICE_HOST"
	envSystemdUnit = "INVOCATION_ID"
	dockerMark     = "/.dockerenv"
	podmanMark     = "/run/.containerenv"
)

// DetectInstallKind reads the process's surroundings. A container is checked
// before systemd: a container can run systemd, and its image is still what
// decides the version.
func DetectInstallKind() InstallKind {
	return installKind(os.Getenv, fileExists)
}

func installKind(getenv func(string) string, exists func(string) bool) InstallKind {
	switch {
	case getenv(envKubernetes) != "":
		return InstallKubernetes
	case exists(dockerMark) || exists(podmanMark):
		return InstallContainer
	case getenv(envSystemdUnit) != "":
		return InstallSystemd
	default:
		return InstallOther
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

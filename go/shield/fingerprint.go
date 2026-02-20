package shield

import (
	"crypto/md5"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// FingerprintMode defines the fingerprint collection mode.
type FingerprintMode int

const (
	// FingerprintNone - No fingerprinting (backward compatible)
	FingerprintNone FingerprintMode = iota
	// FingerprintMotherboard - Motherboard serial only
	FingerprintMotherboard
	// FingerprintCPU - CPU identifier only
	FingerprintCPU
	// FingerprintCombined - Motherboard + CPU (recommended)
	FingerprintCombined
)

// CollectFingerprint collects hardware fingerprint based on mode.
//
// Platform Support:
//   - Windows: wmic commands
//   - Linux: /sys/class/dmi/id, dmidecode, /proc/cpuinfo
//   - macOS: system_profiler, sysctl
//
// Returns:
//   - Fingerprint string (MD5 hex), or empty for FingerprintNone
//   - Error if hardware identifiers cannot be collected
func CollectFingerprint(mode FingerprintMode) (string, error) {
	if mode == FingerprintNone {
		return "", nil
	}

	if mode == FingerprintMotherboard {
		return getMotherboardSerial()
	}

	if mode == FingerprintCPU {
		return getCpuID()
	}

	if mode == FingerprintCombined {
		var components []string

		if mb, err := getMotherboardSerial(); err == nil {
			components = append(components, mb)
		}

		if cpu, err := getCpuID(); err == nil {
			components = append(components, cpu)
		}

		if len(components) == 0 {
			return "", fmt.Errorf("hardware fingerprint unavailable")
		}

		// Create MD5 hash of combined components
		combined := strings.Join(components, "-")
		return fmt.Sprintf("%x", md5.Sum([]byte(combined))), nil
	}

	return "", fmt.Errorf("unknown fingerprint mode: %d", mode)
}

// getMotherboardSerial gets motherboard serial number (platform-specific).
func getMotherboardSerial() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("wmic", "baseboard", "get", "serialnumber", "/value").Output()
		if err != nil {
			return "", err
		}

		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "SerialNumber=") {
				serial := strings.TrimSpace(strings.TrimPrefix(line, "SerialNumber="))
				if serial != "" && serial != "To be filled by O.E.M." {
					return serial, nil
				}
			}
		}

	case "linux":
		// Try DMI sysfs first (no elevated privileges needed)
		data, err := os.ReadFile("/sys/class/dmi/id/board_serial")
		if err == nil {
			serial := strings.TrimSpace(string(data))
			if serial != "" && serial != "To be filled by O.E.M." {
				return serial, nil
			}
		}

		// Fallback to dmidecode
		out, err := exec.Command("dmidecode", "-s", "baseboard-serial-number").Output()
		if err == nil {
			serial := strings.TrimSpace(string(out))
			if serial != "" && serial != "To be filled by O.E.M." {
				return serial, nil
			}
		}

	case "darwin":
		out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
		if err != nil {
			return "", err
		}

		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "Serial Number") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					return strings.TrimSpace(parts[1]), nil
				}
			}
		}
	}

	return "", fmt.Errorf("motherboard serial number unavailable")
}

// getCpuID gets CPU identifier (platform-specific).
func getCpuID() (string, error) {
	switch runtime.GOOS {
	case "windows":
		out, err := exec.Command("wmic", "cpu", "get", "ProcessorId", "/value").Output()
		if err != nil {
			return "", err
		}

		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "ProcessorId=") {
				cpuID := strings.TrimSpace(strings.TrimPrefix(line, "ProcessorId="))
				if cpuID != "" {
					return cpuID, nil
				}
			}
		}

	case "linux":
		data, err := os.ReadFile("/proc/cpuinfo")
		if err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "processor") && strings.Contains(line, "0") {
					// Use first processor as identifier (hashed)
					return fmt.Sprintf("%x", md5.Sum([]byte(line))), nil
				}
			}
		}

	case "darwin":
		out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output()
		if err == nil {
			cpuInfo := strings.TrimSpace(string(out))
			if cpuInfo != "" {
				return fmt.Sprintf("%x", md5.Sum([]byte(cpuInfo))), nil
			}
		}
	}

	return "", fmt.Errorf("CPU identifier unavailable")
}

// NewWithFingerprint creates a Shield instance with hardware fingerprinting.
//
// Derives keys from password + hardware identifier, binding encryption to
// the physical device.
//
// Example:
//
//	shield, err := shield.NewWithFingerprint("password", "github.com", shield.FingerprintCombined)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	encrypted, _ := shield.Encrypt([]byte("secret data"))
func NewWithFingerprint(password, service string, mode FingerprintMode) (*Shield, error) {
	fingerprint, err := CollectFingerprint(mode)
	if err != nil {
		return nil, err
	}

	combinedPassword := password
	if fingerprint != "" {
		combinedPassword = fmt.Sprintf("%s:%s", password, fingerprint)
	}

	return New(combinedPassword, service, nil), nil
}

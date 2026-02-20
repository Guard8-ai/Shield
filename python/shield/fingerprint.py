"""Hardware fingerprinting for device-bound encryption.

Collects platform-specific hardware identifiers to create device-bound keys.
Adapted from SaaSClient-SideLicensingSystem with enhanced cross-platform support.
"""

import hashlib
import platform
import subprocess
from enum import Enum
from typing import Optional


class FingerprintMode(Enum):
    """Fingerprint collection mode."""

    NONE = "none"  # No hardware fingerprinting (backward compatible)
    MOTHERBOARD = "motherboard"  # Use motherboard serial number only
    CPU = "cpu"  # Use CPU identifier only
    COMBINED = "combined"  # Use combined motherboard + CPU (recommended)


class FingerprintError(Exception):
    """Hardware fingerprint unavailable (VM or restricted access)."""

    pass


def collect_fingerprint(mode: FingerprintMode) -> str:
    """Collect hardware fingerprint based on mode.

    Args:
        mode: Fingerprint collection mode

    Returns:
        Hardware fingerprint string (empty for FingerprintMode.NONE)

    Raises:
        FingerprintError: If hardware identifiers cannot be collected

    Platform Support:
        - Windows: wmic commands (baseboard, CPU)
        - Linux: /sys/class/dmi/id, dmidecode, /proc/cpuinfo
        - macOS: system_profiler SPHardwareDataType
    """
    if mode == FingerprintMode.NONE:
        return ""

    if mode == FingerprintMode.MOTHERBOARD:
        return _get_motherboard_serial()

    if mode == FingerprintMode.CPU:
        return _get_cpu_id()

    if mode == FingerprintMode.COMBINED:
        components = []

        try:
            components.append(_get_motherboard_serial())
        except FingerprintError:
            pass

        try:
            components.append(_get_cpu_id())
        except FingerprintError:
            pass

        if not components:
            raise FingerprintError("No hardware identifiers available")

        # Create MD5 hash of combined components (matches SaaSClient and Rust)
        combined = "-".join(components)
        return hashlib.md5(combined.encode()).hexdigest()

    raise ValueError(f"Unknown fingerprint mode: {mode}")


def _get_motherboard_serial() -> str:
    """Get motherboard serial number (platform-specific)."""
    system = platform.system()

    if system == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "baseboard", "get", "serialnumber", "/value"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.startswith("SerialNumber="):
                    serial = line.replace("SerialNumber=", "").strip()
                    if serial and serial != "To be filled by O.E.M.":
                        return serial
        except Exception:
            pass

    elif system == "Linux":
        # Try DMI sysfs first (no elevated privileges needed)
        try:
            with open("/sys/class/dmi/id/board_serial", "r") as f:
                serial = f.read().strip()
                if serial and serial != "To be filled by O.E.M.":
                    return serial
        except Exception:
            pass

        # Fallback to dmidecode (may require sudo)
        try:
            result = subprocess.run(
                ["dmidecode", "-s", "baseboard-serial-number"],
                capture_output=True,
                text=True,
                check=False,
            )
            serial = result.stdout.strip()
            if serial and serial != "To be filled by O.E.M.":
                return serial
        except Exception:
            pass

    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                if "Serial Number" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        return parts[1].strip()
        except Exception:
            pass

    raise FingerprintError("Motherboard serial number unavailable")


def _get_cpu_id() -> str:
    """Get CPU identifier (platform-specific)."""
    system = platform.system()

    if system == "Windows":
        try:
            result = subprocess.run(
                ["wmic", "cpu", "get", "ProcessorId", "/value"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                if line.startswith("ProcessorId="):
                    cpu_id = line.replace("ProcessorId=", "").strip()
                    if cpu_id:
                        return cpu_id
        except Exception:
            pass

    elif system == "Linux":
        try:
            with open("/proc/cpuinfo", "r") as f:
                for line in f:
                    if line.startswith("processor") and "0" in line:
                        # Use first processor as identifier (hashed)
                        return hashlib.md5(line.encode()).hexdigest()
        except Exception:
            pass

    elif system == "Darwin":  # macOS
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=False,
            )
            cpu_info = result.stdout.strip()
            if cpu_info:
                return hashlib.md5(cpu_info.encode()).hexdigest()
        except Exception:
            pass

    raise FingerprintError("CPU identifier unavailable")

//go:build windows

package vsock

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPortToKeyNameRoundTrip(t *testing.T) {
	ports := []uint64{1, 1024, 0x400, 60999, 0xFFFFFFFF}
	for _, port := range ports {
		keyName := PortToKeyName(port)
		parsed, err := portFromKeyName(keyName)
		require.NoError(t, err, "port %d: key name %s should parse", port, keyName)
		assert.Equal(t, port, parsed, "round-trip of port %d through %s", port, keyName)
	}
}

func TestParseHexToUint64(t *testing.T) {
	valid := map[string]uint64{
		"00000400": 0x400,
		"400":      0x400,
		"FFFFFFFF": 0xFFFFFFFF,
	}
	for hex, want := range valid {
		got, err := parseHexToUint64(hex)
		require.NoError(t, err, "hex %s should parse", hex)
		assert.Equal(t, want, got)
	}

	for _, hex := range []string{"", "XYZW", "-1", "0x400"} {
		_, err := parseHexToUint64(hex)
		assert.Error(t, err, "hex %q should be rejected", hex)
	}
}

func TestPortFromKeyNameMalformed(t *testing.T) {
	malformed := []string{
		"",                                       // empty
		"FACB-11E6-BD58-64006A7986D3",            // missing port prefix
		"00000400",                               // missing suffix
		"00000400-FACB-11E6-BD58",                // truncated suffix
		"00000400-FACB-11E6-BD58-64006A7986D1",   // wrong suffix
		"00000400-C104-C8BE-B2B5-6951DA57D591",   // foreign GUID
		"ZZZZZZZZ-FACB-11E6-BD58-64006A7986D3",   // non-hex port
		"0000000400-FACB-11E6-BD58-64006A7986D3", // port segment too long
	}
	for _, keyName := range malformed {
		_, err := portFromKeyName(keyName)
		assert.Error(t, err, "key name %q should be rejected", keyName)
	}

	// lowercase key names must still parse: registry key names are
	// case-insensitive on Windows
	port, err := portFromKeyName("00000400-facb-11e6-bd58-64006a7986d3")
	require.NoError(t, err)
	assert.Equal(t, uint64(0x400), port)
}

func TestEntryCanBeReusedBy(t *testing.T) {
	base := HVSockRegistryEntry{
		KeyName:                "00000400-FACB-11E6-BD58-64006A7986D3",
		Purpose:                Network,
		Port:                   0x400,
		MachineName:            "test",
		ToolName:               PodmanToolName,
		KeepAfterMachineRemove: true,
	}

	tests := []struct {
		name        string
		modify      func(*HVSockRegistryEntry)
		machineName string
		purpose     HVSockPurpose
		expected    bool
	}{
		{
			name:        "exact match",
			machineName: "test",
			purpose:     Network,
			expected:    true,
		},
		{
			name:        "different machine cannot reuse the entry",
			modify:      func(e *HVSockRegistryEntry) { e.MachineName = "other" },
			machineName: "test",
			purpose:     Network,
			expected:    false,
		},
		{
			name:        "different purpose",
			machineName: "test",
			purpose:     Events,
			expected:    false,
		},
		{
			name:        "entry without KeepAfterMachineRemove is not reused",
			modify:      func(e *HVSockRegistryEntry) { e.KeepAfterMachineRemove = false },
			machineName: "test",
			purpose:     Network,
			expected:    false,
		},
		{
			name:        "machine created by another tool still matches (ToolName is informational)",
			modify:      func(e *HVSockRegistryEntry) { e.ToolName = "some-helper" },
			machineName: "test",
			purpose:     Network,
			expected:    true,
		},
		{
			name:        "empty machine name does not match an entry bound to a machine",
			machineName: "",
			purpose:     Network,
			expected:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := base
			if tt.modify != nil {
				tt.modify(&entry)
			}
			assert.Equal(t, tt.expected, entryCanBeReusedBy(&entry, tt.machineName, tt.purpose))
		})
	}
}

func TestRemoveKeepsPersistentEntries(t *testing.T) {
	// A pre-created entry: KeepAfterMachineRemove is set and the key does not
	// exist in the registry. If Remove() attempted a registry deletion it would
	// fail with ErrNotExist, so a nil return proves the guard short-circuits
	// before touching the registry.
	entry := HVSockRegistryEntry{
		KeyName:                "0000ABCD-FACB-11E6-BD58-64006A7986D3",
		Purpose:                Network,
		Port:                   0xABCD,
		MachineName:            "test",
		ToolName:               "some-helper",
		KeepAfterMachineRemove: true,
	}
	assert.NoError(t, entry.Remove())
}

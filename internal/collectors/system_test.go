package collectors

import "testing"

func TestMountsIgnore(t *testing.T) {
	m := mounts([]string{"/proc", "/sys"})
	if _, ok := m["/"]; !ok {
		t.Fatalf("raiz ausente: %v", m)
	}
	for mnt := range m {
		if within(mnt, "/proc") || within(mnt, "/sys") {
			t.Fatalf("%s devia ser ignorado", mnt)
		}
	}
}

func TestModulesParse(t *testing.T) {
	if len(modules()) == 0 {
		t.Skip("/proc/modules vazio (kernel sem módulos ou container)")
	}
}

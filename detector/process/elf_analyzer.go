package process

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ELFAnalyzer provides utilities for analyzing ELF binaries
type ELFAnalyzer struct{}

// NewELFAnalyzer creates a new ELF analyzer
func NewELFAnalyzer() *ELFAnalyzer {
	return &ELFAnalyzer{}
}

// IsGoBinary checks if a binary is a Go executable using buildinfo
func (ea *ELFAnalyzer) IsGoBinary(executablePath string) (bool, string, error) {
	if executablePath == "" {
		return false, "", fmt.Errorf("executable path is empty")
	}

	info, err := buildinfo.ReadFile(executablePath)
	if err != nil {
		return false, "", nil // Not a Go binary
	}

	// Extract Go version
	version := info.GoVersion

	return true, version, nil
}

// HasRustSymbols checks if binary has Rust symbols
func (ea *ELFAnalyzer) HasRustSymbols(executablePath string) (bool, error) {
	if executablePath == "" {
		return false, nil
	}

	elfFile, err := elf.Open(executablePath)
	if err != nil {
		return false, nil // Not an ELF file or can't read
	}
	defer elfFile.Close()

	// Check symbol table
	symbols, err := elfFile.Symbols()
	if err == nil {
		for _, sym := range symbols {
			if strings.Contains(sym.Name, "__rust_") ||
			   strings.Contains(sym.Name, "_ZN") && strings.Contains(sym.Name, "rust") {
				return true, nil
			}
		}
	}

	// Check dynamic symbols
	dynSymbols, err := elfFile.DynamicSymbols()
	if err == nil {
		for _, sym := range dynSymbols {
			if strings.Contains(sym.Name, "__rust_") {
				return true, nil
			}
		}
	}

	return false, nil
}

// HasCPlusPlusLibraries checks if binary is linked with C++ libraries
func (ea *ELFAnalyzer) HasCPlusPlusLibraries(executablePath string) (bool, string, error) {
	if executablePath == "" {
		return false, "", nil
	}

	elfFile, err := elf.Open(executablePath)
	if err != nil {
		return false, "", nil
	}
	defer elfFile.Close()

	// Check for C++ standard library
	libraries, err := elfFile.ImportedLibraries()
	if err != nil {
		return false, "", nil
	}

	for _, lib := range libraries {
		if strings.Contains(lib, "libstdc++") {
			return true, "gcc", nil
		}
		if strings.Contains(lib, "libc++") {
			return true, "llvm", nil
		}
	}

	return false, "", nil
}

// ExtractPHPVersion extracts PHP version from ELF .rodata section
func (ea *ELFAnalyzer) ExtractPHPVersion(executablePath string) (string, error) {
	if executablePath == "" {
		return "", nil
	}

	elfFile, err := elf.Open(executablePath)
	if err != nil {
		return "", nil
	}
	defer elfFile.Close()

	// Read .rodata section
	section := elfFile.Section(".rodata")
	if section == nil {
		return "", nil
	}

	data, err := section.Data()
	if err != nil {
		return "", nil
	}

	// Look for PHP version pattern (e.g., "PHP/8.2.10")
	versionRegex := regexp.MustCompile(`PHP/(\d+\.\d+\.\d+)`)
	matches := versionRegex.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return matches[1], nil
	}

	// Alternative pattern (e.g., "8.2.10")
	altRegex := regexp.MustCompile(`\b(\d+\.\d+\.\d+)\b`)
	matches = altRegex.FindStringSubmatch(string(data))
	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", nil
}

// GetDynamicLibraries returns all dynamic libraries the binary depends on
func (ea *ELFAnalyzer) GetDynamicLibraries(executablePath string) ([]string, error) {
	if executablePath == "" {
		return nil, nil
	}

	elfFile, err := elf.Open(executablePath)
	if err != nil {
		return nil, nil
	}
	defer elfFile.Close()

	libraries, err := elfFile.ImportedLibraries()
	if err != nil {
		return nil, err
	}

	return libraries, nil
}

// GetLibcType determines if the binary uses musl or glibc
func (ea *ELFAnalyzer) GetLibcType(executablePath string) (string, error) {
	if executablePath == "" {
		return "", nil
	}

	elfFile, err := elf.Open(executablePath)
	if err != nil {
		return "", nil
	}
	defer elfFile.Close()

	// Check interpreter (program interpreter)
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_INTERP {
			data := make([]byte, prog.Filesz)
			_, err := prog.ReadAt(data, 0)
			if err != nil {
				continue
			}

			interpreter := string(data)
			if strings.Contains(interpreter, "musl") {
				return "musl", nil
			}
			if strings.Contains(interpreter, "ld-linux") {
				return "glibc", nil
			}
		}
	}

	return "", nil
}

// HasPythonSymbols checks if binary has Python-related symbols
func (ea *ELFAnalyzer) HasPythonSymbols(executablePath string) (bool, string, error) {
	if executablePath == "" {
		return false, "", nil
	}

	elfFile, err := elf.Open(executablePath)
	if err != nil {
		return false, "", nil
	}
	defer elfFile.Close()

	// Check for Python library dependencies
	libraries, err := elfFile.ImportedLibraries()
	if err == nil {
		pythonVersionRegex := regexp.MustCompile(`libpython(\d+\.\d+)`)
		for _, lib := range libraries {
			if matches := pythonVersionRegex.FindStringSubmatch(lib); len(matches) > 1 {
				return true, matches[1], nil
			}
			if strings.Contains(lib, "libpython3") {
				return true, "3.x", nil
			}
			if strings.Contains(lib, "libpython2") {
				return true, "2.x", nil
			}
		}
	}

	return false, "", nil
}

// ReadBinaryContent reads a portion of binary file for signature checking
func ReadBinaryContent(filePath string, maxBytes int) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buffer := make([]byte, maxBytes)
	n, err := file.Read(buffer)
	if err != nil && n == 0 {
		return nil, err
	}

	return buffer[:n], nil
}

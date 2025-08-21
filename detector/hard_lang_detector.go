package detector

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// HardLanguageDetector inspects an image's layers and returns the detected language
func HardLanguageDetector(imageName string) (string, error) {
	ref, err := name.ParseReference(imageName)
	if err != nil {
		return "Unknown", fmt.Errorf("error parsing image name: %w", err)
	}

	// This uses the local cache automatically and handles authentication
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return "Unknown", fmt.Errorf("error getting image from registry: %w", err)
	}

	// iterate over the image layers
	layers, err := img.Layers()
	if err != nil {
		return "Unknown", fmt.Errorf("error getting image layers: %w", err)
	}

	for _, layer := range layers {
		reader, err := layer.Uncompressed()
		if err != nil {
			log.Printf("Error getting uncompressed layer: %v. Skipping.", err)
			continue
		}
		defer reader.Close()

		detected := scanTarballForLanguage(reader)
		if detected != "Unknown" {
			return detected, nil
		}
	}

	return "Unknown", nil
}

// scanTarballForLanguage reads a tarball stream and looks for language-specific files
func scanTarballForLanguage(reader io.Reader) string {
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			log.Printf("Error reading tar header: %v. Skipping.", err)
			return "Unknown"
		}
		// Only check files, not directories
		if header.Typeflag == tar.TypeReg {
			if header.Typeflag == tar.TypeReg && isExecutable(header.FileInfo()) {
				// Read the file content into a buffer
				var fileBytes bytes.Buffer
				if _, err := io.Copy(&fileBytes, tarReader); err != nil {
					log.Printf("Error reading file content for %s: %v", header.Name, err)
					continue
				}

				// Check for Go-specific signature in the binary
				if isGoBinary(fileBytes.Bytes()) {
					fmt.Println("Checking for go binary")
					return "Go"
				}

				// TODO: Add checks for other compiled languages (e.g., Rust, C++)
			}
			// Implements heuristic based on file names
			fileName := header.Name
			if strings.Contains(fileName, "package.json") {
				return "Node.js"
			}
			if strings.Contains(fileName, "go.mod") {
				return "Go"
			}
			if strings.HasSuffix(header.Name, ".jar") {
				return detectJava(tarReader, header.Size)
			}
			if strings.Contains(fileName, "requirements.txt") {
				return "Python"
			}
			if strings.Contains(fileName, ".csproj") {
				return "C#"
			}
			// TODO: add more specific checks e.g., for interpreter binaries in common paths like /usr/bin/
		}

	}
	return "Unknown"
}

// isExecutable checks if a file has an executable permission bit
func isExecutable(fi os.FileInfo) bool {
	// Check if the owner, group, or others have execute permissions
	return fi.Mode()&0111 != 0
}

// isGoBinary checks for the embedded Go version string in a binary file
func isGoBinary(data []byte) bool {
	// This is a common signature embedded by the Go compiler
	if bytes.Contains(data, []byte("go1.")) {
		return true
	}
	return false
}

// detectJava inspects a tarball for Java-related files and frameworks
func detectJava(tarReader *tar.Reader, fileSize int64) string {
	// Read the entire JAR file into a buffer
	var jarBytes bytes.Buffer
	_, err := io.CopyN(&jarBytes, tarReader, fileSize)
	if err != nil {
		log.Printf("Error reading JAR file content: %v", err)
		return "Unknown"
	}

	// Open the JAR file (which is a zip file)
	zipReader, err := zip.NewReader(bytes.NewReader(jarBytes.Bytes()), fileSize)
	if err != nil {
		// This is not a valid zip file, so it's not a standard JAR
		return "Unknown"
	}

	isJava := false
	isSpringBoot := false

	// Check for specific files within the JAR
	for _, file := range zipReader.File {
		// --- 1. Check for Spring Boot directory structure ---
		if strings.HasPrefix(file.Name, "BOOT-INF/") {
			isSpringBoot = true
		}

		// --- 2. Check for the MANIFEST file ---
		if file.Name == "META-INF/MANIFEST.MF" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			defer rc.Close()

			manifestBytes, err := io.ReadAll(rc)
			if err != nil {
				continue
			}

			manifestContent := string(manifestBytes)
			// Check for Spring Boot-specific manifest entries
			if strings.Contains(manifestContent, "Spring-Boot-Classes") ||
				strings.Contains(manifestContent, "Spring-Boot-Library") {
				isSpringBoot = true
			}
		}
	}

	if isSpringBoot {
		return "Java (Spring Boot)"
	}

	// Check for other standard Java clues
	if isJava {
		return "Java"
	}

	return "Unknown"
}

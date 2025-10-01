package detector

import (
	"fmt"
	"regexp"
	"strings"
)

// RuntimeInspector provides enhanced runtime inspection capabilities
type RuntimeInspector struct{}

// FileSystemSignature represents language-specific files to look for
type FileSystemSignature struct {
	Language   string
	Files      []string
	Priority   int
	Confidence string
}

var fileSystemSignatures = []FileSystemSignature{
	{
		Language:   "nodejs",
		Files:      []string{"package.json", "node_modules", "yarn.lock", "package-lock.json"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Python",
		Files:      []string{"requirements.txt", "setup.py", "Pipfile", "pyproject.toml", "poetry.lock"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Java",
		Files:      []string{"pom.xml", "build.gradle", "gradlew", ".mvn", "MANIFEST.MF"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Go",
		Files:      []string{"go.mod", "go.sum", "Gopkg.toml", "Gopkg.lock"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Ruby",
		Files:      []string{"Gemfile", "Gemfile.lock", "Rakefile", ".ruby-version"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   ".NET",
		Files:      []string{"*.csproj", "*.fsproj", "*.vbproj", "appsettings.json", "web.config"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "PHP",
		Files:      []string{"composer.json", "composer.lock", "artisan", "index.php"},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language:   "Rust",
		Files:      []string{"Cargo.toml", "Cargo.lock"},
		Priority:   10,
		Confidence: "high",
	},
}

// PortSignature maps common ports to languages/frameworks
type PortSignature struct {
	Port       string
	Language   string
	Framework  string
	Confidence string
}

var portSignatures = []PortSignature{
	// Databases
	{Port: "27017", Language: "MongoDB", Framework: "Database", Confidence: "high"},
	{Port: "27018", Language: "MongoDB", Framework: "Database Shard", Confidence: "high"},
	{Port: "27019", Language: "MongoDB", Framework: "Database Config", Confidence: "high"},
	{Port: "5432", Language: "PostgreSQL", Framework: "Database", Confidence: "high"},
	{Port: "3306", Language: "MySQL", Framework: "Database", Confidence: "high"},
	{Port: "3307", Language: "MySQL", Framework: "Database", Confidence: "high"},
	{Port: "1521", Language: "Oracle", Framework: "Database", Confidence: "high"},
	{Port: "1433", Language: "MSSQL", Framework: "Database", Confidence: "high"},
	{Port: "5984", Language: "CouchDB", Framework: "Database", Confidence: "high"},
	{Port: "7000", Language: "Cassandra", Framework: "Database", Confidence: "high"},
	{Port: "7001", Language: "Cassandra", Framework: "Database SSL", Confidence: "high"},
	{Port: "9042", Language: "Cassandra", Framework: "Database CQL", Confidence: "high"},
	{Port: "8086", Language: "InfluxDB", Framework: "Time Series DB", Confidence: "high"},
	{Port: "9000", Language: "ClickHouse", Framework: "Database", Confidence: "high"},
	{Port: "8123", Language: "ClickHouse", Framework: "Database HTTP", Confidence: "high"},
	{Port: "28015", Language: "RethinkDB", Framework: "Database", Confidence: "high"},
	{Port: "7687", Language: "Neo4j", Framework: "Graph Database", Confidence: "high"},
	{Port: "7474", Language: "Neo4j", Framework: "Graph Database HTTP", Confidence: "high"},
	{Port: "8529", Language: "ArangoDB", Framework: "Multi-Model Database", Confidence: "high"},

	// Key-Value Stores & Caches
	{Port: "6379", Language: "Redis", Framework: "Cache", Confidence: "high"},
	{Port: "6380", Language: "Redis", Framework: "Cache", Confidence: "high"},
	{Port: "11211", Language: "Memcached", Framework: "Cache", Confidence: "high"},
	{Port: "2379", Language: "etcd", Framework: "Key-Value Store", Confidence: "high"},
	{Port: "2380", Language: "etcd", Framework: "Key-Value Store Peer", Confidence: "high"},

	// Search & Analytics
	{Port: "9200", Language: "Elasticsearch", Framework: "Search Engine", Confidence: "high"},
	{Port: "9300", Language: "Elasticsearch", Framework: "Search Engine Transport", Confidence: "high"},
	{Port: "8983", Language: "Solr", Framework: "Search Engine", Confidence: "high"},
	{Port: "5601", Language: "Kibana", Framework: "Analytics", Confidence: "high"},

	// Message Queues
	{Port: "5672", Language: "RabbitMQ", Framework: "Message Queue", Confidence: "high"},
	{Port: "15672", Language: "RabbitMQ", Framework: "Message Queue Management", Confidence: "high"},
	{Port: "9092", Language: "Kafka", Framework: "Message Queue", Confidence: "high"},
	{Port: "6650", Language: "Pulsar", Framework: "Message Queue", Confidence: "high"},
	{Port: "4222", Language: "NATS", Framework: "Message Queue", Confidence: "high"},
}

// ProcessPatterns for detecting language from running processes
type ProcessPattern struct {
	Language   string
	Framework  string
	Patterns   []string
	Priority   int
	Confidence string
}

var processPatterns = []ProcessPattern{
	{
		Language: "Java",
		Framework: "Spring Boot",
		Patterns: []string{
			"spring-boot",
			"org.springframework.boot",
			"java.*-jar.*spring",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Java",
		Framework: "Tomcat",
		Patterns: []string{
			"catalina",
			"org.apache.catalina",
			"tomcat",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Java",
		Framework: "",
		Patterns: []string{
			"^java ",
			"/java ",
			"java.*-jar",
			"openjdk",
		},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language: "nodejs",
		Framework: "Express",
		Patterns: []string{
			"node.*express",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "nodejs",
		Framework: "Next.js",
		Patterns: []string{
			"next start",
			"next dev",
			".next",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "nodejs",
		Framework: "NestJS",
		Patterns: []string{
			"nest start",
			"@nestjs",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "nodejs",
		Framework: "",
		Patterns: []string{
			"^node ",
			"/node ",
			"npm start",
			"npm run",
		},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language: "Python",
		Framework: "Django",
		Patterns: []string{
			"django",
			"manage.py",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Python",
		Framework: "Flask",
		Patterns: []string{
			"flask",
			"gunicorn.*flask",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Python",
		Framework: "FastAPI",
		Patterns: []string{
			"fastapi",
			"uvicorn",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Python",
		Framework: "",
		Patterns: []string{
			"^python",
			"/python",
			"gunicorn",
			"celery",
		},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language: "Ruby",
		Framework: "Rails",
		Patterns: []string{
			"rails",
			"puma.*config.ru",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Ruby",
		Framework: "Sinatra",
		Patterns: []string{
			"sinatra",
			"rackup",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "Ruby",
		Framework: "",
		Patterns: []string{
			"^ruby",
			"/ruby",
			"puma",
		},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language: ".NET",
		Framework: "ASP.NET Core",
		Patterns: []string{
			"dotnet.*dll",
			"aspnetcore",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: ".NET",
		Framework: "",
		Patterns: []string{
			"^dotnet",
			"/dotnet",
		},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language: "PHP",
		Framework: "Laravel",
		Patterns: []string{
			"artisan",
			"laravel",
		},
		Priority:   15,
		Confidence: "high",
	},
	{
		Language: "PHP",
		Framework: "",
		Patterns: []string{
			"php-fpm",
			"^php ",
			"/php",
		},
		Priority:   10,
		Confidence: "high",
	},
	{
		Language: "Go",
		Framework: "",
		Patterns: []string{
			"/app/",
			"/usr/local/bin/.*server",
			"/usr/local/bin/.*service",
		},
		Priority:   5,
		Confidence: "medium",
	},
}

// PackageManagerSignature represents package managers and their associated languages
type PackageManagerSignature struct {
	Binary     string
	Language   string
	Priority   int
	Confidence string
}

var packageManagerSignatures = []PackageManagerSignature{
	{Binary: "/usr/bin/npm", Language: "nodejs", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/bin/npm", Language: "nodejs", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/yarn", Language: "nodejs", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/bin/yarn", Language: "nodejs", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/pnpm", Language: "nodejs", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/pip", Language: "Python", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/pip3", Language: "Python", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/bin/pip", Language: "Python", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/gem", Language: "Ruby", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/bin/gem", Language: "Ruby", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/go/bin/go", Language: "Go", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/go", Language: "Go", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/mvn", Language: "Java", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/gradle", Language: "Java", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/composer", Language: "PHP", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/bin/composer", Language: "PHP", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/dotnet", Language: ".NET", Priority: 10, Confidence: "high"},
	{Binary: "/usr/local/bin/dotnet", Language: ".NET", Priority: 10, Confidence: "high"},
	{Binary: "/usr/bin/cargo", Language: "Rust", Priority: 10, Confidence: "high"},
}

// BinarySignature represents compiled binary detection patterns
type BinarySignature struct {
	Pattern    string
	Language   string
	Confidence string
}

var binarySignatures = []BinarySignature{
	{Pattern: "Go BuildID", Language: "Go", Confidence: "high"},
	{Pattern: "statically linked", Language: "Go", Confidence: "medium"},
	{Pattern: "libjvm", Language: "Java", Confidence: "high"},
	{Pattern: "libpython", Language: "Python", Confidence: "high"},
	{Pattern: "libnode", Language: "nodejs", Confidence: "high"},
	{Pattern: "libruby", Language: "Ruby", Confidence: "high"},
	{Pattern: "libcoreclr", Language: ".NET", Confidence: "high"},
}

// AnalyzeProcesses analyzes process list with enhanced pattern matching
func (ri *RuntimeInspector) AnalyzeProcesses(processes []string) (string, string, string, []string) {
	processString := strings.ToLower(strings.Join(processes, " "))
	var evidence []string
	bestMatch := struct {
		language   string
		framework  string
		confidence string
		priority   int
	}{}

	for _, pattern := range processPatterns {
		for _, patternStr := range pattern.Patterns {
			matched, _ := regexp.MatchString(patternStr, processString)
			if matched {
				evidence = append(evidence, fmt.Sprintf("Process pattern matched: %s", patternStr))
				if pattern.Priority > bestMatch.priority {
					bestMatch.language = pattern.Language
					bestMatch.framework = pattern.Framework
					bestMatch.confidence = pattern.Confidence
					bestMatch.priority = pattern.Priority
				}
			}
		}
	}

	if bestMatch.language != "" {
		return bestMatch.language, bestMatch.framework, bestMatch.confidence, evidence
	}

	return "", "", "", evidence
}

// DetectFileSystemSignatures checks for language-specific files in the container
func (ri *RuntimeInspector) DetectFileSystemSignatures(namespace, podName, containerName string, execFunc func(string, string, string, []string) (string, error)) (string, string, []string) {
	var evidence []string

	for _, sig := range fileSystemSignatures {
		// Try to find files in common locations
		searchPaths := []string{
			"/app",
			"/usr/src/app",
			"/opt/app",
			"/home/app",
			"/",
			"/workspace",
		}

		for _, path := range searchPaths {
			for _, file := range sig.Files {
				// Try to check if file exists
				cmd := []string{"sh", "-c", fmt.Sprintf("test -e %s/%s && echo 'found' || echo 'notfound'", path, file)}
				output, err := execFunc(namespace, podName, containerName, cmd)
				if err == nil && strings.Contains(output, "found") {
					evidence = append(evidence, fmt.Sprintf("Found %s in %s", file, path))
					return sig.Language, sig.Confidence, evidence
				}
			}
		}
	}

	return "", "", evidence
}

// DetectPackageManagers checks for the presence of language-specific package managers
func (ri *RuntimeInspector) DetectPackageManagers(namespace, podName, containerName string, execFunc func(string, string, string, []string) (string, error)) (string, string, []string) {
	var evidence []string
	bestMatch := struct {
		language   string
		confidence string
		priority   int
	}{}

	for _, pm := range packageManagerSignatures {
		// Check if package manager binary exists
		output, err := execFunc(namespace, podName, containerName, []string{"sh", "-c", fmt.Sprintf("test -f %s && echo found", pm.Binary)})
		if err == nil && strings.Contains(output, "found") {
			evidence = append(evidence, fmt.Sprintf("Package manager found: %s", pm.Binary))
			if pm.Priority > bestMatch.priority {
				bestMatch.language = pm.Language
				bestMatch.confidence = pm.Confidence
				bestMatch.priority = pm.Priority
			}
		}
	}

	return bestMatch.language, bestMatch.confidence, evidence
}

// DetectBinarySignature analyzes the main process binary for language signatures
func (ri *RuntimeInspector) DetectBinarySignature(namespace, podName, containerName string, execFunc func(string, string, string, []string) (string, error)) (string, string, []string) {
	var evidence []string

	// Try to get the main process binary
	commands := [][]string{
		{"sh", "-c", "file /proc/1/exe 2>/dev/null"},
		{"sh", "-c", "file /usr/local/bin/* 2>/dev/null | head -5"},
		{"sh", "-c", "ldd /proc/1/exe 2>/dev/null"},
	}

	var binaryInfo string
	for _, cmd := range commands {
		output, err := execFunc(namespace, podName, containerName, cmd)
		if err == nil && output != "" {
			binaryInfo += output + " "
		}
	}

	if binaryInfo == "" {
		return "", "", evidence
	}

	binaryInfoLower := strings.ToLower(binaryInfo)
	bestMatch := struct {
		language   string
		confidence string
	}{}

	// Check against binary signatures
	for _, sig := range binarySignatures {
		if strings.Contains(binaryInfoLower, strings.ToLower(sig.Pattern)) {
			evidence = append(evidence, fmt.Sprintf("Binary signature: %s", sig.Pattern))
			// High confidence matches override medium/low
			if bestMatch.confidence == "" || sig.Confidence == "high" {
				bestMatch.language = sig.Language
				bestMatch.confidence = sig.Confidence
			}
		}
	}

	return bestMatch.language, bestMatch.confidence, evidence
}

// DetectByPort analyzes listening ports to infer language/framework
func (ri *RuntimeInspector) DetectByPort(namespace, podName, containerName string, execFunc func(string, string, string, []string) (string, error)) (string, string, string, []string) {
	var evidence []string

	// Try different commands to get listening ports
	commands := [][]string{
		{"sh", "-c", "netstat -tlnp 2>/dev/null | grep LISTEN"},
		{"sh", "-c", "ss -tlnp 2>/dev/null"},
		{"sh", "-c", "lsof -iTCP -sTCP:LISTEN 2>/dev/null"},
	}

	var portOutput string
	for _, cmd := range commands {
		output, err := execFunc(namespace, podName, containerName, cmd)
		if err == nil && output != "" {
			portOutput = output
			break
		}
	}

	if portOutput == "" {
		return "", "", "", evidence
	}

	// Match ports from output
	bestMatch := struct {
		language   string
		framework  string
		confidence string
	}{}

	for _, portSig := range portSignatures {
		if strings.Contains(portOutput, ":"+portSig.Port) {
			evidence = append(evidence, fmt.Sprintf("Listening on port %s", portSig.Port))
			// Prioritize higher confidence matches
			if bestMatch.confidence == "" || portSig.Confidence == "high" {
				bestMatch.language = portSig.Language
				bestMatch.framework = portSig.Framework
				bestMatch.confidence = portSig.Confidence
			}
		}
	}

	if bestMatch.language != "" {
		return bestMatch.language, bestMatch.framework, bestMatch.confidence, evidence
	}

	return "", "", "", evidence
}

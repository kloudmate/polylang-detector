package detector

var otelSupportedLanguages = map[string]string{
	"Go":     "go",
	"nodejs": "node",
	"Python": "python",
	"Java":   "java",
	".NET":   "dotnet",
}

var envVarKeywords = map[string]string{
	"GODEBUG":                     "Go",
	"GOENV":                       "Go",
	"GOOS":                        "Go",
	"GOPATH":                      "Go",
	"NODE_ENV":                    "Node.js",
	"NPM_CONFIG":                  "Node.js",
	"npm_package_":                "Node.js",
	"PYTHONPATH":                  "Python",
	"VIRTUAL_ENV":                 "Python",
	"PYTHONDONTWRITEBYTECODE":     "Python",
	"JAVA_HOME":                   "Java",
	"JAVA_TOOL_OPTIONS":           "Java",
	"JAVA_VERSION":                "Java",
	"JRE_HOME":                    "Java",
	"MAVEN_HOME":                  "Java",
	"GRADLE_HOME":                 "Java",
	"CLASSPATH":                   "Java",
	"ASPNETCORE_URLS":             ".NET",
	"DOTNET_RUNNING_IN_CONTAINER": ".NET",
}

package detector

var imageKeywords = map[string]string{
	"golang":                   "Go",
	"node":                     "Node.js",
	"python":                   "Python",
	"openjdk":                  "Java",
	"java":                     "Java",
	"alpine":                   "Base Image (Alpine Linux)",
	"ubuntu":                   "Base Image (Ubuntu Linux)",
	"busybox":                  "Base Image (BusyBox)",
	"mcr.microsoft.com/dotnet": "dotnet",
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
	"JRE_HOME":                    "Java",
	"MAVEN_HOME":                  "Java",
	"GRADLE_HOME":                 "Java",
	"CLASSPATH":                   "Java",
	"ASPNETCORE_URLS":             ".NET",
	"DOTNET_RUNNING_IN_CONTAINER": ".NET",
}

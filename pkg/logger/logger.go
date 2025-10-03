package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// DomainLogger wraps zap logger with enterprise-grade structured logging
type DomainLogger struct {
	*zap.Logger
}

// NewProductionLogger creates a production-ready logger with enterprise formatting
func NewProductionLogger() (*DomainLogger, error) {
	config := zap.NewProductionConfig()
	config.EncoderConfig.TimeKey = "timestamp"
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.EncoderConfig.MessageKey = "message"
	config.EncoderConfig.LevelKey = "severity"
	config.EncoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	logger, err := config.Build(
		zap.AddCallerSkip(1),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)
	if err != nil {
		return nil, err
	}

	return &DomainLogger{Logger: logger}, nil
}

// Language Detection Domain Events
func (l *DomainLogger) LanguageDetectionStarted(namespace, podName, containerName string) {
	l.Info("Language detection initiated",
		zap.String("event", "detection.started"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("container", containerName),
	)
}

func (l *DomainLogger) LanguageDetected(namespace, podName, containerName, image, language, framework, confidence string) {
	fields := []zap.Field{
		zap.String("event", "detection.completed"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("container", containerName),
		zap.String("image", image),
		zap.String("language", language),
		zap.String("confidence", confidence),
	}

	if framework != "" {
		fields = append(fields, zap.String("framework", framework))
	}

	l.Info("Language successfully detected", fields...)
}

func (l *DomainLogger) LanguageDetectedWithTier(namespace, podName, containerName, image, language, framework, confidence, tier string) {
	fields := []zap.Field{
		zap.String("event", "detection.completed"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("container", containerName),
		zap.String("image", image),
		zap.String("language", language),
		zap.String("confidence", confidence),
		zap.String("detection_tier", tier),
	}

	if framework != "" {
		fields = append(fields, zap.String("framework", framework))
	}

	l.Info("Language successfully detected", fields...)
}

func (l *DomainLogger) LanguageDetectionFailed(namespace, podName, containerName string, err error) {
	l.Error("Language detection failed",
		zap.String("event", "detection.failed"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("container", containerName),
		zap.Error(err),
	)
}

func (l *DomainLogger) UnsupportedLanguage(language string) {
	l.Warn("Language not supported for auto-instrumentation",
		zap.String("event", "detection.unsupported"),
		zap.String("language", language),
	)
}

// Cache Domain Events
func (l *DomainLogger) CacheHit(image, language string) {
	l.Debug("Cache hit - using cached detection result",
		zap.String("event", "cache.hit"),
		zap.String("image", image),
		zap.String("language", language),
	)
}

func (l *DomainLogger) CacheMiss(image string) {
	l.Debug("Cache miss - performing new detection",
		zap.String("event", "cache.miss"),
		zap.String("image", image),
	)
}

func (l *DomainLogger) CacheStored(image, language string) {
	l.Debug("Detection result cached",
		zap.String("event", "cache.stored"),
		zap.String("image", image),
		zap.String("language", language),
	)
}

// RPC Domain Events
func (l *DomainLogger) RPCConnectionInitiated(address string) {
	l.Info("Attempting RPC connection",
		zap.String("event", "rpc.connection.initiated"),
		zap.String("server_address", address),
	)
}

func (l *DomainLogger) RPCConnectionEstablished(address string) {
	l.Info("RPC connection established successfully",
		zap.String("event", "rpc.connection.established"),
		zap.String("server_address", address),
	)
}

func (l *DomainLogger) RPCConnectionFailed(address string, err error) {
	l.Warn("RPC connection failed, will retry",
		zap.String("event", "rpc.connection.failed"),
		zap.String("server_address", address),
		zap.Error(err),
	)
}

func (l *DomainLogger) RPCBatchQueued(batchSize, queueSize int) {
	l.Debug("Detection results queued for transmission",
		zap.String("event", "rpc.batch.queued"),
		zap.Int("current_batch_size", batchSize),
		zap.Int("max_queue_size", queueSize),
	)
}

func (l *DomainLogger) RPCBatchSending(count int, reason string) {
	l.Info("Transmitting detection results to config updater",
		zap.String("event", "rpc.batch.sending"),
		zap.Int("result_count", count),
		zap.String("trigger_reason", reason),
	)
}

func (l *DomainLogger) RPCBatchSent(count int, response string) {
	l.Info("Detection results transmitted successfully",
		zap.String("event", "rpc.batch.sent"),
		zap.Int("result_count", count),
		zap.String("server_response", response),
	)
}

func (l *DomainLogger) RPCBatchFailed(count int, err error) {
	l.Error("Failed to transmit detection results",
		zap.String("event", "rpc.batch.failed"),
		zap.Int("result_count", count),
		zap.Error(err),
	)
}

// eBPF Scanning Domain Events
func (l *DomainLogger) EbpfScanStarted() {
	l.Info("eBPF-based pod scanning started",
		zap.String("event", "ebpf.scan.started"),
	)
}

func (l *DomainLogger) EbpfScanStopped() {
	l.Info("eBPF-based pod scanning stopped",
		zap.String("event", "ebpf.scan.stopped"),
	)
}

func (l *DomainLogger) EbpfScanCycleStarted(count int) {
	l.Info("Starting eBPF scan cycle",
		zap.String("event", "ebpf.scan.cycle_started"),
		zap.Int("total_pods", count),
	)
}

func (l *DomainLogger) EbpfScanCycleCompleted(scanned, detected int) {
	l.Info("eBPF scan cycle completed",
		zap.String("event", "ebpf.scan.cycle_completed"),
		zap.Int("pods_scanned", scanned),
		zap.Int("pods_detected", detected),
	)
}

// Application Lifecycle Events
func (l *DomainLogger) ApplicationStarting(version, commit string) {
	l.Info("Polylang Detector starting",
		zap.String("event", "application.starting"),
		zap.String("version", version),
		zap.String("commit", commit),
	)
}

func (l *DomainLogger) ApplicationReady() {
	l.Info("Polylang Detector ready to process workloads",
		zap.String("event", "application.ready"),
	)
}

func (l *DomainLogger) ApplicationShuttingDown(signal string) {
	l.Info("Graceful shutdown initiated",
		zap.String("event", "application.shutdown.initiated"),
		zap.String("signal", signal),
	)
}

func (l *DomainLogger) ApplicationShutdownComplete() {
	l.Info("Graceful shutdown completed",
		zap.String("event", "application.shutdown.completed"),
	)
}

// Kubernetes Client Events
func (l *DomainLogger) K8sClientInitialized(mode string) {
	l.Info("Kubernetes client initialized",
		zap.String("event", "kubernetes.client.initialized"),
		zap.String("mode", mode),
	)
}

func (l *DomainLogger) K8sClientInitFailed(err error) {
	l.Error("Failed to initialize Kubernetes client",
		zap.String("event", "kubernetes.client.init_failed"),
		zap.Error(err),
	)
}

func (l *DomainLogger) DeploymentInfoRetrieved(namespace, podName, deploymentName, kind string) {
	l.Debug("Workload ownership information retrieved",
		zap.String("event", "kubernetes.deployment.info_retrieved"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("deployment", deploymentName),
		zap.String("kind", kind),
	)
}

func (l *DomainLogger) DeploymentInfoFailed(namespace, podName string, err error) {
	l.Warn("Failed to retrieve workload ownership information",
		zap.String("event", "kubernetes.deployment.info_failed"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.Error(err),
	)
}

// eBPF Detection Domain Events
func (l *DomainLogger) EbpfDetectionStarted(namespace, podName string) {
	l.Info("eBPF-based language detection initiated",
		zap.String("event", "ebpf.detection.started"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
	)
}

func (l *DomainLogger) EbpfDetectionSucceeded(namespace, podName, language, method string) {
	l.Info("eBPF detection succeeded",
		zap.String("event", "ebpf.detection.succeeded"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.String("language", language),
		zap.String("detection_method", method),
	)
}

func (l *DomainLogger) EbpfDetectionFailed(namespace, podName string, err error) {
	l.Warn("eBPF detection failed, falling back to exec-based detection",
		zap.String("event", "ebpf.detection.failed"),
		zap.String("namespace", namespace),
		zap.String("pod", podName),
		zap.Error(err),
	)
}

func (l *DomainLogger) EbpfProcessInspected(pid int, language, executable string) {
	l.Debug("Process inspected via eBPF",
		zap.String("event", "ebpf.process.inspected"),
		zap.Int("pid", pid),
		zap.String("language", language),
		zap.String("executable", executable),
	)
}

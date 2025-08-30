package detector

import (
	"context"
	"net/rpc"
	"time"

	"k8s.io/klog/v2"
)

// DialWithRetry attempts to connect to the RPC server with a backoff
func (c *PolylangDetector) DialWithRetry(ctx context.Context, retryInterval time.Duration) error {
	time.Sleep(time.Second * 10)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			c.Logger.Sugar().Infof("Attempting to connect to RPC server at %s...", c.ServerAddr)
			client, err := rpc.Dial("tcp", c.ServerAddr)
			if err == nil {
				klog.Info("Successfully connected to RPC server.")
				c.RpcClient = client
				return nil
			}
			c.Logger.Sugar().Warnf("failed to connect to RPC server: %v. Retrying in %v...", err, retryInterval)
			time.Sleep(retryInterval)
		}
	}
}

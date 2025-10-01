package detector

import (
	"context"
	"net/rpc"
	"time"
)

// DialWithRetry attempts to connect to the RPC server with a backoff
func (c *PolylangDetector) DialWithRetry(ctx context.Context, retryInterval time.Duration) error {
	time.Sleep(time.Second * 10)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			c.DomainLogger.(interface {
				RPCConnectionInitiated(address string)
			}).RPCConnectionInitiated(c.ServerAddr)

			client, err := rpc.Dial("tcp", c.ServerAddr)
			if err == nil {
				c.DomainLogger.(interface {
					RPCConnectionEstablished(address string)
				}).RPCConnectionEstablished(c.ServerAddr)
				c.RpcClient = client
				return nil
			}

			c.DomainLogger.(interface {
				RPCConnectionFailed(address string, err error)
			}).RPCConnectionFailed(c.ServerAddr, err)

			time.Sleep(retryInterval)
		}
	}
}

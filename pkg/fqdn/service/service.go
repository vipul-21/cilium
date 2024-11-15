package service

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	identityPkg "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/dns"
	"github.com/google/uuid"

	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/time"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

type updateOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) error

type FQDNDataServer struct {
	pb.UnimplementedFQDNDataServer

	ctx    context.Context
	cancel context.CancelFunc

	endpointManager  *endpointmanager.EndpointManager
	streams          lock.Map[pb.FQDNData_SubscribeToDNSPoliciesServer, context.CancelFunc]
	updateOnDNSMsg   updateOnDNSMsgFunc
	dnsMappingResult lock.Map[string, bool]

	snapshotMutex   lock.Mutex
	currentSnapshot map[identityPkg.NumericIdentity]*policy.CachedSelectorPolicy
}

var (
	log  = logging.DefaultLogger.WithField(logfields.LogSubsys, "fqdn/server")
	kaep = keepalive.EnforcementPolicy{
		PermitWithoutStream: true, // Allow pings even when there are no active streams
	}
	kasp = keepalive.ServerParameters{
		Time:    5 * time.Second, // Ping the client if it is idle for 5 seconds to ensure the connection is still active
		Timeout: 1 * time.Second, // Wait 1 second for the ping ack before assuming the connection is dead
	}
)

func (s *FQDNDataServer) SubscribeToDNSPolicies(stream pb.FQDNData_SubscribeToDNSPoliciesServer) error {
	streamCtx, cancel := context.WithCancel(stream.Context())
	s.streams.Store(stream, cancel)

	go func() {
		<-streamCtx.Done()
		// If the client has closed the connection, the context will be done
		log.Info("Client has closed the connection, closing the stream")
		s.DeleteStream(stream)
	}()

	// Start a goroutine to receive the DNS policies ACKs
	go func() {
		if err := s.ReceiveDNSpolicesACK(stream); err != nil {
			log.Errorf("Error receiving DNS policies ACK: %v", err)
			cancel() // Cancel the context to close the stream
		}
	}()

	//Send the current state of the DNS rules
	go func() {
		log.Debugf("Sending current state of DNS rules")

		// Send the current state of the DNS rules
		s.snapshotMutex.Lock()
		currentSnapshot := s.currentSnapshot
		s.snapshotMutex.Unlock()
		if err := s.UpdatePolicyRulesLocked(currentSnapshot); err != nil {
			log.Errorf("Error sending current state of DNS rules: %v", err)
			cancel() // Cancel the context to close the stream
		}
	}()

	log.Debugf("SubscribeToDNSRules waiting for context to be done")
	select {
	case <-streamCtx.Done():
		log.Info("Closing the stream")
		s.DeleteStream(stream)
		return streamCtx.Err()
	case <-s.ctx.Done():
		log.Info("SubscribeToDNSRules done")
		return s.ctx.Err()
	}
}

func (s *FQDNDataServer) ReceiveDNSpolicesACK(stream pb.FQDNData_SubscribeToDNSPoliciesServer) error {
	for {
		select {
		case <-s.ctx.Done():
			log.Info("Stopping the stream")
			return s.ctx.Err()
		case <-stream.Context().Done():
			log.Info("Stream context is finished, closing the stream")
			return stream.Context().Err()
		default:
			update, err := stream.Recv()
			if err != nil {
				log.Errorf("Failed to receive update: %v", err)
				return err
			}
			log.Debugf("Received update: %v", update)
			requestId := update.GetRequestId()
			_, ok := s.dnsMappingResult.Load(requestId)
			if !ok {
				log.Errorf("Response channel not found for dns message id: %s", requestId)
			} else {
				log.Debugf("Received response for dns message id: %s", requestId)

				// We can send cancel signal to the channel if the success is false,
				// in that case SDP will recreate the stream.
				if !update.GetSuccess() {
					// If the success is false, we can send cancel signal to the channel
					// in that case SDP will recreate the stream.
					log.Errorf("Failed to update DNS policies")
					cancel, ok := s.streams.Load(stream)
					if ok {
						cancel()
					}
				}

			}
			// Delete the response channel from the map
			s.dnsMappingResult.Delete(requestId)
			log.Debugf("Deleted from local cache for dns message id: %s", requestId)
		}
	}
}

func NewServer(endpointManager *endpointmanager.EndpointManager, updateOnDNSMsg updateOnDNSMsgFunc) *FQDNDataServer {
	ctx, cancel := context.WithCancel(context.Background())

	s := &FQDNDataServer{
		endpointManager: endpointManager,
		updateOnDNSMsg:  updateOnDNSMsg,
		ctx:             ctx,
		cancel:          cancel,
		streams:         lock.Map[pb.FQDNData_SubscribeToDNSPoliciesServer, context.CancelFunc]{},
		currentSnapshot: make(map[identityPkg.NumericIdentity]*policy.CachedSelectorPolicy),
	}

	go func() {
		<-s.ctx.Done()
		log.Info("FQDN service context done, cleaning up resources")
		s.cleanupStreams()
	}()

	return s
}

func (s *FQDNDataServer) UpdatePolicyRulesLocked(policies map[identityPkg.NumericIdentity]*policy.CachedSelectorPolicy) error {
	s.snapshotMutex.Lock()
	defer s.snapshotMutex.Unlock()

	s.currentSnapshot = policies

	requestId := uuid.New().String()
	dnsPolices := &pb.DNSPolicies{
		RequestId: requestId,
	}
	egressL7DnsPolicy := make([]*pb.DNSPolicy, 0, len(policies))
	for identity, po := range policies {
		for l4, _ := range po.RedirectFilters() {
			parseType := l4.GetL7Parser()
			if parseType == policy.ParserTypeDNS {
				for cs, sp := range l4.PerSelectorPolicies {
					dnsServers := make([]*pb.DNSServer, 0, len(cs.GetSelections(versioned.Latest())))
					for _, sel := range cs.GetSelections(versioned.Latest()) {
						dnsServers = append(dnsServers, &pb.DNSServer{
							DnsServerIdentity: uint32(sel),
							DnsServerPort:     uint32(l4.GetPort()),
							DnsServerProto:    uint32(l4.U8Proto),
						})
					}
					dnsPattern := make([]string, 0, len(sp.DNS))
					for _, dns := range sp.DNS {
						if dns.MatchPattern != "" {
							dnsPattern = append(dnsPattern, dns.MatchPattern)
						}
						if dns.MatchName != "" {
							dnsPattern = append(dnsPattern, dns.MatchName)
						}
					}
					egressL7DnsPolicy = append(egressL7DnsPolicy, &pb.DNSPolicy{
						SourceIdentity: uint32(identity),
						DnsServers:     dnsServers,
						DnsPattern:     dnsPattern,
					})
				}
			}
		}
	}

	log.Debugf("Current EgressL7DnsPolicy: %v for request Id %v", egressL7DnsPolicy, requestId)
	dnsPolices.EgressL7DnsPolicy = egressL7DnsPolicy

	log.Debugf("Sending Policy updates to sdp: %v", dnsPolices)
	s.streams.Range(func(key pb.FQDNData_SubscribeToDNSPoliciesServer, cancel context.CancelFunc) bool {
		log.Debugf("Sending update to stream: %v", key)
		stream := key.(pb.FQDNData_SubscribeToDNSPoliciesServer)
		s.dnsMappingResult.Store(requestId, false)
		if err := stream.Send(dnsPolices); err != nil {
			log.Errorf("Failed to send update: %v", err)
			// Cancel the goroutine and remove the stream from the map
			cancel()
		}
		return true
	})
	return nil
}

func (s *FQDNDataServer) DeleteStream(stream pb.FQDNData_SubscribeToDNSPoliciesServer) {
	_, ok := s.streams.Load(stream)
	if ok {
		log.Infof("Deleting stream: %v", stream)
		s.streams.Delete(stream)
	} else {
		log.Warnf("Stream not found: %v", stream)
	}

}

// cleanupStreams handles the cleanup of streams when the server's context is cancelled.
func (s *FQDNDataServer) cleanupStreams() {
	s.streams.Range(func(key pb.FQDNData_SubscribeToDNSPoliciesServer, cancelFunc context.CancelFunc) bool {
		cancelFunc() // Ensure we cancel the context of each stream
		s.streams.Delete(key)
		return true
	})
	log.Info("All streams have been cleaned up")
}

// UpdatesMappings updates the FQDN mapping with the given data
// SDP sends the fqdn mapping to cilium agent
// Steps to update the mapping:
// 1. Get the endpoint from the IP
// 2. If the endpoint is not found, return an error
// 3. If the IPs are not empty, update the cilium agent with the mapping
func (s *FQDNDataServer) UpdatesMappings(ctx context.Context, mappings *pb.FQDNMapping) (*pb.UpdatesMappingsResult, error) {
	log.Debugf("UpdateMappings %v", mappings)
	now := time.Now()
	var ips []netip.Addr

	endpointAddr := netip.MustParseAddr(string(mappings.SourceIp))

	ep := (*s.endpointManager).LookupIP(endpointAddr)
	if ep == nil {
		log.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
		// return fmt.Errorf("endpoint not found for IP: %s", mappings.ClientIp)
		return &pb.UpdatesMappingsResult{}, fmt.Errorf("endpoint not found for IP: %s", mappings.SourceIp)
	}

	if len(mappings.GetIPS()) == 0 {
		// We don't have any IPs to update the mappings with
		return &pb.UpdatesMappingsResult{
			Success: true,
		}, nil
	}

	for _, ip := range mappings.GetIPS() {
		ips = append(ips, netip.MustParseAddr(string(ip)))
	}

	if mappings.GetResponseCode() == dns.RcodeSuccess {
		err := s.updateOnDNSMsg(now, ep, mappings.GetFQDN(), ips, int(mappings.GetTTL()), nil)
		if err != nil {
			return &pb.UpdatesMappingsResult{}, fmt.Errorf("cannot update DNS cache: %v", err)
		}
	}

	return &pb.UpdatesMappingsResult{
		Success: true,
	}, nil
}

// RunServer starts the FQDN service on the given port
func RunServer(port int, server *FQDNDataServer) {
	address := fmt.Sprintf("localhost:%d", port)
	log.Infof("Starting FQDN service on %s", address)
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.KeepaliveEnforcementPolicy(kaep), grpc.KeepaliveParams(kasp))
	pb.RegisterFQDNDataServer(grpcServer, server)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

package ucloud

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/golang/glog"
	gcfg "gopkg.in/gcfg.v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/kubernetes/pkg/api/v1"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/controller"
)

const (
	providerName = "ucloud"
	maxLimit     = 10000000
)

var (
	ULBNotFound = errors.New("ulb not found")
	EIPNotFound = errors.New("eip not found")
)

type CloudConfig struct {
	Global struct {
		ApiURL     string `gcfg:"api-url"`
		PublicKey  string `gcfg:"public-key"`
		PrivateKey string `gcfg:"private-key"`
		Region     string `gcfg:"region"`
		Zone       string `gcfg:"zone"`
		ProjectID  string `gcfg:"project-id"`
		SSHUser    string `gcfg:"ssh-user"`
		SSHKeyFile string `gcfg:"ssh-key-file"`
	}
}

type Cloud struct {
	UClient
	Region    string
	Zone      string
	ProjectID string
	SSHConfig *ssh.ClientConfig
	// UHost instance that we're running on
	selfInstance *UHostInstanceSet
}

func (c *Cloud) Initialize(clientBuilder controller.ControllerClientBuilder) {}

// LoadBalancer implements cloudprovider.Interface interface
// It is supported by ucloud provider
func (c *Cloud) LoadBalancer() (cloudprovider.LoadBalancer, bool) {
	return c, true
}

// Instances implements cloudprovider.Interface interface
// It is supported by ucloud provider
func (c *Cloud) Instances() (cloudprovider.Instances, bool) {
	return c, true
}

// Clusters implements cloudprovider.Interface interface
// It is not supported by ucloud provider
func (c *Cloud) Clusters() (cloudprovider.Clusters, bool) {
	return nil, false
}

// Routes implements cloudprovider.Interface interface
// It is not supported by ucloud provider
func (c *Cloud) Routes() (cloudprovider.Routes, bool) {
	return nil, false
}

// ProviderName implements cloudprovider.Interface interface
// It returns the cloud provider ID.
func (c *Cloud) ProviderName() string {
	return providerName
}

// ScrubDNS implements cloudprovider.Interface interface
// It provides an opportunity for cloud-provider-specific code to process DNS settings for pods.
func (c *Cloud) ScrubDNS(nameservers, searches []string) (nsOut, srchOut []string) {
	return nameservers, searches
}

// Zones implements cloudprovider.Interface interface
// It is supported by ucloud provider
func (c *Cloud) Zones() (cloudprovider.Zones, bool) {
	return c, true
}

// GetZone implements cloudprovider.Zones interface
// It returns the Zone containing the current failure zone and locality region and the program is running on
func (c *Cloud) GetZone() (cloudprovider.Zone, error) {
	return cloudprovider.Zone{
		FailureDomain: c.Zone,
		Region:        c.Region,
	}, nil
}

// NodeAddresses implements cloudprovider.Instances Interface
// It returns the addresses of the specified instance.
func (c *Cloud) NodeAddresses(nodeName types.NodeName) ([]v1.NodeAddress, error) {
	addrs := []v1.NodeAddress{
		v1.NodeAddress{
			Type:    v1.NodeHostName,
			Address: string(nodeName),
		},
	}
	uhostID, err := c.InstanceID(nodeName)
	if err != nil {
		glog.Errorf("failed to get instance id for %s: %v", nodeName, err)
		return addrs, nil
	}
	p := GetUHostInstanceParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		UHostID:   uhostID,
	}
	r, err := c.UClient.GetUHostInstance(p)
	if err != nil {
		glog.Errorf("failed to GetUHostInstance: %v", err)
		return addrs, nil
	}
	if r.RetCode != 0 {
		glog.Errorf("failed to GetUHostInstance: %s", r.Message)
		return addrs, nil
	}
	for _, ip := range r.UHostSet[0].IPSet {
		if ip.Type == "Private" {
			addrs = append(addrs, v1.NodeAddress{Type: v1.NodeInternalIP, Address: ip.IP})
		} else {
			addrs = append(addrs, v1.NodeAddress{Type: v1.NodeExternalIP, Address: ip.IP})
		}
	}
	return addrs, nil
}

// ExternalID implements cloudprovider.Instances interface
// It returns the cloud provider ID of the node with specified NodeName.
func (c *Cloud) ExternalID(nodeName types.NodeName) (string, error) {
	ip := strings.Replace(string(nodeName), "-", ".", -1)
	ids, err := c.getUHostIDs([]string{ip})
	if err != nil {
		glog.Errorf("failed to get uhost id for host %s: %v", ip, err)
		return "", err
	}
	if len(ids) == 0 {
		return "", cloudprovider.InstanceNotFound
	}
	return ids[0], nil
}

// InstanceID implements cloudprovider.Instances interface
// It returns the cloud provider ID of the node with the specified NodeName.
func (c *Cloud) InstanceID(nodeName types.NodeName) (string, error) {
	ip := strings.Replace(string(nodeName), "-", ".", -1)
	ids, err := c.getUHostIDs([]string{ip})
	if err != nil {
		glog.Errorf("failed to get uhost id for host %s: %v", ip, err)
		return "", err
	}
	if len(ids) == 0 {
		return "", cloudprovider.InstanceNotFound
	}
	return ids[0], nil
}

// InstanceType implements cloudprovider.Instances interface
// It returns the type of the specified instance.
func (c *Cloud) InstanceType(nodeName types.NodeName) (string, error) {
	// find instance in UHost
	p1 := DescribeUHostInstanceParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     maxLimit,
	}
	r1, err := c.UClient.DescribeUHostInstance(p1)
	if err != nil {
		glog.Errorf("failed to DescribeUHostInstance: %v", err)
		return "", err
	}
	if r1.RetCode != 0 {
		glog.Errorf("failed to DescribeUHostInstance: %v", r1.Message)
		return "", errors.New(r1.Message)
	}
	hostIP := strings.Replace(string(nodeName), "-", ".", -1)
	for _, host := range r1.UHostSet {
		for _, ip := range host.IPSet {
			if ip.IP == hostIP {
				return host.UHostType, nil
			}
		}
	}

	// find instance in PHost
	p2 := DescribePHostParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     maxLimit,
	}
	r2, err := c.UClient.DescribePHost(p2)
	if err != nil {
		glog.Errorf("failed to DescribePHost: %v", err)
		return "", err
	}
	if r2.RetCode != 0 {
		glog.Errorf("failed to DescribePhost: %v", r2.Message)
		return "", errors.New(r2.Message)
	}
	for _, host := range r2.PHostSet {
		for _, ip := range host.IPSet {
			if ip.IPAddr == hostIP {
				return host.PHostType, nil
			}
		}
	}

	return "", cloudprovider.InstanceNotFound
}

func (c *Cloud) InstanceTypeByProviderID(providerID string) (string, error) {
	return "", nil
}

func (c *Cloud) NodeAddressesByProviderID(providerID string) ([]v1.NodeAddress, error) {
	return nil, nil
}

// AddSSHKeyToAllInstances implements cloudprovider.Instances interface
// It adds an SSH public key as a legal identity for all instances.
func (c *Cloud) AddSSHKeyToAllInstances(user string, keyData []byte) error {
	return errors.New("unimplemented")
}

// CurrentNodeName implement cloudprovider.Instances interface
// It returns the name of the node we are currently running on.
func (c *Cloud) CurrentNodeName(hostname string) (types.NodeName, error) {
	return types.NodeName(hostname), nil
}

// UCloud API doesn't support get ULB by name
func (c *Cloud) describeLoadBalancer(name string) (*ULBSet, error) {
	p := DescribeULBParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     maxLimit,
	}
	resp, err := c.UClient.DescribeULB(p)
	if err != nil {
		glog.Errorf("failed to describe ULB in region %s of project %s", c.Region, c.ProjectID)
		return nil, err
	}
	glog.V(3).Infof("describe ULB response: %+v", resp)
	if resp.RetCode != 0 {
		return nil, ULBNotFound
	}
	for _, lb := range resp.DataSet {
		if lb.Name == name {
			return &lb, nil
		}
	}
	return nil, ULBNotFound
}

func (c *Cloud) createLoadBalancer(name string, hostIDs []string, port int) (string, error) {
	p1 := CreateULBParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		ULBName:   name,
		Tag:       "tidb-k8s",
		OuterMode: "No",
		InnerMode: "Yes",
	}
	r1, err := c.UClient.CreateULB(p1)
	if err != nil {
		glog.Errorf("failed to create ULB with param %+v: %v", p1, err)
		return "", err
	}
	glog.V(3).Infof("create ULB response: %+v", r1)
	if r1.RetCode != 0 {
		return "", errors.New(r1.Message)
	}

	p4 := CreateVServerParam{
		Region:        c.Region,
		ProjectID:     c.ProjectID,
		ULBID:         r1.ULBID,
		VServerName:   "tidb-server",
		Protocol:      "TCP",
		FrontendPort:  port,
		ListenType:    "PacketsTransmit", // RequestProxy | PacketsTransmit
		ClientTimeout: 0,
	}
	r4, err := c.UClient.CreateVServer(p4)
	if err != nil {
		glog.Errorf("failed to create VServer with param %+v: %v", p4, err)
		return "", err
	}
	glog.V(3).Infof("create vserver response: %+v", r4)
	if r4.RetCode != 0 {
		return "", errors.New(r4.Message)
	}

	for _, host := range hostIDs {
		p5 := AllocateBackendParam{
			Region:    c.Region,
			ProjectID: c.ProjectID,
			ULBID:     r1.ULBID,
			VServerID: r4.VServerID,
			// ResourceType: "UHost", // ResourceType is handled in AllocateULB4Backend
			ResourceID: host,
			Port:       port,
			Enabled:    1,
		}
		r5, err := c.UClient.AllocateULB4Backend(p5, c.SSHConfig)
		if err != nil {
			glog.Errorf("failed to allocate ULB for backend with param %+v: %v", p5, err)
			return "", err
		}
		if r5.RetCode != 0 {
			return "", errors.New(r5.Message)
		}
	}

	return r1.ULBID, nil
}

func (c *Cloud) deleteLoadBalancer(name string) error {
	ulbSet, err := c.describeLoadBalancer(name)
	if err != nil && err == ULBNotFound {
		glog.Errorf("failed to describe loadbalancer %s: %v", name, err)
		return nil
	}
	if len(ulbSet.VServerSet) == 0 {
		return errors.New("empty VServerSet for ULBSet")
	}
	ulbIP := ulbSet.PrivateIP
	hostIPs := []string{}
	for _, backend := range ulbSet.VServerSet[0].VServerSet {
		hostIPs = append(hostIPs, backend.PrivateIP)
	}
	p := DeleteULBParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		ULBID:     ulbSet.ULBID,
	}
	r, err := c.UClient.DeleteInternalULB(p, hostIPs, ulbIP)
	if err != nil {
		glog.Errorf("failed to delete internal ULB: %v", err)
		return err
	}
	if r.RetCode != 0 {
		glog.Errorf("failed to delete internal ULB: %v", r.Message)
		return err
	}
	return nil
}

// GetLoadBalancer implements cloudprovider.LoadBanacer interface
// It returns whether the specified load balancer exists, and if so what its status is.
func (c *Cloud) GetLoadBalancer(clusterName string, service *v1.Service) (status *v1.LoadBalancerStatus, exists bool, err error) {
	loadBalancerName := cloudprovider.GetLoadBalancerName(service)
	glog.V(3).Infof("get loadbalancer name: %s", loadBalancerName)
	ulbSet, err := c.describeLoadBalancer(loadBalancerName)
	if err != nil {
		if err == ULBNotFound {
			return nil, false, nil
		}
		glog.Errorf("failed to describe loadbalancer %s: %v", loadBalancerName, err)
		return nil, false, err
	}
	status, err = toLBStatus(ulbSet)
	if err != nil {
		return nil, false, err
	}
	return status, true, nil
}

func toLBStatus(ulbSet *ULBSet) (*v1.LoadBalancerStatus, error) {
	if ulbSet.PrivateIP == "" {
		return nil, EIPNotFound
	}
	ing := v1.LoadBalancerIngress{IP: ulbSet.PrivateIP}
	return &v1.LoadBalancerStatus{Ingress: []v1.LoadBalancerIngress{ing}}, nil
}

// EnsureLoadBalancer implements cloudprovider.LoadBalancer interface
// It creates a new load balancer or updates the existing one.
func (c *Cloud) EnsureLoadBalancer(clusterName string, service *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	loadBalancerName := cloudprovider.GetLoadBalancerName(service)
	glog.V(3).Infof("loadBalancer name: %s", loadBalancerName)
	ulbSet, err := c.describeLoadBalancer(loadBalancerName)
	if err != nil && err != ULBNotFound {
		glog.Errorf("failed to describe loadbalancer %s: %v", loadBalancerName, err)
		return nil, err
	}
	if err == nil {
		status, err := toLBStatus(ulbSet)
		if err != nil {
			glog.Errorf("failed to get load balancer status: %v", err)
			return nil, err
		}
		return status, nil
	}

	// ULB not found, create one
	if len(service.Spec.Ports) == 0 {
		return nil, errors.New("no port found for service")
	}
	backendPort := int(service.Spec.Ports[0].NodePort)
	nodeIPs := []string{}
	for _, node := range nodes {
		for _, addr := range node.Status.Addresses {
			if addr.Type == v1.NodeInternalIP {
				nodeIPs = append(nodeIPs, addr.Address)
				break
			}
		}
	}
	uHostIDs, err := c.getUHostIDs(nodeIPs)
	if err != nil {
		glog.Errorf("failed to get UHost IDs from node IPs %v: %v", nodeIPs, err)
		return nil, err
	}
	ulbID, err := c.createLoadBalancer(loadBalancerName, uHostIDs, backendPort)
	if err != nil {
		glog.Errorf("failed to create loadbalancer(%s) for UHost(%v): %v", loadBalancerName, uHostIDs, err)
		return nil, err
	}
	p := DescribeULBParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		ULBID:     ulbID,
	}
	r, err := c.UClient.DescribeULB(p)
	if err != nil {
		glog.Errorf("failed to DescribeULB for %s: %v", ulbID, err)
		return nil, err
	}
	if r.RetCode != 0 {
		glog.Errorf("failed to DescribeULB for %s: %v", ulbID, err)
		return nil, errors.New(r.Message)
	}
	if len(r.DataSet) == 0 {
		return nil, errors.New("no IP found for load balancer")
	}
	status := &v1.LoadBalancerStatus{
		Ingress: []v1.LoadBalancerIngress{
			v1.LoadBalancerIngress{IP: r.DataSet[0].PrivateIP},
		},
	}
	return status, nil
}

func (c *Cloud) getUHostIDs(nodeIPs []string) ([]string, error) {
	var instanceIDs []string
	// list UHost
	p1 := DescribeUHostInstanceParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     maxLimit,
	}
	r1, err := c.UClient.DescribeUHostInstance(p1)
	if err != nil {
		glog.Errorf("failed to describe uhost instance: %v", err)
		return nil, err
	}
	if r1.RetCode != 0 {
		glog.Errorf("failed to describe uhost instance: %v", r1.Message)
		return nil, errors.New(r1.Message)
	}
	ips := make(map[string]bool)
	for _, ip := range nodeIPs {
		ips[ip] = true
	}
	glog.V(3).Infof("node IPs: %v UHost: %v", ips, r1.UHostSet)
	for _, host := range r1.UHostSet {
		for _, ip := range host.IPSet {
			if _, ok := ips[ip.IP]; ok {
				instanceIDs = append(instanceIDs, host.UHostID)
			}
		}
	}

	// list PHost
	p2 := DescribePHostParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     maxLimit,
	}
	r2, err := c.UClient.DescribePHost(p2)
	if err != nil {
		glog.Errorf("failed to describe phost: %v", err)
		return nil, err
	}
	if r2.RetCode != 0 {
		glog.Errorf("failed to describe phost: %v", r2.Message)
		return nil, errors.New(r1.Message)
	}
	for _, host := range r2.PHostSet {
		for _, ip := range host.IPSet {
			if _, ok := ips[ip.IPAddr]; ok {
				instanceIDs = append(instanceIDs, host.PHostID)
			}
		}
	}

	glog.V(3).Infof("instanceIDs: %v", instanceIDs)
	return instanceIDs, nil
}

// UpdateLoadBalancer implements cloudprovider.LoadBalancer interface
// It updates hosts under the specified load balancer.
func (c *Cloud) UpdateLoadBalancer(clusterName string, service *v1.Service, nodes []*v1.Node) error {
	loadBalancerName := cloudprovider.GetLoadBalancerName(service)
	glog.V(3).Infof("update loadbalancer name: %s", loadBalancerName)
	ulbSet, err := c.describeLoadBalancer(loadBalancerName)
	if err != nil {
		glog.Errorf("failed to describe loadbalancer %s: %v", loadBalancerName, err)
		return err
	}
	if len(service.Spec.Ports) == 0 {
		return fmt.Errorf("no port found for serivce %s/%s", service.Namespace, service.Name)
	}
	port := int(service.Spec.Ports[0].NodePort)
	nodeNames := []string{}
	for _, node := range nodes {
		nodeNames = append(nodeNames, node.Name)
	}
	uHostIDs, err := c.getUHostIDs(nodeNames)
	if err != nil {
		glog.Errorf("failed to get UHost IDs from node names(%v): %v", nodeNames, err)
		return err
	}
	ulbID := ulbSet.ULBID
	vserverID := ulbSet.VServerSet[0].VserverID
	m1 := make(map[string]bool)
	m2 := make(map[string]string)
	for _, host := range uHostIDs {
		m1[host] = true
	}
	for _, backend := range ulbSet.VServerSet[0].VServerSet {
		m2[backend.ResourceID] = backend.BackendID
	}
	glog.V(3).Infof("m1: %v m2: %v", m1, m2)
	// remove backend if not in m1, create backend if not in m1
	for host, backendID := range m2 {
		if _, ok := m1[host]; !ok {
			// delete backend
			p := ReleaseBackendParam{
				Region:    c.Region,
				ProjectID: c.ProjectID,
				ULBID:     ulbID,
				BackendID: backendID,
			}
			r, err := c.UClient.ReleaseBackend(p)
			if err != nil {
				glog.Errorf("failed to release backend with parameter %+v: %v", p, err)
				return err
			}
			glog.V(3).Infof("update loadbalancer(release backend) response: %+v", r)
			if r.RetCode != 0 {
				glog.Errorf("failed to release backend with parameter %+v: %v", p, r.Message)
				return errors.New(r.Message)
			}
		}
	}
	for host := range m1 {
		if _, ok := m2[host]; !ok {
			// create backend
			p := AllocateBackendParam{
				Region:       c.Region,
				ProjectID:    c.ProjectID,
				ULBID:        ulbID,
				VServerID:    vserverID,
				ResourceType: "UHost",
				ResourceID:   host,
				Port:         port,
				Enabled:      1,
			}
			r, err := c.UClient.AllocateULB4Backend(p, c.SSHConfig)
			if err != nil {
				glog.Errorf("failed to allocate ULB for backend with parameter %+v: %v", p, err)
				return err
			}
			glog.V(3).Infof("update loadbalancer(allocate backend) response: %+v", r)
			if r.RetCode != 0 {
				glog.Errorf("failed to allocate ULB for backend with parameter %+v: %v", p, r.Message)
				return errors.New(r.Message)
			}
		}
	}
	return nil
}

// EnsureLoadBalancerDeleted implements cloudprovider.LoadBalancer interface
// It deletes the specified load balancer if it exists,
// returning nil if the load balancer either not exists or was successfully deleted.
func (c *Cloud) EnsureLoadBalancerDeleted(clusterName string, service *v1.Service) error {
	loadBalancerName := cloudprovider.GetLoadBalancerName(service)
	glog.V(3).Infof("loadbalancer name: %s", loadBalancerName)
	if err := c.deleteLoadBalancer(loadBalancerName); err != nil {
		glog.Errorf("failed to delete loadbalancer %s: %v", loadBalancerName, err)
		return err
	}
	return nil
}

func newUCloud(config io.Reader) (*Cloud, error) {
	var (
		cfg CloudConfig
		err error
	)
	err = gcfg.ReadInto(&cfg, config)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %v", err)
	}
	sshConfig, err := NewSSHConfig(cfg.Global.SSHUser, cfg.Global.SSHKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSH config from %s: %v", cfg.Global.SSHKeyFile, err)
	}
	cloud := &Cloud{
		Region:    cfg.Global.Region,
		Zone:      cfg.Global.Zone,
		ProjectID: cfg.Global.ProjectID,
		SSHConfig: sshConfig,
	}
	cloud.UClient = UClient{
		PrivateKey: cfg.Global.PrivateKey,
		PublicKey:  cfg.Global.PublicKey,
		BaseURL:    cfg.Global.ApiURL,
	}
	return cloud, nil
}

func init() {
	cloudprovider.RegisterCloudProvider(providerName, func(config io.Reader) (cloudprovider.Interface, error) {
		return newUCloud(config)
	})
}

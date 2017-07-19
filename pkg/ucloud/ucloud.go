package ucloud

import (
	"errors"
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
	operatorName = "Bgp"
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
		glog.V(3).Infof("failed to get instance id for %s: %v", nodeName, err)
		return addrs, nil
	}
	p := GetUHostInstanceParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		UHostID:   uhostID,
	}
	r, err := c.UClient.GetUHostInstance(p)
	if err != nil {
		glog.V(3).Infof("failed to GetUHostInstance: %v", err)
		return addrs, nil
	}
	if r.RetCode != 0 {
		glog.V(3).Infof("failed to GetUHostInstance: %s", r.Message)
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
		glog.V(3).Infof("failed to get uhost id for host %s: %v", ip, err)
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
		glog.V(3).Infof("failed to get uhost id for host %s: %v", ip, err)
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
	p := DescribeUHostInstanceParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     100,
	}
	r, err := c.UClient.DescribeUHostInstance(p)
	if err != nil {
		glog.V(3).Infof("failed to DescribeUHostInstance: %v", err)
		return "", err
	}
	if r.RetCode != 0 {
		glog.V(3).Infof("failed to DescribeUHostInstance: %v", r.Message)
		return "", errors.New(r.Message)
	}
	hostIP := strings.Replace(string(nodeName), "-", ".", -1)
	for _, host := range r.UHostSet {
		for _, ip := range host.IPSet {
			if ip.IP == hostIP {
				return host.UHostType, nil
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

func (c *Cloud) describeLoadBalancer(name string) (*ULBSet, error) {
	p := DescribeULBParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     100,
	}
	resp, err := c.UClient.DescribeULB(p)
	glog.V(3).Infof("describe ULB response: %+v", resp)
	if err != nil {
		return nil, err
	}
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
	glog.V(3).Infof("create ULB response: %+v", r1)
	if err != nil {
		return "", err
	}
	if r1.RetCode != 0 {
		return "", errors.New(r1.Message)
	}

	// p2 := AllocateEIPParam{
	// 	Region:       c.Region,
	// 	OperatorName: operatorName,
	// 	Bandwidth:    2,
	// 	Quantity:     1,
	// }
	// r2, err := c.UClient.AllocateEIP(p2)
	// if err != nil {
	// 	return eip, err
	// }
	// glog.V(3).Infof("allocate EIP response: %+v", r2)
	// if r2.RetCode != 0 {
	// 	return eip, errors.New(r2.Message)
	// }

	// p3 := BindEIPParam{
	// 	Region:       c.Region,
	// 	EIPID:        r2.EIPSet[0].EIPID,
	// 	ResourceType: "ulb",
	// 	ResourceID:   r1.ULBID,
	// }
	// r3, err := c.UClient.BindEIP(p3)
	// if err != nil {
	// 	return eip, err
	// }
	// glog.V(3).Infof("bind EIP response: %+v", r3)
	// if r3.RetCode != 0 {
	// 	return eip, errors.New(r3.Message)
	// }

	p4 := CreateVServerParam{
		Region:        c.Region,
		ProjectID:     c.ProjectID,
		ULBID:         r1.ULBID,
		VServerName:   "tidb-server",
		Protocol:      "TCP",
		FrontendPort:  port,
		ListenType:    "PacketsTransmit", // RequestProxy | PacketsTransmit
		ClientTimeout: 60,
	}
	r4, err := c.UClient.CreateVServer(p4)
	if err != nil {
		return "", err
	}
	glog.V(3).Infof("create vserver response: %+v", r4)
	if r4.RetCode != 0 {
		return "", errors.New(r4.Message)
	}

	for _, host := range hostIDs {
		p5 := AllocateBackendParam{
			Region:       c.Region,
			ProjectID:    c.ProjectID,
			ULBID:        r1.ULBID,
			VServerID:    r4.VServerID,
			ResourceType: "UHost",
			ResourceID:   host,
			Port:         port,
			Enabled:      1,
		}
		r5, err := c.UClient.AllocateULB4Backend(p5, c.SSHConfig)
		if err != nil {
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
		return nil
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
		glog.Error(err)
	}
	if r.RetCode != 0 {
		glog.Error(r.Message)
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
		return nil, false, err
	}
	status, err = toLBStatus(ulbSet)
	if err != nil {
		return nil, false, err
	}
	return status, true, nil
}

func toLBStatus(ulbSet *ULBSet) (*v1.LoadBalancerStatus, error) {
	if len(ulbSet.IPSet) == 0 {
		return nil, EIPNotFound
	}
	ing := v1.LoadBalancerIngress{IP: ulbSet.IPSet[0].EIP}
	return &v1.LoadBalancerStatus{Ingress: []v1.LoadBalancerIngress{ing}}, nil
}

// EnsureLoadBalancer implements cloudprovider.LoadBalancer interface
// It creates a new load balancer or updates the existing one.
func (c *Cloud) EnsureLoadBalancer(clusterName string, service *v1.Service, nodes []*v1.Node) (*v1.LoadBalancerStatus, error) {
	loadBalancerName := cloudprovider.GetLoadBalancerName(service)
	glog.V(3).Infof("loadBalancer name: %s", loadBalancerName)
	_, err := c.describeLoadBalancer(loadBalancerName)
	if err != nil && err != ULBNotFound {
		return nil, err
	}
	if len(service.Spec.Ports) == 0 {
		return nil, errors.New("no port found for service")
	}
	backendPort := int(service.Spec.Ports[0].NodePort)
	// frontendPort := int(service.Spec.Ports[0].Port)
	// if service.Spec.Ports[0].TargetPort.Type == intstr.Int {
	// 	frontendPort = int(service.Spec.Ports[0].TargetPort.IntVal)
	// }
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
		return nil, err
	}
	ulbID, err := c.createLoadBalancer(loadBalancerName, uHostIDs, backendPort)
	if err != nil {
		return nil, err
	}
	p := DescribeULBParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		ULBID:     ulbID,
	}
	r, err := c.UClient.DescribeULB(p)
	if err != nil {
		glog.V(3).Infof("failed to DescribeULB for %s: %v", ulbID, err)
		return nil, err
	}
	if r.RetCode != 0 {
		glog.V(3).Infof("failed to DescribeULB for %s: %v", ulbID, err)
		return nil, errors.New(r.Message)
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
	p := DescribeUHostInstanceParam{
		Region:    c.Region,
		ProjectID: c.ProjectID,
		Limit:     100,
	}
	r, err := c.UClient.DescribeUHostInstance(p)
	if err != nil {
		glog.V(3).Infof("failed to describe uhost instance: %v", err)
		return instanceIDs, err
	}
	if r.RetCode != 0 {
		glog.V(3).Infof("failed to describe uhost instance: %v", r.Message)
		return instanceIDs, errors.New(r.Message)
	}
	ips := make(map[string]bool)
	for _, ip := range nodeIPs {
		ips[ip] = true
	}
	glog.V(3).Infof("node IPs: %v", ips)
	for _, host := range r.UHostSet {
		for _, ip := range host.IPSet {
			glog.V(3).Infof("IPSet: %v", ip)
			if _, ok := ips[ip.IP]; ok {
				instanceIDs = append(instanceIDs, host.UHostID)
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
		return err
	}
	if len(service.Spec.Ports) == 0 {
		return errors.New("no port found for serivce")
	}
	port := int(service.Spec.Ports[0].Port)
	nodeNames := []string{}
	for _, node := range nodes {
		nodeNames = append(nodeNames, node.Name)
	}
	uHostIDs, err := c.getUHostIDs(nodeNames)
	if err != nil {
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
				return err
			}
			glog.V(3).Infof("update loadbalancer(release backend) response: %+v", r)
			if r.RetCode != 0 {
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
				return err
			}
			glog.V(3).Infof("update loadbalancer(allocate backend) response: %+v", r)
			if r.RetCode != 0 {
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
	return c.deleteLoadBalancer(loadBalancerName)
}

func newUCloud(config io.Reader) (*Cloud, error) {
	var (
		cfg CloudConfig
		err error
	)
	err = gcfg.ReadInto(&cfg, config)
	if err != nil {
		return nil, err
	}
	sshConfig, err := NewSSHConfig(cfg.Global.SSHUser, cfg.Global.SSHKeyFile)
	if err != nil {
		return nil, err
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
	glog.V(3).Infof("ucloud: %+v", cloud)
	return cloud, nil
}

func init() {
	cloudprovider.RegisterCloudProvider(providerName, func(config io.Reader) (cloudprovider.Interface, error) {
		return newUCloud(config)
	})
}

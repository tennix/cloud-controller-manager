package ucloud

import (
	"bytes"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/golang/glog"
)

// TODO gcfg
const (
	sshPemKey string = "/root/.ssh/id_rsa"
	sshUser   string = "root"
	sshPort   int64  = 22
)

var (
	sshConfig *ssh.ClientConfig
)

type Parameter interface {
	QueryString() string
}

type ReturnStatus struct {
	RetCode int    `json:"RetCode"`
	Action  string `json:"Action,omitempty"`
	Message string `json:"Message,omitempty"`
}

type Params map[string]string

func (p Params) toQueryString() string {
	keys := []string{}
	for k, v := range p {
		if v == "" { // ignore empty string
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	s := ""
	for _, k := range keys {
		if k == "PrivateKey" || k == "Signature" {
			continue
		}
		s = s + k + p[k]
	}
	s += p["PrivateKey"]
	h := sha1.New()
	io.WriteString(h, s)
	sig := fmt.Sprintf("%x", h.Sum(nil))
	qs := ""
	for _, k := range keys {
		if k == "PrivateKey" || k == "Signature" {
			continue
		}
		v := url.Values{}
		v.Set(k, p[k])
		qs = qs + "&" + v.Encode()
	}
	v := url.Values{}
	v.Set("Signature", sig)
	qs = qs + "&" + v.Encode()
	return qs
}

func toParams(p interface{}) Params {
	values := reflect.ValueOf(p)
	types := reflect.TypeOf(p)
	params := make(map[string]string, values.NumField())
	for i := 0; i < values.NumField(); i++ {
		tag := types.Field(i).Tag.Get("json")
		value := values.Field(i).Interface()
		params[tag] = fmt.Sprintf("%v", value)
	}
	return params
}

type DescribeUHostInstanceParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"` // required
	Zone       string `json:"zone"`
	UHostIDsN  string `json:"UHostIds.n"`
	Tag        string `json:"tag"`
	Offset     int    `json:"offset"`
	Limit      int    `json:"limit"`
}

type GetUHostInstanceParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"` // required
	UHostID    string `json:"UHostIds.0"`
}

func (p *GetUHostInstanceParam) setKey(pubKey, privKey string) {
	p.Action = "DescribeUHostInstance"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p GetUHostInstanceParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type DescribeUHostInstanceResponse struct {
	ReturnStatus
	TotalCount int                `json:"TotalCount"`
	UHostSet   []UHostInstanceSet `json:"UHostSet"`
}

type UHostInstanceSet struct {
	UHostID            string         `json:"UHostId"`
	UHostType          string         `json:"UhostType"`
	Zone               string         `json:"Zone"`
	StorageType        string         `json:"StorageType"`
	ImageID            string         `json:"ImageId"`
	BasicImageID       string         `json:"BasiceImageId"`
	BasicImageName     string         `json:"BasicImageName"`
	Tag                string         `json:"Tag"`
	Remark             string         `json:"Remark"`
	Name               string         `json:"Name"`
	State              string         `json:"state"`
	CreateTime         int            `json:"CreateTime"`
	ChargeType         string         `json:"ChargeType"`
	ExpireTime         int            `json:"ExpireTime"`
	CPU                int            `json:"CPU"`
	Memory             int            `json:"Memory"` // unit: MB
	AutoRenew          string         `json:"AutoRenew"`
	DiskSet            []UHostDiskSet `json:"DiskSet"`
	IPSet              []UHostIPSet   `json:"IPSet"`
	NetCapability      string         `json:"NetCapability"`
	NetworkState       string         `json:"NetworkState"`
	TimemachineFeature string         `json:"TimemachineFeature"`
	HotplugFeature     bool           `json:"HotplugFeature"`
}

type UHostIPSet struct {
	Type      string `json:"Type"`
	IPID      string `json:"IPId"`
	IP        string `json:"IP"`
	VpcID     string `json:"VPCId"`
	SubentID  string `json:"SubnetId"`
	Weight    int    `json:"Weight"`
	Bandwidth int    `json:"bandwidth"`
}

type UHostDiskSet struct {
	Type   string `json:"Type"`
	DiskID string `json:"DiskId"`
	Name   string `json:"Name"`
	Drive  string `json:"Drive"`
	Size   int    `json:"Size"`
}

func (p *DescribeUHostInstanceParam) setKey(pubKey, privKey string) {
	p.Action = "DescribeUHostInstance"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p DescribeUHostInstanceParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type DescribeULBParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"` // required
	Offset     int    `json:"Offset"`
	Limit      int    `json:"Limit"`
	ULBID      string `json:"ULBId"`
}

func (p *DescribeULBParam) setKey(pubKey, privKey string) {
	p.Action = "DescribeULB"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p DescribeULBParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type ULBSet struct {
	ULBID         string `json:"ULBId,omitempty"`
	ULBName       string `json:"ULBName,omitempty"`
	Name          string `json:"Name"`
	Tag           string `json:"Tag"`
	PrivateIP     string `json:"PrivateIP"`
	Remark        string `json:"Remark"`
	BandwidthType int    `json:"BandwidthType"`
	Bandwidth     int    `json:"Bandwidth"`
	CreateTime    int    `json:"CreateTime"`
	ExpireTime    int    `json:"ExpireTime"`
	//	Resource      []Resource      `json:"Resource"`
	IPSet      []ULBIPSet      `json:"IPSet"`
	VServerSet []ULBVServerSet `json:"VServerSet"`
	ULBType    string          `json:"ULBType"`
}

type ULBIPSet struct {
	OperatorName string `json:"OperatorName"`
	EIP          string `json:"EIP"`
	EIPID        string `json:"EIPId"`
}

type ULBVServerSet struct {
	VserverID       string          `json:"VServerId"`
	VServerName     string          `json:"VServerName"`
	Protocol        string          `json:"Protocol"`
	FrontendPort    int             `json:"FrontendPort"`
	Method          string          `json:"Method"`
	PersistenceType string          `json:"PersistenceType"`
	PersistenceInfo string          `json:"PersistenceInfo"`
	ClientTimeout   int             `json:"ClientTimeout"`
	Status          int             `json:"Status"`
	SSLSet          []ULBSSLSet     `json:"SSLSet"`
	VServerSet      []ULBBackendSet `json:"VServerSet"`
}

type ULBSSLSet struct {
	SSLID              string               `json:"SSLId"`
	SSLName            string               `json:"SSLName"`
	SSLType            string               `json:"SSLType"`
	SSLContent         string               `json:"SSLContent"`
	CreateTime         int                  `json:"CreateTime"`
	SSLBindedTargetSet []SSLBindedTargetSet `json:"SSLBindedTargetSet"`
}

type SSLBindedTargetSet struct {
	VServerID   string `json:"VServerId"`
	VServerName string `json:"VServerName"`
	ULBID       string `json:"ULBId"`
	ULBName     string `json:"ULBName"`
}

type ULBBackendSet struct {
	BackendID    string `json:"BackendId"`
	ResourceType string `json:"ResourceType"`
	ResourceID   string `json:"ResourceId"`
	ResourceName string `json:"ResourceName"`
	PrivateIP    string `json:"PrivateIP"`
	Port         int    `json:"Port"`
	Enabled      int    `json:"Enabled"`
	Status       int    `json:"Status"`
}

type DescribeULBResponse struct {
	ReturnStatus
	TotalCount int      `json:"TotalCount"`
	DataSet    []ULBSet `json:"DataSet"`
}

type CreateULBParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"` // required
	ULBName    string `json:"ULBName"`
	Tag        string `json:"Tag"`
	Remark     string `json:"Remark"`
	OuterMode  string `json:"OuterMode"`
	InnerMode  string `json:"InnerMode"`
	ChargeType string `json:"ChargeType"`
}

func (p *CreateULBParam) setKey(pubKey, privKey string) {
	p.Action = "CreateULB"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p CreateULBParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type CreateULBResponse struct {
	ReturnStatus
	ULBID string `json:"ULBId"`
}

type DeleteULBParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"`
	ULBID      string `json:"ULBId"`
}

func (p *DeleteULBParam) setKey(pubKey, privKey string) {
	p.Action = "DeleteULB"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p DeleteULBParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type DeleteULBResponse ReturnStatus

type UpdateULBAttributeParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"`
	ULBID      string `json:"ULBId"`
	Name       string `json:"Name"`
	Tag        string `json:"Tag"`
	Remark     string `json:"Remark"`
}

func (p *UpdateULBAttributeParam) setKey(pubKey, privKey string) {
	p.Action = "UpdateULBAttribute"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p UpdateULBAttributeParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type UpdateULBAttributeResponse ReturnStatus

type CreateVServerParam struct {
	Action          string `json:"Action"`
	PublicKey       string `json:"PublicKey"`
	PrivateKey      string `json:"PrivateKey"`
	Signature       string `json:"Signature"`
	ProjectID       string `json:"ProjectId"`
	Region          string `json:"Region"`
	ULBID           string `json:"ULBId"`
	VServerName     string `json:"VServerName"`
	ListenType      string `json:"ListenType"`
	Protocol        string `json:"Protocol"`
	FrontendPort    int    `json:"FrontendPort"`
	Method          string `json:"Method"`
	PersistenceType string `json:"PersistenceType"`
	PersistenceInfo string `json:"PersistenceInfo"`
	ClientTimeout   int    `json:"ClientTimeout"`
}

func (p *CreateVServerParam) setKey(pubKey, privKey string) {
	p.Action = "CreateVServer"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p CreateVServerParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type CreateVServerResponse struct {
	ReturnStatus
	VServerID string `json:"VServerId"`
}

type DeleteVServerParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"`
	ULBID      string `json:"ULBId"`
	VServerID  string `json:"VServerId"`
}

func (p *DeleteVServerParam) setKey(pubKey, privKey string) {
	p.Action = "DeleteVServer"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p DeleteVServerParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type DeleteVServerResponse ReturnStatus

type UpdateVServerAttributeParam struct {
	Action          string `json:"Action"`
	PublicKey       string `json:"PublicKey"`
	PrivateKey      string `json:"PrivateKey"`
	Signature       string `json:"Signature"`
	ProjectID       string `json:"ProjectId"`
	Region          string `json:"Region"`
	ULBID           string `json:"ULBId"`
	VServerID       string `json:"VServerId"`
	VServerName     string `json:"VServerName"`
	Protocol        string `json:"Protocol"`
	Method          string `json:"Method"`
	PersistenceType string `json:"PersistenceType"`
	PersistenceInfo string `json:"PersistenceInfo"`
	ClientTimeout   int    `json:"ClientTimeout"`
}

func (p *UpdateVServerAttributeParam) setKey(pubKey, privKey string) {
	p.Action = "UpdateVServerAttribute"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p UpdateVServerAttributeParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type UpdateVServerAttributeResponse ReturnStatus

type AllocateBackendParam struct {
	Action       string `json:"Action"`
	PublicKey    string `json:"PublicKey"`
	PrivateKey   string `json:"PrivateKey"`
	Signature    string `json:"Signature"`
	ProjectID    string `json:"ProjectId"`
	Region       string `json:"Region"`
	ULBID        string `json:"ULBId"`
	VServerID    string `json:"VServerId"`
	ResourceType string `json:"ResourceType"`
	ResourceID   string `json:"ResourceId"`
	Port         int    `json:"Port"`
	Enabled      int    `json:"Enabled"` // 0 or 1
}

func (p *AllocateBackendParam) setKey(pubKey, privKey string) {
	p.Action = "AllocateBackend"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p AllocateBackendParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type AllocateBackendResponse struct {
	ReturnStatus
	BackendID string `json:"BackendId"`
}

type UpdateBackendAttributeParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"`
	ULBID      string `json:"ULBId"`
	BackendID  string `json:"BackendId"`
	Port       int    `json:"Port"`
	Enabled    int    `json:"Enabled"`
}

func (p *UpdateBackendAttributeParam) setKey(pubKey, privKey string) {
	p.Action = "UpdateBackendAttribute"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p UpdateBackendAttributeParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type UpdateBackendAttributeResponse ReturnStatus

type ReleaseBackendParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	ProjectID  string `json:"ProjectId"`
	Region     string `json:"Region"`
	ULBID      string `json:"ULBId"`
	BackendID  string `json:"BackendId"`
}

func (p *ReleaseBackendParam) setKey(pubKey, privKey string) {
	p.Action = "ReleaseBackend"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p ReleaseBackendParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type ReleaseBackendResponse ReturnStatus

type AllocateEIPParam struct {
	Action           string `json:"Action"`
	PublicKey        string `json:"PublicKey"`
	PrivateKey       string `json:"PrivateKey"`
	Signature        string `json:"Signature"`
	Region           string `json:"Region"`
	OperatorName     string `json:"OperatorName"`
	Bandwidth        int    `json:"Bandwidth"`
	Tag              string `json:"tag"`
	ChargeType       string `json:"ChargeType"`
	Quantity         int    `json:"Quantity"`
	PayMode          string `json:"PayMode"`
	ShareBandwidthID string `json:"ShareBandwidth"`
	CouponID         string `json:"CouponId"`
	Name             string `json:"Name"`
	Remark           string `json:"Remark"`
}

type AllocateEIPResponse struct {
	ReturnStatus
	EIPSet []UnetAllocateEIPSet `json:"EIPSet"`
}

type UnetAllocateEIPSet struct {
	EIPID   string           `json:"EIPId"`
	EIPAddr []UnetEIPAddrSet `json:"EIPAddr"`
}

type UnetEIPAddrSet struct {
	OperatorName string `json:"OperatorName"`
	IP           string `json:"IP"`
}

func (p *AllocateEIPParam) setKey(pubKey, privKey string) {
	p.Action = "AllocateEIP"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p AllocateEIPParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type ReleaseEIPParam struct {
	Action     string `json:"Action"`
	PublicKey  string `json:"PublicKey"`
	PrivateKey string `json:"PrivateKey"`
	Signature  string `json:"Signature"`
	Region     string `json:"Region"`
	EIPID      string `json:"EIPId"`
}

type ReleaseEIPResponse ReturnStatus

func (p *ReleaseEIPParam) setKey(pubKey, privKey string) {
	p.Action = "ReleaseEIP"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p ReleaseEIPParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type BindEIPParam struct {
	Action       string `json:"Action"`
	PublicKey    string `json:"PublicKey"`
	PrivateKey   string `json:"PrivateKey"`
	Signature    string `json:"Signature"`
	Region       string `json:"Region"`
	EIPID        string `json:"EIPId"`
	ResourceType string `json:"ResourceType"`
	ResourceID   string `json:"ResourceId"`
}

type BindEIPResponse ReturnStatus

func (p *BindEIPParam) setKey(pubKey, privKey string) {
	p.Action = "BindEIP"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p BindEIPParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type UnBindEIPParam struct {
	Action       string `json:"Action"`
	PublicKey    string `json:"PublicKey"`
	PrivateKey   string `json:"PrivateKey"`
	Signature    string `json:"Signature"`
	Region       string `json:"Region"`
	EIPID        string `json:"EIPId"`
	ResourceType string `json:"ResourceType"`
	ResourceID   string `json:"ResourceId"`
}

type UnBindEIPResponse ReturnStatus

func (p *UnBindEIPParam) setKey(pubKey, privKey string) {
	p.Action = "UnBindEIP"
	p.PublicKey = pubKey
	p.PrivateKey = privKey
}

func (p UnBindEIPParam) QueryString() string {
	params := toParams(p)
	return params.toQueryString()
}

type UClient struct {
	BaseURL    string
	PublicKey  string
	PrivateKey string
}

func New(baseURL, pubKey, privKey string) UClient {
	return UClient{
		BaseURL:    baseURL,
		PublicKey:  pubKey,
		PrivateKey: privKey,
	}
}

func (c UClient) GetQueryURL(p Parameter) string {
	return c.BaseURL + "/?" + p.QueryString()
}

func (c UClient) DescribeULB(p DescribeULBParam) (*DescribeULBResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("DescribeULB request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &DescribeULBResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) CreateULB(p CreateULBParam) (*CreateULBResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("CreateULB request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &CreateULBResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) UpdateULBAttribute(p UpdateULBAttributeParam) (*UpdateULBAttributeResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("UpdateULBAttribute request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &UpdateULBAttributeResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) DeleteULB(p DeleteULBParam) (*DeleteULBResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("DeleteULB request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &DeleteULBResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) DeleteInternalULB(p DeleteULBParam, hostIPs []string, ulbIP string) (*DeleteULBResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("DeleteULB request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &DeleteULBResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	if err != nil {
		return nil, err
	}
	for _, hostIP := range hostIPs {
		if err := ifdownULB4(sshConfig, hostIP, ulbIP); err != nil {
			glog.V(3).Infof("failed to delete virtual network interface for %s: %v", hostIP, err)
		}
	}
	return r, err
}

func (c UClient) CreateVServer(p CreateVServerParam) (*CreateVServerResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("CreateVServer request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &CreateVServerResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) UpdateVServerAttribute(p UpdateVServerAttributeParam) (*UpdateVServerAttributeResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("UpdateVServerAttribute request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &UpdateVServerAttributeResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) DeleteVServer(p DeleteVServerParam) (*DeleteVServerResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("DeleteVServer request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &DeleteVServerResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) AllocateBackend(p AllocateBackendParam) (*AllocateBackendResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("AllocateBackend request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &AllocateBackendResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) AllocateULB4Backend(p AllocateBackendParam, sshConfig *ssh.ClientConfig) (*AllocateBackendResponse, error) {
	var (
		hostIP string
		ulbIP  string
	)
	if p.ResourceType != "UHost" {
		return nil, fmt.Errorf("AllocateULB4Backend not support ResourceType[%s]", p.ResourceType)
	}
	p1 := GetUHostInstanceParam{
		Region:    p.Region,
		ProjectID: p.ProjectID,
		UHostID:   p.ResourceID,
	}
	r1, err := c.GetUHostInstance(p1)
	glog.V(3).Infof("AllocateULB4Backend describe uhost response: %+v", r1)
	if err != nil {
		return nil, err
	}
	if r1.RetCode != 0 {
		return nil, errors.New(r1.Message)
	}
	if len(r1.UHostSet) != 1 {
		return nil, fmt.Errorf("AllocateULB4Backend uhost[%s] not found", p.ResourceID)
	}

	for _, ip := range r1.UHostSet[0].IPSet {
		if ip.Type == "Private" {
			hostIP = ip.IP
			break
		}
	}

	p2 := DescribeULBParam{
		Region:    p.Region,
		ProjectID: p.ProjectID,
		ULBID:     p.ULBID,
	}
	r2, err := c.DescribeULB(p2)
	glog.V(3).Infof("AllocateULB4Backend describe ULB response: %+v", r2)
	if err != nil {
		return nil, err
	}
	if r2.RetCode != 0 {
		return nil, errors.New(r2.Message)
	}
	if len(r2.DataSet) != 1 {
		return nil, ULBNotFound
	}
	ulbIP = r2.DataSet[0].PrivateIP
	if ulbIP == "" {
		return nil, errors.New("AllocateULB4Backend ulb has invalid private ip")
	}

	err = ifupULB4(sshConfig, hostIP, ulbIP)
	if err != nil {
		return nil, err
	}

	return c.AllocateBackend(p)
}

func (c UClient) UpdateBackendAttribute(p UpdateBackendAttributeParam) (*UpdateBackendAttributeResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("UpdateBackendAttribute request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &UpdateBackendAttributeResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) ReleaseBackend(p ReleaseBackendParam) (*ReleaseBackendResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("ReleaseBackend request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &ReleaseBackendResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) AllocateEIP(p AllocateEIPParam) (*AllocateEIPResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("AllocateEIP request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &AllocateEIPResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) BindEIP(p BindEIPParam) (*BindEIPResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("BindEIP request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &BindEIPResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) UnbindEIP(p UnBindEIPParam) (*UnBindEIPResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("UnbindEIP request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &UnBindEIPResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) ReleaseEIP(p ReleaseEIPParam) (*ReleaseEIPResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("UnbindEIP request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &ReleaseEIPResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

func (c UClient) DescribeUHostInstance(p DescribeUHostInstanceParam) (*DescribeUHostInstanceResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("DescribeUHostInstance request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &DescribeUHostInstanceResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	if err != nil {
		return nil, err
	}
	return r, err
}

func (c UClient) GetUHostInstance(p GetUHostInstanceParam) (*DescribeUHostInstanceResponse, error) {
	p.setKey(c.PublicKey, c.PrivateKey)
	resp, err := http.Get(c.GetQueryURL(p))
	glog.V(3).Infof("GetUHostInstance request url: %s", c.GetQueryURL(p))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r := &DescribeUHostInstanceResponse{}
	err = json.NewDecoder(resp.Body).Decode(r)
	return r, err
}

// NewSSHConfig creates a SSH ClientConfig
func NewSSHConfig(user string, keyFile string) (*ssh.ClientConfig, error) {
	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}}, nil
}

func ip2long(ipstr string) (uint32, error) {
	var ip uint32
	strs := strings.Split(ipstr, ".")
	if len(strs) != 4 {
		return ip, fmt.Errorf("invalid IP format: %s", ipstr)
	}
	prop := []int{0x1000000, 0x10000, 0x100, 1}
	for i, s := range strs {
		p, err := strconv.Atoi(s)
		if err != nil || (p < 0 || p > 255) {
			return ip, fmt.Errorf("invalid IP format: %s", ipstr)
		}
		ip += uint32(p * prop[i])
	}
	return ip, nil
}

func ifupULB4(sshConfig *ssh.ClientConfig, hostIP string, ulbIP string) error {
	iplong, err := ip2long(ulbIP)
	if err != nil {
		return err
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", hostIP, sshPort), sshConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	cmd := fmt.Sprintf("echo -e \"DEVICE=lo:%d\nIPADDR=%s\nNETMASK=255.255.255.255\" > /etc/sysconfig/network-scripts/ifcfg-lo:%d; ifup lo:%d", iplong, ulbIP, iplong, iplong)
	glog.V(3).Infof("ifupULB4: %s %s", hostIP, cmd)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(cmd)
	glog.V(3).Infof("ifupULB4: %+v %+v %+v", err, stdout.String(), stderr.String())

	return err
}

func ifdownULB4(sshConfig *ssh.ClientConfig, hostIP string, ulbIP string) error {
	iplong, err := ip2long(ulbIP)
	if err != nil {
		return err
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", hostIP, sshPort), sshConfig)
	if err != nil {
		return err
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	cmd := fmt.Sprintf("rm -f /etc/sysconfig/network-scripts/ifcfg-log:%d; ifdown lo:%d", iplong, iplong)
	glog.V(3).Infof("ifdownULB4: %s %s", hostIP, cmd)

	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
	)
	session.Stdout = &stdout
	session.Stderr = &stderr

	err = session.Run(cmd)
	glog.V(3).Infof("ifdownULB4: %+v %+v %+v", err, stdout.String(), stderr.String())

	return err
}

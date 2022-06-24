package common

import (
	"time"
)

const GO_BIRTHDAY = "2006-01-02 15:04:05"

const (
	REMOTE_API_TIMEOUT = 30
)

const (
	LOCALHOST                    = "127.0.0.1"
	MASTER_CONTROLLER_CHECK_PORT = 4040
)

const (
	SUCCESS                         = "SUCCESS"
	FAIL                            = "FAIL"
	INVALID_PARAMETERS              = "INVALID_PARAMETERS"
	RESOURCE_NOT_FOUND              = "RESOURCE_NOT_FOUND"
	RESOURCE_ALREADY_EXIST          = "RESOURCE_ALREADY_EXIST"
	PARAMETER_ILLEGAL               = "PARAMETER_ILLEGAL"
	INVALID_POST_DATA               = "INVALID_POST_DATA"
	SERVER_ERROR                    = "SERVER_ERROR"
	RESOURCE_NUM_EXCEEDED           = "RESOURCE_NUM_EXCEEDED"
	SELECTED_RESOURCES_NUM_EXCEEDED = "SELECTED_RESOURCES_NUM_EXCEEDED"
)

const (
	HEALTH_CHECK_INTERVAL = 60 * time.Second
	CONTROLLER_CHECK_URL  = "http://%s:20014/v1/health/"
	ANALYZER_CHECK_URL    = "http://%s:20205/v1/health/"
)

const (
	HOST_STATE_COMPLETE    = 2
	HOST_STATE_EXCEPTION   = 4
	HOST_STATE_MAINTENANCE = 5

	HOST_TYPE_VM  = 1
	HOST_TYPE_NSP = 3
	HOST_TYPE_DFI = 4

	HOST_HTYPE_ESXI    = 2
	HOST_HTYPE_KVM     = 3
	HOST_HTYPE_HYPER_V = 5
	HOST_HTYPE_GATEWAY = 6
)

const (
	HOST_VCPUS     = 8
	HOST_MEMORY_MB = 16384
)

const (
	CONTROLLER_NODE_TYPE_MASTER = 1
	CONTROLLER_NODE_TYPE_SLAVE  = 2
)

const (
	ARCH_X86 = 1
	ARCH_ARM = 2
)

const (
	OS_CENTOS  = 1
	OS_REDHAT  = 2
	OS_UBUNTU  = 3
	OS_SUSE    = 4
	OS_WINDOWS = 5
)

const (
	VTAP_ENABLE_FALSE = 0
	VTAP_ENABLE_TRUE  = 1
)

const (
	VTAP_STATE_NOT_CONNECTED = iota
	VTAP_STATE_NORMAL
	VTAP_STATE_DISABLE
	VTAP_STATE_PENDING
)

const (
	VTAP_STATE_NOT_CONNECTED_STR = "LOST"
	VTAP_STATE_NORMAL_STR        = "RUNNING"
	VTAP_STATE_DISABLE_STR       = "DISABLE"
	VTAP_STATE_PENDING_STR       = "PENDING"
)

const (
	VTAP_TYPE_KVM = 1 + iota
	VTAP_TYPE_EXSI
	VTAP_TYPE_WORKLOAD_V
	_ // 4
	VTAP_TYPE_WORKLOAD_P
	VTAP_TYPE_DEDICATED
	VTAP_TYPE_POD_HOST
	VTAP_TYPE_POD_VM
	VTAP_TYPE_TUNNEL_DECAPSULATION
	VTAP_TYPE_HYPER_V
)

const (
	VTAP_EXCEPTION_LICENSE_NOT_ENGOUTH     = 0x10000000
	VTAP_EXCEPTION_ALLOC_ANALYZER_FAILED   = 0x40000000
	VTAP_EXCEPTION_ALLOC_CONTROLLER_FAILED = 0x80000000
)

const VTAP_LICENSE_CHECK_INTERVAL = time.Minute

const (
	VTAP_LICENSE_TYPE_NONE = iota
	VTAP_LICENSE_TYPE_A
	VTAP_LICENSE_TYPE_B
	VTAP_LICENSE_TYPE_C
	VTAP_LICENSE_TYPE_DEDICATED
	VTAP_LICENSE_TYPE_MAX
)

const (
	VTAP_LICENSE_FUNCTION_NONE = iota
	VTAP_LICENSE_FUNCTION_APPLICATION_MONITORING
	VTAP_LICENSE_FUNCTION_NETWORK_MONITORING
	VTAP_LICENSE_FUNCTION_TRAFFIC_DISTRIBUTION
	VTAP_LICENSE_FUNCTION_MAX
)

const (
	DEFAULT_REGION        = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	DEFAULT_AZ            = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	DEFAULT_VTAP_GROUP_ID = 1
	DEFAULT_DOMAIN_ICON   = -3
	DEFAULT_REGION_NAME   = "系统默认"
)

const (
	DOMAIN_ENABLED_FALSE = 0
	DOMAIN_ENABLED_TRUE  = 1
)

const (
	DEFAULT_ENCRYPTION_PASSWORD = "******"
	DEFAULT_PORT_NAME_REGEX     = "(cni|flannel|vxlan.calico|tunl)"

	OPENSTACK         = 1
	VSPHERE           = 2
	NSP               = 3
	TENCENT           = 4
	OTHERS            = 5
	AWS               = 6
	PINGAN            = 7
	ZSTACK            = 8
	ALIYUN            = 9
	HUAWEI_PRIVATE    = 10
	KUBERNETES        = 11
	SIMULATION        = 12
	HUAWEI            = 13
	QINGCLOUD         = 14
	QINGCLOUD_PRIVATE = 15
	F5                = 16
	CMB_CMDB          = 17
	AZURE             = 18
	APSARA_STACK      = 19
	TENCENT_TCE       = 20
	KINGSOFT_PRIVATE  = 22
	GENESIS           = 23
	MICROSOFT_ACS     = 24
	BAIDU_BCE         = 25

	OPENSTACK_EN         = "openstack"
	VSPHERE_EN           = "vsphere"
	NSP_EN               = "nsp"
	TENCENT_EN           = "tencent"
	OTHERS_EN            = "others"
	AWS_EN               = "aws"
	PINGAN_EN            = "pingan"
	ZSTACK_EN            = "zstack"
	ALIYUN_EN            = "aliyun"
	HUAWEI_PRIVATE_EN    = "huawei_private"
	KUBERNETES_EN        = "kubernetes"
	SIMULATION_EN        = "simulation"
	HUAWEI_EN            = "huawei"
	QINGCLOUD_EN         = "qingcloud"
	QINGCLOUD_PRIVATE_EN = "qingcloud_private"
	F5_EN                = "f5"
	CMB_CMDB_EN          = "cmb_cmdb"
	AZURE_EN             = "azure"
	APSARA_STACK_EN      = "apsara_stack"
	TENCENT_TCE_EN       = "tencent_tce"
	QINGCLOUD_K8S_EN     = "qingcloud_k8s"
	KINGSOFT_PRIVATE_EN  = "kingsoft_private"
	GENESIS_EN           = "genesis"
	MICROSOFT_ACS_EN     = "microsoft_acs"
	BAIDU_BCE_EN         = "baidu_bce"

	TENCENT_CH          = "腾讯云"
	PINGAN_CH           = "平安云"
	ALIYUN_CH           = "阿里云"
	HUAWEI_CH           = "华为云"
	QINGCLOUD_CH        = "青云"
	KINGSOFT_PRIVATE_CH = "金山银河云"
	MICROSOFT_CH        = "微软云"
	BAIDU_BCE_CH        = "百度云"
)

const (
	NETWORK_ISP_LCUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	NETWORK_TYPE_WAN   = 3
	NETWORK_TYPE_LAN   = 4
)

const (
	VM_STATE_RUNNING   = 4
	VM_STATE_STOPPED   = 9
	VM_STATE_EXCEPTION = 11

	VM_HTYPE_VM_C = 1
	VM_HTYPE_BM_C = 2
	VM_HTYPE_VM_N = 3
	VM_HTYPE_BM_N = 4
	VM_HTYPE_VM_S = 5
	VM_HTYPE_BM_S = 6
)

const (
	VIF_DEFAULT_MAC = "00:00:00:00:00:00"

	VIF_TYPE_WAN = 3
	VIF_TYPE_LAN = 4

	VIF_DEVICE_TYPE_VM             = 1
	VIF_DEVICE_TYPE_VROUTER        = 5
	VIF_DEVICE_TYPE_HOST           = 6
	VIF_DEVICE_TYPE_DHCP_PORT      = 9
	VIF_DEVICE_TYPE_POD            = 10
	VIF_DEVICE_TYPE_POD_SERVICE    = 11
	VIF_DEVICE_TYPE_REDIS_INSTANCE = 12
	VIF_DEVICE_TYPE_RDS_INSTANCE   = 13
	VIF_DEVICE_TYPE_POD_NODE       = 14
	VIF_DEVICE_TYPE_LB             = 15
	VIF_DEVICE_TYPE_NAT_GATEWAY    = 16
)

const (
	CREATE_METHOD_LEARN         = 0
	CREATE_METHOD_USER_DEFINE   = 1
	CONTACT_CREATE_METHOD_LEARN = 1 // TODO 修改与其他统一
)

const (
	SECURITY_GROUP_RULE_UNKNOWN = 0
	SECURITY_GROUP_RULE_ACCEPT  = 1
	SECURITY_GROUP_RULE_DROP    = 2

	SECURITY_GROUP_RULE_INGRESS = 1
	SECURITY_GROUP_RULE_EGRESS  = 2

	SECURITY_GROUP_IP_TYPE_UNKNOWN = 0
	SECURITY_GROUP_RULE_IPV4       = 1
	SECURITY_GROUP_RULE_IPV6       = 2

	SECURITY_GROUP_RULE_IPV4_CIDR = "0.0.0.0/0"
	SECURITY_GROUP_RULE_IPV6_CIDR = "::/0"
)

const (
	ROUTING_TABLE_TYPE_VPN             = "vpn"
	ROUTING_TABLE_TYPE_LOCAL           = "local"
	ROUTING_TABLE_TYPE_ROUTER          = "router"
	ROUTING_TABLE_TYPE_NAT_GATEWAY     = "nat-gateway"
	ROUTING_TABLE_TYPE_PEER_CONNECTION = "peer-connection"
	ROUTING_TABLE_TYPE_INSTANCE        = "Instance"
)

const (
	LB_MODEL_INTERNAL = 1
	LB_MODEL_EXTERNAL = 2

	LB_SERVER_TYPE_VM = 1
	LB_SERVER_TYPE_IP = 2
)

const (
	RDS_UNKNOWN = 0

	RDS_TYPE_MYSQL      = 1
	RDS_TYPE_SQL_SERVER = 2
	RDS_TYPE_PPAS       = 3
	RDS_TYPE_PSQL       = 4
	RDS_TYPE_MARIADB    = 5

	RDS_STATE_RUNNING   = 1
	RDS_STATE_RESTORING = 2

	RDS_SERIES_BASIC = 1
	RDS_SERIES_HA    = 2

	RDS_MODEL_PRIMARY   = 1
	RDS_MODEL_READONLY  = 2
	RDS_MODEL_TEMPORARY = 3
	RDS_MODEL_GUARD     = 4
	RDS_MODEL_SHARE     = 5
)

const (
	INTERVAL_1MINUTE = 60
	INTERVAL_1HOUR   = 3600
	INTERVAL_1DAY    = 86400
	INTERVAL_1WEEK   = 604800
	INTERVAL_1MONTH  = 2678400
	INTERVAL_1YEAR   = 31536000
)

const (
	DATA_SOURCE_FLOW   = "flow"
	DATA_SOURCE_APP    = "app"
	DATA_SOURCE_L4_LOG = "flow_log.l4"
	DATA_SOURCE_L7_LOG = "flow_log.l7"

	DATA_SOURCE_STATE_EXCEPTION = 0
	DATA_SOURCE_STATE_NORMAL    = 1
)

const (
	IPV4_MAX_MASK = 32
	IPV6_MAX_MASK = 128

	IPV4_DEFAULT_NETMASK = 24
	IPV6_DEFAULT_NETMASK = 64
)

const (
	POD_NODE_TYPE_MASTER = 1
	POD_NODE_TYPE_NODE   = 2

	POD_NODE_STATE_EXCEPTION = 0
	POD_NODE_STATE_NORMAL    = 1

	POD_NODE_SERVER_TYPE_HOST = 1
	POD_NODE_SERVER_TYPE_VM   = 2
)

const (
	POD_SERVICE_TYPE_CLUSTERIP = 1
	POD_SERVICE_TYPE_NODEPORT  = 2
)

const (
	POD_GROUP_DEPLOYMENT            = 1
	POD_GROUP_STATEFULSET           = 2
	POD_GROUP_RC                    = 3
	POD_GROUP_DAEMON_SET            = 4
	POD_GROUP_REPLICASET_CONTROLLER = 5
)

const (
	POD_STATE_EXCEPTION = 0
	POD_STATE_RUNNING   = 1
)

const (
	RESOURCE_STATE_CODE_SUCCESS   = 1
	RESOURCE_STATE_CODE_DELETING  = 2
	RESOURCE_STATE_CODE_EXCEPTION = 3
	RESOURCE_STATE_CODE_WARNING   = 4
)

const (
	SUB_DOMAIN_ERROR_DISPLAY_NUM = 10
)

const (
	METAFLOW_STATSD_PREFIX       = "metaflow.server.controller"
	CLOUD_METRIC_NAME_TASK_COST  = "cloud.task.cost"
	CLOUD_METRIC_NAME_INFO_COUNT = "cloud.info.count"
	CLOUD_METRIC_NAME_API_COUNT  = "cloud.api.count"
	CLOUD_METRIC_NAME_API_COST   = "cloud.api.cost"
)

var ProtocolMap = map[string]int{
	"TCP": 6,
	"UDP": 17,
}

var CloudMonitorExceptionAPI = map[string]string{
	"aliyun":            "NetworkInterfaceSet,ListenerPortAndProtocol,BackendServer,SnatTableEntry,ForwardTableEntry,KVStoreZone,RouteEntry,Permission",
	"tencent":           "Listeners,NetworkInterfaceSet",
	"openstack":         "services,users",
	"qingcloud":         "DescribeSecurityGroupIPSets,DescribeSecurityGroupRules,DescribeLoadBalancerListeners,DescribeLoadBalancerBackends,DescribeNics,DescribeEips",
	"apsara_stack":      "NetworkInterfaceSet,ListenerPortAndProtocol,BackendServer,SnatTableEntry,ForwardTableEntry,RouteEntry,Permission",
	"tencent_tce":       "DescribeNetworkInterfacesEx,DescribeSecurityGroupPolicy",
	"qingcloud_private": "DescribeSecurityGroupIPSets,DescribeSecurityGroupRules,DescribeLoadBalancerListeners,DescribeLoadBalancerBackends,DescribeNics,DescribeEips",
}

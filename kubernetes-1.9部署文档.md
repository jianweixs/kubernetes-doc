# kubernetes 1.9二进制方式部署文档

## 1.创建TLS证书和秘钥

**注意**：kubernetes 系统的各组件需要使用 TLS 证书对通信进行加密，本文档使用 CloudFlare 的 PKI 工具集 cfssl 来生成 Certificate Authority (CA) 和其它证书；
生成的 CA 证书和秘钥文件如下：

- ca-key.pem
- ca.pem
- kubernetes-key.pem
- kubernetes.pem
- kube-proxy.pem
- kube-proxy-key.pem
- admin.pem
- admin-key.pem

#### 使用证书的组件如下：

- etcd：使用 ca.pem、kubernetes-key.pem、kubernetes.pem；
- kube-apiserver：使用 ca.pem、kubernetes-key.pem、kubernetes.pem；
- kubelet：使用 ca.pem；
- kube-proxy：使用 ca.pem、kube-proxy-key.pem、kube-proxy.pem；
- kubectl：使用 ca.pem、admin-key.pem、admin.pem；
- kube-controller-manager：使用 ca-key.pem、ca.pem
  **注意**：以下操作都在 master 节点即 10.71.10.208 这台主机上执行，证书只需要创建一次即可，以后在向集群中添加新节点时只要将 /etc/kubernetes/ 目录下的证书拷贝到新节点上即可。

#### 安装 CFSSL

```
~]# wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
~]# chmod +x cfssl_linux-amd64
~]# mv cfssl_linux-amd64 /usr/local/bin/cfssl

~]# wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
~]# chmod +x cfssljson_linux-amd64
~]# mv cfssljson_linux-amd64 /usr/local/bin/cfssljson

~]# wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
~]# chmod +x cfssl-certinfo_linux-amd64
~]# mv cfssl-certinfo_linux-amd64 /usr/local/bin/cfssl-certinfo
```

#### 创建 CA (Certificate Authority)

创建 CA 

```
~]# mkdir /root/ssl
~]# cd /root/ssl
~]# cfssl print-defaults config > config.json
~]# cfssl print-defaults csr > csr.json
```

根据config.json文件的格式创建如下的ca-config.json文件
过期时间设置成了 87600h

```
cat > ca-config.json <<EOF
{
  "signing": {
	"default": {
	  "expiry": "87600h"
	},
	"profiles": {
	  "kubernetes": {
		"usages": [
			"signing",
			"key encipherment",
			"server auth",
			"client auth"
		],
		"expiry": "87600h"
	  }
	}
  }
}
>EOF
```

**字段说明**

- ca-config.json：可以定义多个 profiles，分别指定不同的过期时间、使用场景等参数；后续在签名证书时使用某个 profile；
- signing：表示该证书可用于签名其它证书；生成的 ca.pem 证书中 CA=TRUE；
  *server auth：表示client可以用该 CA 对server提供的证书进行验证；
- client auth：表示server可以用该CA对client提供的证书进行验证；

#### 创建 CA 证书签名请求

创建 ca-csr.json 文件，内容如下：

```
{
  "CN": "kubernetes",
  "key": {
	"algo": "rsa",
	"size": 2048
  },
  "names": [
	{
	  "C": "CN",
	  "ST": "BeiJing",
	  "L": "BeiJing",
	  "O": "k8s",
	  "OU": "System"
	}
  ],
	"ca": {
	   "expiry": "87600h"
	}
}
```

- "CN"：Common Name，kube-apiserver 从证书中提取该字段作为请求的用户名 (User Name)；浏览器使用该字段验证网站是否合法；
- "O"：Organization，kube-apiserver 从证书中提取该字段作为请求用户所属的组 (Group)；

生成 CA 证书和私钥

```
~]# cfssl gencert -initca ca-csr.json | cfssljson -bare ca
~]# ls ca*
ca-config.json  ca.csr  ca-csr.json  ca-key.pem  ca.pem
```

#### 创建 kubernetes 证书

创建 kubernetes 证书签名请求文件 kubernetes-csr.json：

```
{
    "CN": "kubernetes",
    "hosts": [
      "k8s.test.com.cn",
      "127.0.0.1",
      "10.254.0.1",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
```

如果 hosts 字段不为空则需要指定授权使用该证书的 IP 或域名列表，由于该证书后续被 kubernetes master 集群使用，kubernetes master 集群的域名列表 和 kubernetes 服务的服务 IP（一般是 kube-apiserver 指定的 service-cluster-ip-range 网段的第一个IP，如 10.254.0.1）。

这是最小化安装的kubernetes集群，包括一个私有镜像仓库，三个节点的kubernetes集群，以上物理节点的IP也可以更换为主机名。
生成 kubernetes 证书和私钥

```
~]# cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
~]# ls kubernetes*`
kubernetes.csr  kubernetes-csr.json  kubernetes-key.pem  kubernetes.pem
```

#### 创建 admin 证书

创建 admin 证书签名请求文件 admin-csr.json：

```
{
  "CN": "admin",
  "hosts": [],
  "key": {
	"algo": "rsa",
	"size": 2048
  },
  "names": [
	{
	  "C": "CN",
	  "ST": "BeiJing",
	  "L": "BeiJing",
	  "O": "system:masters",
	  "OU": "System"
	}
  ]
}
```

后续 kube-apiserver 使用 RBAC 对客户端(如 kubelet、kube-proxy、Pod)请求进行授权；

- kube-apiserver 预定义了一些 RBAC 使用的 RoleBindings，如 cluster-admin 将 Group system:masters 与 Role cluster-admin 绑定，该 Role 授予了调用kube-apiserver 的所有 API的权限；
- O 指定该证书的 Group 为 system:masters，kubelet 使用该证书访问 kube-apiserver 时 ，由于证书被 CA 签名，所以认证通过，同时由于证书用户组为经过预授权的 system:masters，所以被授予访问所有 API 的权限；

**注意**：这个admin 证书，是将来生成管理员用的kube config 配置文件用的，现在我们一般建议使用RBAC 来对kubernetes 进行角色权限控制， kubernetes 将证书中的CN 字段 作为User， O 字段作为 Group（具体参考 Kubernetes中的用户与身份认证授权中 X509 Client Certs 一段）。
在搭建完 kubernetes 集群后，我们可以通过命令: `kubectl get clusterrolebinding cluster-admin -o yaml `查看到 clusterrolebinding cluster-admin 的 subjects 的 kind 是 Group，name 是 system:masters。 roleRef 对象是 ClusterRole cluster-admin。 意思是凡是 system:masters Group 的 user 或者 serviceAccount 都拥有 cluster-admin 的角色。 因此我们在使用 kubectl 命令时候，才拥有整个集群的管理权限。可以使用 kubectl get clusterrolebinding cluster-admin -o yaml 来查看。

```
~]# kubectl get clusterrolebinding cluster-admin -o yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
	rbac.authorization.kubernetes.io/autoupdate: "true"
  creationTimestamp: 2017-04-11T11:20:42Z
  labels:
	kubernetes.io/bootstrapping: rbac-defaults
  name: cluster-admin
  resourceVersion: "52"
  selfLink: /apis/rbac.authorization.k8s.io/v1/clusterrolebindings/cluster-admin
  uid: e61b97b2-1ea8-11e7-8cd7-f4e9d49f8ed0
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: system:masters
```

生成 admin 证书和私钥：

```
~]# cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
~]# ls admin*
admin.csr  admin-csr.json  admin-key.pem  admin.pem
```

#### 创建 kube-proxy 证书

创建 kube-proxy 证书签名请求文件 kube-proxy-csr.json：

```
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
	"algo": "rsa",
	"size": 2048
  },
  "names": [
	{
	  "C": "CN",
	  "ST": "BeiJing",
	  "L": "BeiJing",
	  "O": "k8s",
	  "OU": "System"
	}
  ]
}
```

- CN 指定该证书的 User 为 system:kube-proxy；
- kube-apiserver 预定义的 RoleBinding cluster-admin 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；

生成 kube-proxy 客户端证书和私钥

```
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes  kube-proxy-csr.json | cfssljson -bare kube-proxy
ls kube-proxy*
kube-proxy.csr  kube-proxy-csr.json  kube-proxy-key.pem  kube-proxy.pem
```

#### 校验证书

以 kubernetes 证书为例，使用 opsnssl 命令

```
$ openssl x509  -noout -text -in  kubernetes.pem
Certificate:
	Data:
		Version: 3 (0x2)
		Serial Number:
			29:8e:f5:12:e7:d6:6a:b2:40:e5:70:d4:f6:d9:20:c0:4a:bc:63:b6
	Signature Algorithm: sha256WithRSAEncryption
		Issuer: C=CN, ST=BeiJing, L=BeiJing, O=k8s, OU=System, CN=kubernetes
		Validity
			Not Before: May 15 09:32:00 2018 GMT
			Not After : May 12 09:32:00 2028 GMT
		Subject: C=CN, ST=BeiJing, L=BeiJing, O=k8s, OU=System, CN=kubernetes
		Subject Public Key Info:
			Public Key Algorithm: rsaEncryption
				Public-Key: (2048 bit)
		X509v3 extensions:
			X509v3 Key Usage: critical
				Digital Signature, Key Encipherment
			X509v3 Extended Key Usage:
				TLS Web Server Authentication, TLS Web Client Authentication
			X509v3 Basic Constraints: critical
				CA:FALSE
			X509v3 Subject Key Identifier:
				FB:B8:B7:5A:55:6F:7D:B7:C0:65:4F:A3:92:EA:B7:E3:28:01:11:9A
			X509v3 Authority Key Identifier:
				keyid:6A:24:08:FE:66:D7:FF:7B:F9:57:CC:4E:81:97:64:F8:B4:F7:D0:BF

			X509v3 Subject Alternative Name:
				DNS:k8s.test.com.cn, DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.254.0.1
...
```

- 确认 Issuer 字段的内容和 ca-csr.json 一致；
- 确认 Subject 字段的内容和 kubernetes-csr.json 一致；
- 确认 X509v3 Subject Alternative Name 字段的内容和 kubernetes-csr.json 一致；
- 确认 X509v3 Key Usage、Extended Key Usage 字段的内容和 ca-config.json 中 kubernetes profile 一致；

使用 cfssl-certinfo 命令

```
$ cfssl-certinfo -cert kubernetes.pem
...
{
  "subject": {
	"common_name": "kubernetes",
	"country": "CN",
	"organization": "k8s",
	"organizational_unit": "System",
	"locality": "BeiJing",
	"province": "BeiJing",
	"names": [
	  "CN",
	  "BeiJing",
	  "BeiJing",
	  "k8s",
	  "System",
	  "kubernetes"
	]
  },
  "issuer": {
	"common_name": "kubernetes",
	"country": "CN",
	"organization": "k8s",
	"organizational_unit": "System",
	"locality": "BeiJing",
	"province": "BeiJing",
	"names": [
	  "CN",
	  "BeiJing",
	  "BeiJing",
	  "k8s",
	  "System",
	  "kubernetes"
	]
  },
  "serial_number": "237256676365269637429135088024757254892960900022",
  "sans": [
	"k8s.test.com.cn",
	"kubernetes",
	"kubernetes.default",
	"kubernetes.default.svc",
	"kubernetes.default.svc.cluster",
	"kubernetes.default.svc.cluster.local",
	"127.0.0.1",
	"10.254.0.1"
  ],
  "not_before": "2018-05-15T09:32:00Z",
  "not_after": "2028-05-12T09:32:00Z",
  "sigalg": "SHA256WithRSA",
},
...

```

分发证书
将生成的证书和秘钥文件（后缀名为.pem）拷贝到所有机器的 /etc/kubernetes/ssl 目录下备用；

```
mkdir -p /etc/kubernetes/ssl
cp *.pem /etc/kubernetes/ssl
```

## 2.创建 kubeconfig 文件

注意：请先参考 安装kubectl命令行工具，先在 master 节点上安装 kubectl 然后再进行下面的操作。
kubelet、kube-proxy 等 Node 机器上的进程与 Master 机器的 kube-apiserver 进程通信时需要认证和授权；
kubernetes 1.4 开始支持由 kube-apiserver 为客户端生成 TLS 证书的 TLS Bootstrapping 功能，这样就不需要为每个客户端生成证书了；该功能当前仅支持为 kubelet 生成证书；
因为我的master节点和node节点复用，所有在这一步其实已经安装了kubectl。参考安装kubectl命令行工具。
以下操作只需要在master节点上执行，生成的*.kubeconfig文件可以直接拷贝到node节点的/etc/kubernetes目录下。
创建 TLS Bootstrapping Token
Token auth file
Token可以是任意的包含128 bit的字符串，可以使用安全的随机数发生器生成。

```
export BOOTSTRAP_TOKEN=$(head -c 16 /dev/urandom | od -An -t x | tr -d ' ')
cat > token.csv <<EOF
${BOOTSTRAP_TOKEN},kubelet-bootstrap,10001,"system:kubelet-bootstrap"
EOF
```

后三行是一句，直接复制上面的脚本运行即可。
注意：在进行后续操作前请检查 token.csv 文件，确认其中的 ${BOOTSTRAP_TOKEN} 环境变量已经被真实的值替换。
BOOTSTRAP_TOKEN 将被写入到 kube-apiserver 使用的 token.csv 文件和 kubelet 使用的 bootstrap.kubeconfig 文件，如果后续重新生成了 BOOTSTRAP_TOKEN，则需要：
更新 token.csv 文件，分发到所有机器 (master 和 node）的 /etc/kubernetes/ 目录下，分发到node节点上非必需；
重新生成 bootstrap.kubeconfig 文件，分发到所有 node 机器的 /etc/kubernetes/ 目录下；
重启 kube-apiserver 和 kubelet 进程；
重新 approve kubelet 的 csr 请求；

```
cp token.csv /etc/kubernetes/
```

创建 kubelet bootstrapping kubeconfig 文件
执行下面的命令时需要先安装kubectl命令，请参考安装kubectl命令行工具。

```
cd /etc/kubernetes
export KUBE_APISERVER="https://k8s.test.com.cn:6443"

# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=bootstrap.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials kubelet-bootstrap \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=bootstrap.kubeconfig

# 设置上下文参数
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kubelet-bootstrap \
  --kubeconfig=bootstrap.kubeconfig

# 设置默认上下文
kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```

- --embed-certs 为 true 时表示将 certificate-authority 证书写入到生成的 bootstrap.kubeconfig 文件中；
- 设置客户端认证参数时没有指定秘钥和证书，后续由 kube-apiserver 自动生成；
  创建 kube-proxy kubeconfig 文件

```
export KUBE_APISERVER="https://k8s.test.com.cn:6443"
	# 设置集群参数
	kubectl config set-cluster kubernetes \
	--certificate-authority=/etc/kubernetes/ssl/ca.pem \
	--embed-certs=true \
	--server=${KUBE_APISERVER} \
	--kubeconfig=kube-proxy.kubeconfig
	# 设置客户端认证参数
	kubectl config set-credentials kube-proxy \
	--client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
	--client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
	--embed-certs=true \
	--kubeconfig=kube-proxy.kubeconfig
	# 设置上下文参数
	kubectl config set-context default \
	--cluster=kubernetes \
	--user=kube-proxy \
	--kubeconfig=kube-proxy.kubeconfig
	# 设置默认上下文
	kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

设置集群参数和客户端认证参数时 --embed-certs 都为 true，这会将 certificate-authority、client-certificate 和 client-key 指向的证书文件内容写入到生成的 kube-proxy.kubeconfig 文件中；
kube-proxy.pem 证书中 CN 为 system:kube-proxy，kube-apiserver 预定义的 RoleBinding cluster-admin 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；
分发 kubeconfig 文件
将两个 kubeconfig 文件分发到所有 Node 机器的 /etc/kubernetes/ 目录

```shell
# cp bootstrap.kubeconfig kube-proxy.kubeconfig /etc/kubernetes/
```



## 3.安装kubectl命令行工具

本文档介绍下载和配置 kubernetes 集群命令行工具 kubelet 的步骤。

### 下载 kubectl

注意请下载对应的Kubernetes版本的安装包。

```
wget https://dl.k8s.io/v1.9.4/kubernetes-client-linux-amd64.tar.gz
tar -xzvf kubernetes-client-linux-amd64.tar.gz
cp kubernetes/client/bin/kube* /usr/bin/
chmod a+x /usr/bin/kube*
```

### 创建 kubectl kubeconfig 文件

```shell
export KUBE_APISERVER="https://k8s.test.com.cn:6443"
# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER}
# 设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=/etc/kubernetes/ssl/admin.pem \
  --embed-certs=true \
  --client-key=/etc/kubernetes/ssl/admin-key.pem
# 设置上下文参数
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin
# 设置默认上下文
kubectl config use-context kubernetes
```

- `admin.pem` 证书 OU 字段值为 `system:masters`，`kube-apiserver` 预定义的 RoleBinding `cluster-admin` 将 Group `system:masters` 与 Role `cluster-admin` 绑定，该 Role 授予了调用`kube-apiserver` 相关 API 的权限；
- 生成的 kubeconfig 被保存到 `~/.kube/config` 文件；

**注意：**`~/.kube/config`文件拥有对该集群的最高权限，请妥善保管。



## 4.部署Master节点

![image-20180529234448583](/var/folders/bv/vxdrhkdx38s16rfjdvcfrqzr0000gn/T/abnerworks.Typora/image-20180529234448583.png)



kubernetes master 节点包含的组件：

- kube-apiserver
- kube-scheduler
- kube-controller-manager
  目前这三个组件需要部署在同一台机器上。
  kube-scheduler、kube-controller-manager 和 kube-apiserver 三者的功能紧密相关；
  同时只能有一个 kube-scheduler、kube-controller-manager 进程处于工作状态，如果运行多个，则需要通过选举产生一个 leader；

server 的 tarball kubernetes-server-linux-amd64.tar.gz 已经包含了 client(kubectl) 二进制文件，所以不用单独下载kubernetes-client-linux-amd64.tar.gz文件；

```
~]# wget https://dl.k8s.io/v1.9.4/kubernetes-client-linux-amd64.tar.gz
~]# wget https://dl.k8s.io/v1.9.4/kubernetes-server-linux-amd64.tar.gz
~]# tar -xzvf kubernetes-server-linux-amd64.tar.gz
~]# cd kubernetes
~]# tar -xzvf  kubernetes-src.tar.gz
```

将二进制文件拷贝到指定路径

```
# cp -r server/bin/{kube-apiserver,kube-controller-manager,kube-scheduler,kubectl,kube-proxy,kubelet} /usr/local/bin/
```

#### 配置和启动 kube-apiserver

创建 kube-apiserver的service配置文件
service配置文件/usr/lib/systemd/system/kube-apiserver.service内容：

```shell
[Unit]
Description=Kubernetes API Service
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
After=etcd.service

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/apiserver
ExecStart=/usr/local/bin/kube-apiserver \
		$KUBE_LOGTOSTDERR \
		$KUBE_LOG_LEVEL \
		$KUBE_ETCD_SERVERS \
		$KUBE_API_ADDRESS \
		$KUBE_API_PORT \
		$KUBELET_PORT \
		$KUBE_ALLOW_PRIV \
		$KUBE_SERVICE_ADDRESSES \
		$KUBE_ADMISSION_CONTROL \
		$KUBE_API_ARGS
Restart=on-failure
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

/etc/kubernetes/config文件的内容为：

```
###
# kubernetes system config
#
# The following values are used to configure various aspects of all
# kubernetes services, including
#
#   kube-apiserver.service
#   kube-controller-manager.service
#   kube-scheduler.service
#   kubelet.service
#   kube-proxy.service
# logging to stderr means we get it in the systemd journal
KUBE_LOGTOSTDERR="--logtostderr=true"

# journal message level, 0 is debug
KUBE_LOG_LEVEL="--v=0"

# Should this cluster be allowed to run privileged docker containers
KUBE_ALLOW_PRIV="--allow-privileged=true"

# How the controller-manager, scheduler, and proxy find the apiserver
KUBE_MASTER="--master=http://127.0.0.1:8080"
```

该配置文件同时被kube-apiserver、kube-controller-manager、kube-scheduler、kubelet、kube-proxy使用。
apiserver配置文件/etc/kubernetes/apiserver内容为：

```shell
###
## kubernetes system config
##
## The following values are used to configure the kube-apiserver
##
#
## The address on the local server to listen to.
KUBE_API_ADDRESS="--advertise-address=10.71.10.188 --bind-address=0.0.0.0 --insecure-bind-address=0.0.0.0"
#
## The port on the local server to listen on.
KUBE_API_PORT="--insecure-port=8080 --secure-port=6443"
#
## Port minions listen on
#KUBELET_PORT="--kubelet-port=10250"
#
## Comma separated list of nodes in the etcd cluster
KUBE_ETCD_SERVERS="--etcd-servers=http://10.71.10.188:2379"
#
## Address range to use for services
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"
#
## default admission control policies
KUBE_ADMISSION_CONTROL="--admission-control=ServiceAccount,NamespaceLifecycle,NamespaceExists,LimitRanger,ResourceQuota,NodeRestriction,DefaultStorageClass"
#
## Add your own!

KUBE_API_ARGS="--authorization-mode=RBAC,Node \
				--cert-dir=/etc/kubernetes/ssl \
				--log-dir=/data1/kubernetes/logs \
				--kubelet-https=true \
				--enable-bootstrap-token-auth \
				--token-auth-file=/etc/kubernetes/token.csv \
				--service-node-port-range=30000-32767 \
				--client-ca-file=/etc/kubernetes/ssl/ca.pem \
				--tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
				--tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem \
				--service-account-key-file=/etc/kubernetes/ssl/ca-key.pem \
				--enable-swagger-ui=true \
				--apiserver-count=3 \
				--audit-log-maxage=30 \
				--audit-log-maxbackup=3 \
				--audit-log-maxsize=100 \
				--audit-log-path=/var/lib/audit.log \
				--event-ttl=1h "
```

- --experimental-bootstrap-token-auth Bootstrap Token Authentication在1.9版本已经变成了正式feature，参数名称改为--enable-bootstrap-token-auth
  如果中途修改过--service-cluster-ip-range地址，则必须将default命名空间的kubernetes的service给删除，使用命令：kubectl delete service kubernetes，然后系统会自动用新的ip重建这个service，不然apiserver的log有报错the cluster IP x.x.x.x for service kubernetes/default is not within the service CIDR x.x.x.x/16; please recreate
- --authorization-mode=RBAC 指定在安全端口使用 RBAC 授权模式，拒绝未通过授权的请求；
  kube-scheduler、kube-controller-manager 一般和 kube-apiserver 部署在同一台机器上，它们使用非安全端口和 kube-apiserver通信;
  kubelet、kube-proxy、kubectl 部署在其它 Node 节点上，如果通过安全端口访问 kube-apiserver，则必须先通过 TLS 证书认证，再通过 RBAC 授权；kube-proxy、kubectl 通过在使用的证书里指定相关的 User、Group 来达到通过 RBAC 授权的目的；
  如果使用了 kubelet TLS Boostrap 机制，则不能再指定 --kubelet-certificate-authority、* --kubelet-client-certificate 和 --kubelet-client-key 选项，否则后续 kube-apiserver 校验 kubelet 证书时出现 ”x509: certificate signed by unknown authority“ 错误；
- --admission-control 值必须包含 ServiceAccount；
- --bind-address 不能为 127.0.0.1；
- --runtime-config配置为rbac.authorization.k8s.io/v1beta1，表示运行时的apiVersion；
- --service-cluster-ip-range 指定 Service Cluster IP 地址段，该地址段不能路由可达；
  缺省情况下 kubernetes 对象保存在 etcd /registry 路径下，可以通过 --etcd-prefix 参数进行调整；
  如果需要开通http的无认证的接口，则可以增加以下两个参数：--insecure-port=8080 --insecure-bind-address=127.0.0.1。注意，生产上不要绑定到非127.0.0.1的地址上
  **Kubernetes 1.9**

对于Kubernetes1.9集群，需要注意配置KUBE_API_ARGS环境变量中的--authorization-mode=Node,RBAC，增加对Node授权的模式，否则将无法注册node。

- --experimental-bootstrap-token-auth Bootstrap Token Authentication在kubernetes 1.9版本已经废弃，参数名称改为--enable-bootstrap-token-auth
  启动kube-apiserver

```
~]# systemctl daemon-reload
~]# systemctl enable kube-apiserver
~]# systemctl start kube-apiserver
~]# systemctl status kube-apiserver
```

#### 配置和启动 kube-controller-manager

创建 kube-controller-manager的serivce配置文件
文件路径/usr/lib/systemd/system/kube-controller-manager.service

```shell
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/controller-manager
ExecStart=/usr/local/bin/kube-controller-manager \
		$KUBE_LOGTOSTDERR \
		$KUBE_LOG_LEVEL \
		$KUBE_MASTER \
		$KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

配置文件/etc/kubernetes/controller-manager。

```shell
###
# The following values are used to configure the kubernetes controller-manager

# defaults from config and apiserver should be adequate

# Add your own!
KUBE_CONTROLLER_MANAGER_ARGS="--address=127.0.0.1 --service-cluster-ip-range=10.254.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem --root-ca-file=/etc/kubernetes/ssl/ca.pem --leader-elect=true"

```

- --service-cluster-ip-range 参数指定 Cluster 中 Service 的CIDR范围，该网络在各 Node 间必须路由不可达，必须和 kube-apiserver 中的参数一致；
- --cluster-signing-* 指定的证书和私钥文件用来签名为 TLS BootStrap 创建的证书和私钥；
- --root-ca-file 用来对 kube-apiserver 证书进行校验，指定该参数后，才会在Pod 容器的 ServiceAccount 中放置该 CA 证书文件；
- --address 值必须为 127.0.0.1，kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器；
  启动 kube-controller-manager

```shell
~]# systemctl daemon-reload
~]# systemctl enable kube-controller-manager
~]# systemctl start kube-controller-manager
~]# systemctl status kube-controller-manager
```

#### 配置和启动 kube-scheduler

创建 kube-scheduler的serivce配置文件
文件路径/usr/lib/systemd/system/kube-scheduler.service。

```shell
[Unit]
Description=Kubernetes Scheduler Plugin
Documentation=https://github.com/GoogleCloudPlatform/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/scheduler
ExecStart=/usr/local/bin/kube-scheduler \
			$KUBE_LOGTOSTDERR \
			$KUBE_LOG_LEVEL \
			$KUBE_MASTER \
			$KUBE_SCHEDULER_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

配置文件/etc/kubernetes/scheduler。

```shell
###
# kubernetes scheduler config
# default config should be adequate
# Add your own!
KUBE_SCHEDULER_ARGS="--leader-elect=true --address=127.0.0.1"
```

- --address 值必须为 127.0.0.1，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器；
  启动 kube-scheduler

```shell
~]# systemctl daemon-reload
~]# systemctl enable kube-scheduler
~]# systemctl start kube-scheduler
~]# systemctl status kube-scheduler
```

验证 master 节点功能

```shell
~]# kubectl get componentstatuses
NAME                 STATUS    MESSAGE              ERROR
scheduler            Healthy   ok
controller-manager   Healthy   ok
etcd-0               Healthy   {"health": "true"}
```

如果有组件report unhealthy请参考：https://github.com/kubernetes-incubator/bootkube/issues/64

## 5.部署Node节点

#### 安装docker-ce：

要安装Docker CE，您需要维护的CentOS 7版本。不支持或测试归档版本。

该`centos-extras`库必须启用。此存储库默认情况下[处于启用状态](https://wiki.centos.org/AdditionalResources/Repositories)，但如果您已禁用它，则需要 [重新启用它](https://wiki.centos.org/AdditionalResources/Repositories)。

`overlay2`建议使用存储驱动程序。

CentOS 7下安装Docker，Docker CE支持64位CentOS7，并且要求内核版本比低于3.10.

##### 卸载旧的版本：

`# yum remove docker docker-common docker-selinux docker`

##### 使用yum安装：

`# yum install -y yum-utils device-mapper-persisten-data lvm`

##### 安装最新版Docker CE：

`# yum-config-manager --enable docker-ce-edge`
`# yum install docker-ce`

##### 启动Docker CE

`# systemctl enable docker`
`# systemctl start docker`

##### 测试Docker 是否安装正确

`# docker run hello-word`

#### 配置kubelet

对于kuberentes1.9集群，必须关闭swap，否则kubelet启动将失败。

1.修改`/etc/fstab`将，swap系统注释掉。

2.执行swapoff -a 关闭swap

kubelet 启动时向 kube-apiserver 发送 TLS bootstrapping 请求，需要先将 bootstrap token 文件中的 kubelet-bootstrap 用户赋予 system:node-bootstrapper cluster 角色(role)， 然后 kubelet 才能有权限创建认证请求(certificate signing requests)：

```shell
~]# cd /etc/kubernetes
~]# kubectl create clusterrolebinding kubelet-bootstrap \
  --clusterrole=system:node-bootstrapper \
  --user=kubelet-bootstrap
```

- --user=kubelet-bootstrap 是在 /etc/kubernetes/token.csv 文件中指定的用户名，同时也写入了 /etc/kubernetes/bootstrap.kubeconfig 文件；
  下载最新的kubelet和kube-proxy二进制文件
  注意请下载对应的Kubernetes版本的安装包。

```shell
~]# wget https://dl.k8s.io/v1.9.4/kubernetes-server-linux-amd64.tar.gz
~]# tar -xzvf kubernetes-server-linux-amd64.tar.gz
~]# cd kubernetes
~]# tar -xzvf  kubernetes-src.tar.gz
~]# cp -r ./server/bin/{kube-proxy,kubelet} /usr/local/bin/
```

####  

创建kubelet的service配置文件
文件位置/usr/lib/systemd/system/kubelet.service。

```shell
[Unit]
Description=Kubernetes Kubelet Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/kubelet
ExecStart=/usr/local/bin/kubelet \
			$KUBE_LOGTOSTDERR \
			$KUBE_LOG_LEVEL \
			$KUBELET_API_SERVER \
			$KUBELET_ADDRESS \
			$KUBELET_PORT \
			$KUBELET_HOSTNAME \
			$KUBE_ALLOW_PRIV \
			$KUBELET_POD_INFRA_CONTAINER \
			$KUBELET_ARGS
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

kubelet的配置文件/etc/kubernetes/kubelet。其中的IP地址更改为你的每台node节点的IP地址。
注意：在启动kubelet之前，需要先手动创建/var/lib/kubelet目录。
下面是kubelet的配置文件/etc/kubernetes/kubelet:

```shell
###
## kubernetes kubelet (minion) config
#
## The address for the info server to serve on (set to 0.0.0.0 or "" for all interfaces)
KUBELET_ADDRESS="--address=0.0.0.0"
#
## The port for the info server to serve on
#KUBELET_PORT="--port=10250"
#
## You may leave this blank to use the actual hostname
KUBELET_HOSTNAME="--hostname-override=10.71.10.188"
#
## location of the api-server
## COMMENT THIS ON KUBERNETES 1.8+
#
## pod infrastructure container
KUBELET_POD_INFRA_CONTAINER="--pod-infra-container-image=registry.access.redhat.com/rhel7/pod-infrastructure:latest"
#
## Add your own!
KUBELET_ARGS="--cgroup-driver=systemd \
			--cluster-dns=10.254.0.2 \
			--resolv-conf=/etc/resolv.conf \
			--bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig \
			--kubeconfig=/etc/kubernetes/kubelet.kubeconfig \
			--cert-dir=/etc/kubernetes/ssl \
			--cluster-domain=cluster.local \
			--hairpin-mode promiscuous-bridge \
			--serialize-image-pulls=false"
```

如果使用systemd方式启动，则需要额外增加两个参数--runtime-cgroups=/systemd/system.slice --kubelet-cgroups=/systemd/system.slice
--address 不能设置为 127.0.0.1，否则后续 Pods 访问 kubelet 的 API 接口时会失败，因为 Pods 访问的 127.0.0.1 指向自己而不是 kubelet；
如果设置了--hostname-override 选项，则 kube-proxy 也需要设置该选项，否则会出现找不到 Node 的情况；

- --cgroup-driver 配置成 systemd，不要使用cgroup，否则在 CentOS 系统中 kubelet 将启动失败（保持docker和kubelet中的cgroup driver配置一致即可，不一定非使用systemd）。
- --experimental-bootstrap-kubeconfig 指向 bootstrap kubeconfig 文件，kubelet 使用该文件中的用户名和 token 向 kube-apiserver 发送 TLS Bootstrapping 请求；
  管理员通过了 CSR 请求后，kubelet 自动在 --cert-dir 目录创建证书和私钥文件(kubelet-client.crt 和 kubelet-client.key)，然后写入 --kubeconfig 文件；
  建议在 --kubeconfig 配置文件中指定 kube-apiserver 地址，如果未指定 --api-servers 选项，则必须指定 --require-kubeconfig 选项后才从配置文件中读取 kube-apiserver 的地址，否则 kubelet 启动后将找不到 kube-apiserver (日志中提示未找到 API Server），kubectl get nodes 不会返回对应的 Node 信息;
- --cluster-dns 指定 kubedns 的 Service IP(可以先分配，后续创建 kubedns 服务时指定该 IP)，--cluster-domain 指定域名后缀，这两个参数同时指定后才会生效；
  --cluster-domain 指定 pod 启动时 /etc/resolve.conf 文件中的 search domain ，起初我们将其配置成了 cluster.local.，这样在解析 service 的 DNS 名称时是正常的，可是在解析 headless service 中的 FQDN pod name 的时候却错误，因此我们将其修改为 cluster.local，去掉嘴后面的 ”点号“ 就可以解决该问题，关于 kubernetes 中的域名/服务名称解析请参见我的另一篇文章。
- --kubeconfig=/etc/kubernetes/kubelet.kubeconfig中指定的kubelet.kubeconfig文件在第一次启动kubelet之前并不存在，请看下文，当通过CSR请求后会自动生成kubelet.kubeconfig文件，如果你的节点上已经生成了~/.kube/config文件，你可以将该文件拷贝到该路径下，并重命名为kubelet.kubeconfig，所有node节点可以共用同一个kubelet.kubeconfig文件，这样新添加的节点就不需要再创建CSR请求就能自动添加到kubernetes集群中。同样，在任意能够访问到kubernetes集群的主机上使用kubectl --kubeconfig命令操作集群时，只要使用~/.kube/config文件就可以通过权限认证，因为这里面已经有认证信息并认为你是admin用户，对集群拥有所有权限。
- KUBELET_POD_INFRA_CONTAINER 是基础镜像容器
  启动kublet

```shell
~]# systemctl daemon-reload
~]# systemctl enable kubelet
~]# systemctl start kubelet
~]# systemctl status kubelet
```

通过 kublet 的 TLS 证书请求
kubelet 首次启动时向 kube-apiserver 发送证书签名请求，必须通过后 kubernetes 系统才会将该 Node 加入到集群。
查看未授权的 CSR 请求

```shell
~]# kubectl get csr
NAME        AGE       REQUESTOR           CONDITION
node-csr-oCVlmDaFr5VTBKh8GEmvYX3uU1j5AJBd8xdMVFe1rfA   4m        kubelet-bootstrap   Pending
~]# kubectl get nodes
No resources found.
```

通过 CSR 请求

```shell
~]# kubectl certificate approve node-csr-oCVlmDaFr5VTBKh8GEmvYX3uU1j5AJBd8xdMVFe1rfA
certificatesigningrequest "node-csr-oCVlmDaFr5VTBKh8GEmvYX3uU1j5AJBd8xdMVFe1rfA" approved
~]# kubectl get nodes
NAME           STATUS    ROLES     AGE       VERSION
10.71.10.188   Ready     <none>    1d        v1.9.4
```

自动生成了 kubelet kubeconfig 文件和公私钥

```shell
$ ls -l /etc/kubernetes/kubelet.kubeconfig
-rw------- 1 root root 2284 Apr  7 02:07 /etc/kubernetes/kubelet.kubeconfig
$ ls -l /etc/kubernetes/ssl/kubelet*
-rw-r--r-- 1 root root 1046 Apr  7 02:07 /etc/kubernetes/ssl/kubelet-client.crt
-rw------- 1 root root  227 Apr  7 02:04 /etc/kubernetes/ssl/kubelet-client.key
-rw-r--r-- 1 root root 1103 Apr  7 02:07 /etc/kubernetes/ssl/kubelet.crt
-rw------- 1 root root 1675 Apr  7 02:07 /etc/kubernetes/ssl/kubelet.key
```

假如你更新kubernetes的证书，只要没有更新token.csv，当重启kubelet后，该node就会自动加入到kuberentes集群中，而不会重新发送certificaterequest，也不需要在master节点上执行kubectl certificate approve操作。前提是不要删除node节点上的/etc/kubernetes/ssl/kubelet*和/etc/kubernetes/kubelet.kubeconfig文件。否则kubelet启动时会提示找不到证书而失败。

注意：如果启动kubelet的时候见到证书相关的报错，有个trick可以解决这个问题，可以将master节点上的~/.kube/config文件（该文件在安装kubectl命令行工具这一步中将会自动生成）拷贝到node节点的/etc/kubernetes/kubelet.kubeconfig位置，这样就不需要通过CSR，当kubelet启动后就会自动加入的集群中。

#### 配置 kube-proxy

创建 kube-proxy 的service配置文件
文件路径/usr/lib/systemd/system/kube-proxy.service。

```shell
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/proxy
ExecStart=/usr/local/bin/kube-proxy \
		$KUBE_LOGTOSTDERR \
		$KUBE_LOG_LEVEL \
		$KUBE_MASTER \
		$KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

kube-proxy配置文件/etc/kubernetes/proxy。

```shell
###
# kubernetes proxy config

# default config should be adequate

# Add your own!
KUBE_PROXY_ARGS="--bind-address=0.0.0.0 \
		--hostname-override=10.71.10.188 \ 
		--kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig \
		--cluster-cidr=10.254.0.0/17"
```

- --hostname-override 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 iptables 规则；
  kube-proxy 根据 --cluster-cidr 判断集群内部和外部流量，指定 --cluster-cidr 或 --masquerade-all 选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT；
- --kubeconfig 指定的配置文件嵌入了 kube-apiserver 的地址、用户名、证书、秘钥等请求和认证信息；
  预定义的 RoleBinding cluster-admin 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；
  完整 unit 见 kube-proxy.service
  启动 kube-proxy

```shell
systemctl daemon-reload
systemctl enable kube-proxy
systemctl start kube-proxy
systemctl status kube-proxy
```

## 6.部署calico网络

官方文档地址：https://docs.projectcalico.org/v2.6/usage/configuration/bgp

安装Calico：

1、下载calico.yaml (etcd_endpoints在提供的ConfigMap中配置以匹配您的etcd集群。)
如下yaml文定义了以daemon set的形式在每个node上启动calico的pod

```yaml
[root@gaea188 calico]# cat calico.yaml
# Calico Version v2.6.8
# https://docs.projectcalico.org/v2.6/releases#v2.6.8
# This manifest includes the following component versions:
#   calico/node:v2.6.8
#   calico/cni:v1.11.4
#   calico/kube-controllers:v1.0.3

# This ConfigMap is used to configure a self-hosted Calico installation.
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: kube-system
data:
  # The location of your etcd cluster.  This uses the Service clusterIP
  # defined below.
  etcd_endpoints: "http://10.71.10.188:2379"

  # Configure the Calico backend to use.
  calico_backend: "bird"

  # The CNI network configuration to install on each node.
  cni_network_config: |-
    {
        "name": "k8s-pod-network",
        "cniVersion": "0.1.0",
        "type": "calico",
        "etcd_endpoints": "__ETCD_ENDPOINTS__",
        "log_level": "info",
        "mtu": 1500,
        "ipam": {
            "type": "calico-ipam"
        },
        "policy": {
            "type": "k8s",
             "k8s_api_root": "https://__KUBERNETES_SERVICE_HOST__:__KUBERNETES_SERVICE_PORT__",
             "k8s_auth_token": "__SERVICEACCOUNT_TOKEN__"
        },
        "kubernetes": {
            "kubeconfig": "/etc/cni/net.d/__KUBECONFIG_FILENAME__"
        }
    }

---

# This manifest installs the calico/node container, as well
# as the Calico CNI plugins and network config on
# each master and worker node in a Kubernetes cluster.
kind: DaemonSet
apiVersion: extensions/v1beta1
metadata:
  name: calico-node
  namespace: kube-system
  labels:
    k8s-app: calico-node
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        # Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
        # reserves resources for critical add-on pods so that they can be rescheduled after
        # a failure.  This annotation works in tandem with the toleration below.
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      hostNetwork: true
      tolerations:
      # This taint is set by all kubelets running `--cloud-provider=external`
      # so we should tolerate it to schedule the calico pods
      - key: node.cloudprovider.kubernetes.io/uninitialized
        value: "true"
        effect: NoSchedule
      # Toleration allows the pod to run on master
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      # Allow this pod to be rescheduled while the node is in "critical add-ons only" mode.
      # This, along with the annotation above marks this pod as a critical add-on.
      - key: CriticalAddonsOnly
        operator: Exists
      serviceAccountName: calico-cni-plugin
      # Minimize downtime during a rolling upgrade or deletion; tell Kubernetes to do a "force
      # deletion": https://kubernetes.io/docs/concepts/workloads/pods/pod/#termination-of-pods.
      terminationGracePeriodSeconds: 0
      containers:
        # Runs calico/node container on each Kubernetes node.  This
        # container programs network policy and routes on each
        # host.
        - name: calico-node
          image: quay.io/calico/node:v2.6.8
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Enable BGP.  Disable to enforce policy only.
            - name: CALICO_NETWORKING_BACKEND
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: calico_backend
            # Cluster type to identify the deployment type
            - name: CLUSTER_TYPE
              value: "k8s,bgp"
            # Set noderef for node controller.
            - name: CALICO_K8S_NODE_REF
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            # Disable file logging so `kubectl logs` works.
            - name: CALICO_DISABLE_FILE_LOGGING
              value: "true"
            # Set Felix endpoint to host default action to ACCEPT.
            - name: FELIX_DEFAULTENDPOINTTOHOSTACTION
              value: "ACCEPT"
            # Configure the IP Pool from which Pod IPs will be chosen.
            - name: CALICO_IPV4POOL_CIDR
              value: "10.198.49.0/24"
            - name: CALICO_IPV4POOL_IPIP
              value: "Off"
            # Disable IPv6 on Kubernetes.
            - name: FELIX_IPV6SUPPORT
              value: "false"
            # Set MTU for tunnel device used if ipip is enabled
            - name: FELIX_IPINIPMTU
              value: "1440"
            # Set Felix logging to "info"
            - name: FELIX_LOGSEVERITYSCREEN
              value: "info"
            # Auto-detect the BGP IP address.
            - name: IP
              value: ""
            - name: FELIX_HEALTHENABLED
              value: "true"
          securityContext:
            privileged: true
          resources:
            requests:
              cpu: 250m
          livenessProbe:
            httpGet:
              path: /liveness
              port: 9099
            periodSeconds: 10
            initialDelaySeconds: 10
            failureThreshold: 6
          readinessProbe:
            httpGet:
              path: /readiness
              port: 9099
            periodSeconds: 10
          volumeMounts:
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
            - mountPath: /var/run/calico
              name: var-run-calico
              readOnly: false
        # This container installs the Calico CNI binaries
        # and CNI network config file on each node.
        - name: install-cni
          image: quay.io/calico/cni:v1.11.4
          command: ["/install-cni.sh"]
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # The CNI network config to install on each node.
            - name: CNI_NETWORK_CONFIG
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: cni_network_config
          volumeMounts:
            - mountPath: /host/opt/cni/bin
              name: cni-bin-dir
            - mountPath: /host/etc/cni/net.d
              name: cni-net-dir
      volumes:
        # Used by calico/node.
        - name: lib-modules
          hostPath:
            path: /lib/modules
        - name: var-run-calico
          hostPath:
            path: /var/run/calico
        # Used to install CNI.
        - name: cni-bin-dir
          hostPath:
            path: /opt/cni/bin
        - name: cni-net-dir
          hostPath:
            path: /etc/cni/net.d

---

# This manifest deploys the Calico Kubernetes controllers.
# See https://github.com/projectcalico/kube-controllers
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: calico-kube-controllers
  namespace: kube-system
  labels:
    k8s-app: calico-kube-controllers
spec:
  # The controllers can only have a single active instance.
  replicas: 1
  strategy:
    type: Recreate
  template:
    metadata:
      name: calico-kube-controllers
      namespace: kube-system
      labels:
        k8s-app: calico-kube-controllers
      annotations:
        # Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
        # reserves resources for critical add-on pods so that they can be rescheduled after
        # a failure.  This annotation works in tandem with the toleration below.
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      # The controllers must run in the host network namespace so that
      # it isn't governed by policy that would prevent it from working.
      hostNetwork: true
      tolerations:
      # this taint is set by all kubelets running `--cloud-provider=external`
      # so we should tolerate it to schedule the calico pods
      - key: node.cloudprovider.kubernetes.io/uninitialized
        value: "true"
        effect: NoSchedule
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      # Allow this pod to be rescheduled while the node is in "critical add-ons only" mode.
      # This, along with the annotation above marks this pod as a critical add-on.
      - key: CriticalAddonsOnly
        operator: Exists
      serviceAccountName: calico-kube-controllers
      containers:
        - name: calico-kube-controllers
          image: quay.io/calico/kube-controllers:v1.0.3
          env:
            # The location of the Calico etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # The location of the Kubernetes API.  Use the default Kubernetes
            # service for API access.
            - name: K8S_API
              value: "https://k8s.test.com.cn:6443"
            # Choose which controllers to run.
            - name: ENABLED_CONTROLLERS
              value: policy,profile,workloadendpoint,node
            # Since we're running in the host namespace and might not have KubeDNS
            # access, configure the container's /etc/hosts to resolve
            # kubernetes.default to the correct service clusterIP.
            - name: CONFIGURE_ETC_HOSTS
              value: "true"

---

# This deployment turns off the old "policy-controller". It should remain at 0 replicas, and then
# be removed entirely once the new kube-controllers deployment has been deployed above.
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: calico-policy-controller
  namespace: kube-system
  labels:
    k8s-app: calico-policy-controller
spec:
  # Turn this deployment off in favor of the kube-controllers deployment above.
  replicas: 0
  strategy:
    type: Recreate
  template:
    metadata:
      name: calico-policy-controller
      namespace: kube-system
      labels:
        k8s-app: calico-policy-controller
    spec:
      hostNetwork: true
      serviceAccountName: calico-kube-controllers
      containers:
        - name: calico-policy-controller
          image: quay.io/calico/kube-controllers:v1.0.3
          env:
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints

---

apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: calico-cni-plugin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-cni-plugin
subjects:
- kind: ServiceAccount
  name: calico-cni-plugin
  namespace: kube-system

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: calico-cni-plugin
rules:
  - apiGroups: [""]
    resources:
      - pods
      - nodes
    verbs:
      - get

---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-cni-plugin
  namespace: kube-system

---

apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: calico-kube-controllers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-kube-controllers
subjects:
- kind: ServiceAccount
  name: calico-kube-controllers
  namespace: kube-system

---

kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: calico-kube-controllers
rules:
  - apiGroups:
    - ""
    - extensions
    resources:
      - pods
      - namespaces
      - networkpolicies
      - nodes
    verbs:
      - watch
      - list

---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-kube-controllers
  namespace: kube-system
```

### 部署calico node

`kubectl apply -f calico.yaml`

**注意**：在运行上述命令之前，请确保将配置的ConfigMap配置为您的etcd集群的位置。

### 部署BGPPEER

```yaml
~]# cat gaea188-1.yaml
apiVersion: v1
kind: bgpPeer
metadata:
  peerIP: 10.1.255.1
  scope: node
  node: gaea188
spec:
  asNumber: 65201
~]# ETCD_ENDPOINTS=http://10.71.10.188:2379 ./calicoctl create -f calico/gaea188-1.yaml
~]# cat gaea207-1.yaml
apiVersion: v1
kind: bgpPeer
metadata:
  peerIP: 10.1.255.1
  scope: node
  node: gaea188
spec:
  asNumber: 65201

~]# cat ippool.yaml
apiVersion: v1
kind: ipPool
metadata:
  cidr: 10.198.49.0/24
spec:
  ipip:
    enabled: false
    mode: cross-subnet
  nat-outgoing: true
  disabled: false
```

**本文参考自https://rootsongjc.gitbooks.io/kubernetes-handbook/content/**

# kubeadm部署方式：

​	Kubernetes官方提供的快速安装和初始化Kubernetes集群的工具，目前的还处于孵化开发状态，伴随Kubernetes每个版本的发布都会同步更新。 目前的kubeadm是不能用于生产环境的，目前处于alaph。
参考文档：
	https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
	https://k8smeetup.github.io/docs/admin/kubeadm/ 
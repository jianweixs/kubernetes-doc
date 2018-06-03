Kubernetes原理
    etcd 保存了整个集群的状态；
    kube-apiserver提供了资源操作的唯一入口，并提供认证、授权、访问控制、API注册和发现等机制；

​	通过HTTP协议以方式发布Kubernetes API，为编排调度器的内部和外部端点提供restful API，CLI、Web GUI或其他工具向API服务器发出请求，服务器处理并验证请求，然后更新etcd中API对象的状态。



​    kube-controller-managere负责维护集群的状态，比如故障检测、自动扩展、滚动更新等；
    kube-scheduler负责资源的调度，安装预定的调度策略将pod调度到相应的机器上；

​	调度器基于对资源可用性评估来为每个pod选择运行的节点，然后跟踪资源利用率，以确保pod不会超过它分配限额。

​    kubelet负责维持容器的生命周期，同时也负责Volume(CVI)和网络（CNI）的管理；
    Container runtime 负责镜像管理以及pod和容器的真正运行（CRI)，默认的容器运行时为Docker；
    kube-proxy 负责为Service提供cluster内部服务发现和负载均衡；

## etcd服务

![timg](/Users/jianwei/Desktop/timg.jpeg)

​	etcd是由CoreOS团队发的一个分布式一致性的KV存储系统，可用于服务注册发现和共享配置，随着CoreOS和Kubernetes等项目在开源社区日益火热，它们项目中都用到的etcd组件作为一个高可用强一致性的服务发现存储仓库，渐渐为开发人员所关注。在云计算时代，如何让服务快速透明地接入到计算集群中，如何让共享配置信息快速被集群中的所有机器发现，更为重要的是，如何构建这样一套高可用、安全、易于部署以及响应快速的服务集群，已经成为了迫切需要解决的问题。etcd为解决这类问题带来了福音，本文将从etcd的应用场景开始，深入解读etcd的实现方式，以供开发者们更为充分地享用etcd所带来的便利。



## 特点：







## 使用场景

- 配置管理
- 服务注册于发现
- 选主
- 应用调度
- 分布式队列
- 分布式锁



## 原理：

​	etcd推荐使用奇数作为集群节点个数。因为奇数个节点和其配对的偶数个节点相比，容错能力相同，却可以少一个节点。综合考虑性能和容错能力，etcd官方文档推荐的etcd集群大小是3,5,7。由于etcd使用是Raft算法，每次写入数据需要有2N+1个节点同意可以写入数据，所以部分节点由于网络或者其他不可靠因素延迟收到数据更新，但是最终数据会保持一致，高度可靠。随着节点数目的增加，每次的写入延迟会相应的线性递增，除了节点数量会影响写入数据的延迟，如果节点跟接节点之间的网络延迟，也会导致数据的延迟写入。

结论：

​	1.节点数并非越多越好，过多的节点将会导致数据延迟写入。

​	2.节点跟节点之间的跨机房，专线之间网络延迟，也将会导致数据延迟写入。

​	3.受网络IO和磁盘IO的延迟

​	4.为了提高吞吐量，etcd通常将多个请求一次批量处理并提交Raft，

​	5.增加节点，读性能会提升，写性能会下降，减少节点，写性能会提升。

## 部署

### 单机节点（CentOS 7）

```shell
# yum install etcd -y 
修改配置文件，通过yum 安装的etcd，以下是etcd的配置文件：

~]# vim /etc/etcd/etcd.conf 
#[Member]
#ETC D_CORS=""
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
#ETCD_WAL_DIR=""
#ETCD_LISTEN_PEER_URLS="http://localhost:2380"
ETCD_LISTEN_CLIENT_URLS="http://192.168.1.109:2379"
#ETCD_MAX_SNAPSHOTS="5"
#ETCD_MAX_WALS="5"
ETCD_NAME="default"
#ETCD_SNAPSHOT_COUNT="100000"
#ETCD_HEARTBEAT_INTERVAL="100"
#ETCD_ELECTION_TIMEOUT="1000"
#ETCD_QUOTA_BACKEND_BYTES="0"
#ETCD_MAX_REQUEST_BYTES="1572864"
#ETCD_GRPC_KEEPALIVE_MIN_TIME="5s"
#ETCD_GRPC_KEEPALIVE_INTERVAL="2h0m0s"
#ETCD_GRPC_KEEPALIVE_TIMEOUT="20s"
#
#[Clustering]
#ETCD_INITIAL_ADVERTISE_PEER_URLS="http://localhost:2380"
ETCD_ADVERTISE_CLIENT_URLS="http://192.168.1.109:2379"
#ETCD_DISCOVERY=""
#ETCD_DISCOVERY_FALLBACK="proxy"
#ETCD_DISCOVERY_PROXY=""
#ETCD_DISCOVERY_SRV=""
#ETCD_INITIAL_CLUSTER="default=http://localhost:2380"
#ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
#ETCD_INITIAL_CLUSTER_STATE="new"
#ETCD_STRICT_RECONFIG_CHECK="true"
#ETCD_ENABLE_V2="true"
#
#[Proxy]
#ETCD_PROXY="off"
#ETCD_PROXY_FAILURE_WAIT="5000"
#ETCD_PROXY_REFRESH_INTERVAL="30000"
#ETCD_PROXY_DIAL_TIMEOUT="1000"
#ETCD_PROXY_WRITE_TIMEOUT="5000"
#ETCD_PROXY_READ_TIMEOUT="0"
#
#[Security]
#ETCD_CERT_FILE=""
#ETCD_KEY_FILE=""
#ETCD_CLIENT_CERT_AUTH="false"
#ETCD_TRUSTED_CA_FILE=""
#ETCD_AUTO_TLS="false"
#ETCD_PEER_CERT_FILE=""
#ETCD_PEER_KEY_FILE=""
#ETCD_PEER_CLIENT_CERT_AUTH="false"
#ETCD_PEER_TRUSTED_CA_FILE=""
#ETCD_PEER_AUTO_TLS="false"
#
#[Logging]
#ETCD_DEBUG="false"
#ETCD_LOG_PACKAGE_LEVELS=""
#ETCD_LOG_OUTPUT="default"
#
#[Unsafe]
#ETCD_FORCE_NEW_CLUSTER="false"
#
#[Version]
#ETCD_VERSION="false"
#ETCD_AUTO_COMPACTION_RETENTION="0"
#
#[Profiling]
#ETCD_ENABLE_PPROF="false"
#ETCD_METRICS="basic"
#
#[Auth]
#ETCD_AUTH_TOKEN="simple"
```

参数说明： 

- –data-dir：指定节点的数据存储目录，若不指定，则默认是当前目录。这些数据包括节点ID，集群ID，集群初始化配置，Snapshot文件，若未指 定–wal-dir，还会存储WAL文件 

- –wal-dir：指定节点的was文件存储目录，若指定了该参数，wal文件会和其他数据文件分开存储 

- –name：节点名称 

- –initial-advertise-peer-urls：告知集群其他节点的URL，tcp2380端口用于集群通信 

- –listen-peer-urls：监听URL，用于与其他节点通讯 

- –advertise-client-urls：告知客户端的URL, 也就是服务的URL，tcp2379端口用于监听客户端请求 

- –initial-cluster-token：集群的ID 

- –initial-cluster：集群中所有节点 

- –initial-cluster-state：集群状态，new为新创建集群，existing为已存在的集群

- etcd 默认存储大小限制是 2GB, 可以通过 `--quota-backend-bytes` 标记配置，最大支持 8GB. 

#### 启动etcd服务

```shell
$ systemctl start etcd.service
$ systemctl status etcd.service
● etcd.service - Etcd Server
   Loaded: loaded (/usr/lib/systemd/system/etcd.service; disabled; vendor preset: disabled)
   Active: active (running) since 六 2018-06-02 22:17:34 CST; 9s ago
 Main PID: 2876 (etcd)
   CGroup: /system.slice/etcd.service
           └─2876 /usr/bin/etcd --name=default --data-dir=/var/lib/etcd/default.etcd --listen-client-urls=http://192.168.1.109:2379
```

### 多节点部署

#### 自定义的 etcd discovery 服务

这种方式就是**利用一个已有的 etcd 集群来提供 discovery 服务，从而搭建一个新的 etcd 集群。**

假设已有的 `etcd` 集群的一个访问地址是：`myetcd.local`，那么我们首先需要在已有 `etcd` 中创建一个特殊的 key，方法如下：

```
$ curl -X PUT https://myetcd.local/v2/keys/discovery/6c007a14875d53d9bf0ef5a6fc0257c817f0fb83/_config/size -d value=3
```

其中 `value=3` 表示本集群的大小，即: 有多少集群节点。而 `6c007a14875d53d9bf0ef5a6fc0257c817f0fb83` 就是用来做 discovery 的 token。

接下来你在 3 个节点上分别启动 `etcd` 程序，并加上刚刚的 token。
加 token 的方式同样也有 **命令行参数** 和 **环境变量** 两种。

**命令行参数:**

```shell
-discovery https://myetcd.local/v2/keys/discovery/6c007a14875d53d9bf0ef5a6fc0257c817f0fb83
```

**环境变量**

```shell
ETCD_DISCOVERY=https://myetcd.local/v2/keys/discovery/6c007a14875d53d9bf0ef5a6fc0257c817f0fb83
```

以**命令行参数**启动方式为例：

```shell
$ etcd -name etcd0 -initial-advertise-peer-urls http://10.0.1.10:2380 \
  -listen-peer-urls http://10.0.1.10:2380 \
  -listen-client-urls http://10.0.1.10:2379,http://127.0.0.1:2379 \
  -advertise-client-urls http://10.0.1.10:2379 \
  -discovery https://myetcd.local/v2/keys/discovery/6c007a14875d53d9bf0ef5a6fc0257c817f0fb83
$ etcd -name etcd1 -initial-advertise-peer-urls http://10.0.1.11:2380 \
  -listen-peer-urls http://10.0.1.11:2380 \
  -listen-client-urls http://10.0.1.11:2379,http://127.0.0.1:2379 \
  -advertise-client-urls http://10.0.1.11:2379 \
  -discovery https://myetcd.local/v2/keys/discovery/6c007a14875d53d9bf0ef5a6fc0257c817f0fb83
$ etcd -name etcd2 -initial-advertise-peer-urls http://10.0.1.12:2380 \
  -listen-peer-urls http://10.0.1.12:2380 \
  -listen-client-urls http://10.0.1.12:2379,http://127.0.0.1:2379 \
  -advertise-client-urls http://10.0.1.12:2379 \
  -discovery https://myetcd.local/v2/keys/discovery/6c007a14875d53d9bf0ef5a6fc0257c817f0fb83
```

## 测试

可以使用etcd附带的[基准](https://github.com/coreos/etcd/tree/master/tools/benchmark) CLI工具完成基准测试etcd性能。

对于一些基准性能数字，我们考虑具有以下硬件配置的三个成员的etcd集群：

- Google云计算引擎
- 3台8个vCPU + 16GB内存+ 50GB固态硬盘
- 1台机器（客户端），16个vCPU + 30GB内存+ 50GB SSD
- Ubuntu 17.04
- etcd 3.2.0，去1.8.3

有了这个配置，etcd可以大致写出：

| 密钥数量 | 密钥大小（字节） | 值大小以字节为单位 | 连接数 | 客户数量 | 目标ETCD服务器 | 平均写入QPS | 每个请求的平均延迟 | 平均服务器RSS |
| -------- | ---------------- | ------------------ | ------ | -------- | -------------- | ----------- | ------------------ | ------------- |
| 万       | 8                | 256                | 1      | 1        | 只有领导者     | 583         | 1.6毫秒            | 48 MB         |
| 100000   | 8                | 256                | 100    | 1000     | 只有领导者     | 44341       | 22毫秒             | 124MB         |
| 100000   | 8                | 256                | 100    | 1000     | 所有成员       | 50104       | 20ms的             | 126MB         |

示例命令是：

```shell
# write to leader
benchmark --endpoints=${HOST_1} --target-leader --conns=1 --clients=1 \
    put --key-size=8 --sequential-keys --total=10000 --val-size=256
benchmark --endpoints=${HOST_1} --target-leader  --conns=100 --clients=1000 \
    put --key-size=8 --sequential-keys --total=100000 --val-size=256

# write to all members
benchmark --endpoints=${HOST_1},${HOST_2},${HOST_3} --conns=100 --clients=1000 \
    put --key-size=8 --sequential-keys --total=100000 --val-size=256
```

可线性读取请求通过集群成员的法定人数达成一致以获取最新数据。可序列化的读取请求比线性读取要便宜，因为它们由任何单个etcd成员提供，而不是成员法定人数，以换取可能的陈旧数据。etcd可以阅读：

| 请求数 | 密钥大小（字节） | 值大小以字节为单位 | 连接数 | 客户数量 | 一致性 | 平均读取QPS | 每个请求的平均延迟 |
| ------ | ---------------- | ------------------ | ------ | -------- | ------ | ----------- | ------------------ |
| 万     | 8                | 256                | 1      | 1        | 线性化 | 1,353       | 为0.7ms            |
| 万     | 8                | 256                | 1      | 1        | 序列化 | 2909        | 0.3ms的            |
| 100000 | 8                | 256                | 100    | 1000     | 线性化 | 141578      | 5.5ms              |
| 100000 | 8                | 256                | 100    | 1000     | 序列化 | 185758      | 时间为2.2ms        |

示例命令是：

```shell
# Single connection read requests
benchmark --endpoints=${HOST_1},${HOST_2},${HOST_3} --conns=1 --clients=1 \
    range YOUR_KEY --consistency=l --total=10000
benchmark --endpoints=${HOST_1},${HOST_2},${HOST_3} --conns=1 --clients=1 \
    range YOUR_KEY --consistency=s --total=10000

# Many concurrent read requests
benchmark --endpoints=${HOST_1},${HOST_2},${HOST_3} --conns=100 --clients=1000 \
    range YOUR_KEY --consistency=l --total=100000
benchmark --endpoints=${HOST_1},${HOST_2},${HOST_3} --conns=100 --clients=1000 \
    range YOUR_KEY --consistency=s --total=100000
```

我们鼓励在新环境中首次安装etcd集群时运行基准测试，以确保集群达到足够的性能; 群集延迟和吞吐量可能会对较小的环境差异敏感。

**以上部分测试部分复制自官方文档（https://coreos.com/etcd/docs/latest/op-guide/performance.html）**

- 关于对Raft算法原理参考链接：

		- InfoQ：Raft 一致性算法论文译文

		 http://www.infoq.com/cn/articles/raft-paper 

		知乎：raft算法与paxos算法相比有什么优势，使用场景有什么差异？

		 https://www.zhihu.com/question/36648084

		Raft算法动画：经典的Raft算法动画演示链接

		 http://thesecretlivesofdata.com/raft/
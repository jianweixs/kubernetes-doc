# 一、docker的三大核心概念
![image.png](https://upload-images.jianshu.io/upload_images/1709776-a15a980f33ccd4ac.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

### 镜像（Image）
> Docker镜像类似于虚拟机镜像，可以将它理解为一个只读的模板。
### 容器（Container）
> 类似与一个轻量级的沙箱，docker利用容器来运行和隔离应用。简易版的linux环境（包括root用户权限、进程空间、用户空间和网络空间）以及运行在其中的应用程序打包而成的盒子。
### 仓库（Repository）
> docker集中存放镜像的场所，通过不同的标签（tag）来区分。

# 二、安装docker
CentOS 7下安装Docker，Docker CE支持64位CentOS7，并且要求内核版本比低于3.10.
#### 1.卸载旧的版本：
`# yum remove docker docker-common docker-selinux docker`
#### 2. 使用yum安装：
`# yum install -y yum-utils  device-mapper-persisten-data lvm`
#### 3.安装最新版Docker CE：
`# yum-config-manager --enable docker-ce-edge`
`# yum install docker-ce`
#### 4.启动Docker CE
`# systemctl enable docker`
`# systemctl start docker`
#### 5.测试Docker 是否安装正确
`# docker run hello-word`
# 三、获取镜像
### 1. 从docker 镜像仓库获取镜像
`# Usage: docker pull [OPTIONS] [Docker Registry NAME[:TAG]`
> 命令帮助: docker pull --help
>镜像名称格式：
> Docker镜像仓库地址：地址的格式一般是 <域名/IP>[:端口号]。默认地址是Docker Hub
> 仓库名称：两段式名称，即<用户名>/<软件名>。如果不给出默认为library，也就是官方镜像。
###### Example:
`[root@localhost ~]# docker pull mysql`
`Using default tag: latest`
`Trying to pull repository docker.io/library/mysql ...`
### 2.运行容器
>    docker run -it 
>        -i：交互式操作
>        -t：终端，

### 3.常见的镜像命令操作
    列出镜像：
        # docker image ls
        # docker images 
    列出悬挂镜像：
        docker image ls -f dangling=true 
    删除悬挂镜像：
        docker image prune
    中间层镜像：
    删除本地镜像：
        # docker image rm [选项] <IMAGE1> <IMAGE2>
    使用tag命令为镜像添加标签：
        # docker tag nginx:latest mynginx:latest
    查看镜像详细信息：
        # docker inspect nginx:latest
    查看镜像历史：
        # docker history nginx
        IMAGE               CREATED             CREATED BY                                      SIZE                COMMENT
        ae513a47849c        5 days ago          /bin/sh -c #(nop)  CMD ["nginx" "-g" "daem...   0 B
        <missing>           5 days ago          /bin/sh -c #(nop)  STOPSIGNAL [SIGTERM]         0 B
        <missing>           5 days ago          /bin/sh -c #(nop)  EXPOSE 80/tcp                0 B
        <missing>           5 days ago          /bin/sh -c ln -sf /dev/stdout /var/log/ngi...   0 B
        <missing>           5 days ago          /bin/sh -c set -x  && apt-get update  && a...   53.7 MB
        <missing>           5 days ago          /bin/sh -c #(nop)  ENV NJS_VERSION=1.13.12...   0 B
        <missing>           5 days ago          /bin/sh -c #(nop)  ENV NGINX_VERSION=1.13....   0 B
        <missing>           5 days ago          /bin/sh -c #(nop)  LABEL maintainer=NGINX ...   0 B
        <missing>           7 days ago          /bin/sh -c #(nop)  CMD ["bash"]                 0 B
        <missing>           7 days ago          /bin/sh -c #(nop) ADD file:ec5be7eec56a749...   55.3 MB

    删除镜像：
        # docker rmi IMAGE [IMAGE...]
        eg: docker rmi nginx:latest
    创建镜像：
        # docker commit [OPTIONS] CONTAINER [REPOSITORY:[TAG]]
        -a, --author string    Author (e.g., "John Hannibal Smith <hannibal@a-team.com>")
        -c, --change list      Apply Dockerfile instruction to the created image (default [])
        --help             Print usage
        -m, --message string   Commit message
        -p, --pause            Pause container during commit (default true)
    基于本地模板导入：
        # docker import [OPTIONS] file|[URL]|- [REPOSITORY[:TAG]]
        eg: cat nginx:latest.tar.gz | docker import - nginx:v1
    存储镜像：
        eg:
            docker save -o nginx:v2.tar nginx:latest
            docker load --input nginx:v2.tar
            docker load < nginx:v2.tar
    上传镜像：
        docker push NAME[:TAG] | [RE]
### 4.删除镜像的特殊用法
###### (1) 删除所有仓库名为redis的镜像：
    # docker image rm $(docker iamge ls -q redis)
###### (2) 删除所有在mongo:3.2之前的镜像：
    # docker image rm $(docker image ls -q -f before=mongo:3.2)

# 四、遇到的问题
### 1.docker启动报错
`overlay: the backing xfs filesystem is formatted without d_type suppor`
###### 解决方法: 修改docker-storage为devicemapper
`vim /etc/sysconfig/docker-storage`
`DOCKER_STORAGE_OPTIONS="--storage-driver devicemapper"`  
### 2.pull 镜像的时候遇到以下报错
`Get https://registry-1.docker.io/v2/library/python/manifests/2.7http: TLS handshake timeout` 
###### 解决方法：设置docker镜像加速器
    Configure the Docker daemon
    Either pass the --registry-mirror option when starting dockerd manually, or edit /etc/docker/daemon.json and add the registry-mirrors key and value, to make the change persistent.
    {
    "registry-mirrors": ["https://<my-docker-mirror-host>"]
    }
    https://docs.docker.com/registry/recipes/mirror/#what-if-the-content-changes-on-the-hub

使用Dockerfile定制镜像
    Dockerfile是一个文本文件，其内包含了一条条的执行(Instruction),每一条指令构建一层。

    FROM 指定基础镜像
    RUN 执行命令行命令
#################################
docker启动容器操作流程：
    执行docker run来创建并启动容器的时候，Docker在后台运行的标准流程：
    1.检查本地是否存在指定的镜像，不存在就在共有库中下载；
    2.利用镜像创建一个容器，并启动该容器；
    3.分配一个文件系统给容器，并在只读的镜像层外面挂载一层可读可写层；
    4.从宿主主机配置的网桥接口中桥接一个虚拟接口到容器中；
    5.从网桥的地址池配置一个IP地址给容器；
    6.执行用户指定的应用程序；
    7.执行完毕后容器自动终止。

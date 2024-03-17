# BlockCDP
一个基于 Linux 内核的块设备 CDP (Continual Data Protection) 开源项目。

## 设计概要
[设计概要](https://github.com/OpenCDP/OpenCDP)

## 使用方法
宿主机：Windows11  
虚拟机版本：VMWare Workstation Player 15.5.7  
虚拟机Linux：Ubuntu 18.04.6  
虚拟机Linux内核：Linux 4.15.0-213-generic #224-Ubuntu SMP x86_64  
虚拟机CDP测试磁盘：/dev/sdb（磁盘不能太小，要100MB以上，否则放不下文件系统）  
```bash
#clone代码编译，编译之前需要先安装好开发环境
#编译成功后，会看到目录下面有cdp.ko内核模块文件
#如果需要修改CDP磁盘，则自行修改cdp.c代码重新编译
cd /opt
git clone https://github.com/OpenCDP/BlockCDP.git
cd BlockCDP/
make

#格式化磁盘(可以选择其他文件系统，也可以选择直接清零磁盘)
mkfs.ext4 /dev/sdb

#使用dd命令，先对磁盘做一个基础镜像，用于后续恢复数据用
dd if=/dev/sdb of=/opt/BlockCDP/base.img

#加载cdp模块
insmod cdp.ko

#查看syslog日志
tail -f /var/log/syslog

#查看是否有/dev/cdp设备
lsblk

#挂载cdp磁盘到mnt目录，测试使用情况
mount /dev/cdp /mnt

#挂载成功后，进入mnt目录进行一些数据的读写，文件创建删除等操作
#在syslog日志会看到模块的工作情况，当增量数据大于10MB则会生成一个元数据和数据文件
#如 metafile.2024-03-17-10-56-27 datafile.2024-03-17-10-56-27

#测试数据恢复，代码附带了两个合并增量数据的py文件 merge.py merge-core.py
#直接执行merger.py会显示当前可以合并数据的命令
python merge.py
#返回
['metafile.2024-03-17-10-56-27', 'metafile.2024-03-17-10-59-35']
python merge-core.py metafile.2024-03-17-10-56-27 metafile.2024-03-17-10-56-27 '' '' test
python merge-core.py metafile.2024-03-17-10-59-35 metafile.2024-03-17-10-59-35 '' '' test

#可以看到目前有2份数据可以合并的，有对应的时间节点
#合并数据必须从最开始的数据开始，否则合并出来的数据会错乱
#比如我们看看合并最开始那份数据 2024-03-17-10-56-27
#执行
python merge-core.py metafile.2024-03-17-10-56-27 metafile.2024-03-17-10-56-27 '' '' test
#这里我们输入的是test，只是看看具体数据列表情况，不会真正执行合并
#把test改成run，那么脚本就会把数据写入到base.img基础镜像
#合并完成之后，我们可以用这个base.img镜像去导入磁盘从而恢复数据
#如我们把数据倒回去/dev/sdb，这里也可以用新的磁盘
dd if=/opt/BlockCDP/base.img of=/dev/sdb status=progress

#卸载模块前，先执行刷屏命令，让缓存数据罗盘
sync
#退出所有/mnt目录，然后卸载模块
rmmod cdp

#跳过cdp模块，直接挂载sdb磁盘查看数据
mount /dev/sdb /mnt

```

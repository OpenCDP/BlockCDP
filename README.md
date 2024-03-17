#### English | [简体中文](README_CN.md)
# BlockCDP
BlockCDP is an open-source project for Continuous Data Protection (CDP), which based on the Linux kernel.

## Design & Arch
[Design & Arch](https://github.com/OpenCDP/OpenCDP)

## Usage
Host：Windows11  
VirtualTools：VMWare Workstation Player 15.5.7  
Guest Linux：Ubuntu 18.04.6  
Guest Linux kernel：Linux 4.15.0-213-generic #224-Ubuntu SMP x86_64  
Guest CDP BlockDevice：/dev/sdb（size > 100MB, enough for filesystem）  

```bash
cd /opt
git clone https://github.com/OpenCDP/BlockCDP.git
cd BlockCDP/
make

mkfs.ext4 /dev/sdb

dd if=/dev/sdb of=/opt/BlockCDP/base.img

insmod cdp.ko

tail -f /var/log/syslog

#check /dev/cdp device
lsblk

mount /dev/cdp /mnt

cd /mnt
#do some test 
#create file and write data ...
#in /dev/shm dir you will see some metafile and datafile
# metafile.2024-03-17-10-56-27 datafile.2024-03-17-10-56-27

#check current data which can merge to base.img
python merge.py
#return
['metafile.2024-03-17-10-56-27', 'metafile.2024-03-17-10-59-35']
python merge-core.py metafile.2024-03-17-10-56-27 metafile.2024-03-17-10-56-27 '' '' test
python merge-core.py metafile.2024-03-17-10-59-35 metafile.2024-03-17-10-59-35 '' '' test

#you can merge data one by one
#merge order (old >> new ) time0 time1 time2 ...
#we merge one like this,use test for dryrun, will not truly merge
python merge-core.py metafile.2024-03-17-10-56-27 metafile.2024-03-17-10-56-27 '' '' test
#you can do merge like this, test > run
python merge-core.py metafile.2024-03-17-10-56-27 metafile.2024-03-17-10-56-27 '' '' run

#export data to disk when merge finish
dd if=/opt/BlockCDP/base.img of=/dev/sdb status=progress

#rmmod cdp module, sync data befroe
sync
rmmod cdp

#mount /dev/sdb to check data
mount /dev/sdb /mnt

```

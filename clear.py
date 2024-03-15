import os
import sys

file_path = '/dev/shm'

# 获取当前目录下的所有文件
files = os.listdir(file_path)

# 创建一个字典，用于存储文件名和对应的时间戳
timestamp_dict = {}

# 遍历文件列表，提取文件名中的时间戳并保存到字典中
for file in files:
    if file.startswith("datafile.") or file.startswith("metafile."):
        timestamp = file.split(".")[1]
        timestamp_dict[file] = timestamp

if len(timestamp_dict) <= 2:
    sys.exit(0)
# 根据时间戳对字典进行排序，获取最新的datafile和metafile文件名
latest_datafile = max(timestamp_dict, key=lambda x: timestamp_dict[x] if x.startswith("datafile.") else "")
latest_metafile = max(timestamp_dict, key=lambda x: timestamp_dict[x] if x.startswith("metafile.") else "")

# 删除除最新的datafile和metafile文件之外的其他文件
for file in files:
    if file != latest_datafile and file != latest_metafile:
        os.remove(file_path+'/'+file)


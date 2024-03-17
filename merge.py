# -*- coding: utf-8 -*-
import os
import sys

file_path = '/dev/shm'
file_list = []

files = os.listdir(file_path)
for file_name in files:
    if file_name.startswith('metafile.'):
        file_list.append(file_name)

file_list = sorted(file_list)
print file_list
if len(file_list) <= 0:
    sys.exit(0)

for metafile_name in file_list:
    datafile_name = metafile_name.replace('meta', 'data')
    print "python merge-core.py %s %s '' '' test"%(metafile_name, metafile_name)


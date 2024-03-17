# -*- coding: utf-8 -*-
from datetime import datetime
import time
import sys
import os

metafile_timestamp_list = {}

# 定义要读取的文本文件路径
cdpfile_path = "/dev/shm"
targetfile_path = "/opt/BlockCDP/base.img"

def get_timestamp(ts):
    date_format = "%Y-%m-%d-%H-%M-%S"
    datetime_obj = datetime.strptime(ts, date_format)
    return int(time.mktime(datetime_obj.timetuple()))

def get_metafile_name_timestamp(filename):
    #metafile.2023-12-12-10-39-59
    return get_timestamp(filename[9:])

def read_datefile_data(fd, offset, size):
    #print("%d %d"%(offset, size))
    fd.seek(offset)
    data = fd.read(size)
    return data

def write_data_to_img(fd, offset, size, data):
    fd.seek(offset)
    return fd.write(data)

def get_metafile_timestamp_list(metafile_start, metafile_end, \
                        time_start, time_end):

    global metafile_timestamp_list
    global cdpfile_path

    files = os.listdir(cdpfile_path)
    metafiles = [file for file in files if file.startswith("metafile")]
    #metafiles = sorted(metafiles)
    for metafile in metafiles:
        if metafile_start != '' and metafile_end != '':
            if get_metafile_name_timestamp(metafile) < get_metafile_name_timestamp(metafile_start):
                continue
            if get_metafile_name_timestamp(metafile) > get_metafile_name_timestamp(metafile_end):
                continue

        metafile_fd = open(cdpfile_path+'/'+metafile, 'r')
        metafile_timestamp_list[metafile] = []
        for line in metafile_fd:
            line = line.strip()
            if len(line) == 0:
                continue
            ts = line[0:19]
            kv = line[20:]
            kv = kv.replace('[', '')
            kv = kv.split(']')
            data_offset = int(kv[2])
            data_size = int(kv[1])
            sector_num = int(kv[0])
            its = get_timestamp(ts)

            if time_start != '' and time_end != '':
                if its < get_timestamp(time_start):
                    continue
                if its > get_timestamp(time_end):
                    continue

            metafile_timestamp_list[metafile].append({ \
                                        'ts':ts, \
                                        'ist':its, \
                                        'offset':data_offset, \
                                        'size':data_size, \
                                        'sector':sector_num, \
                                        })
            #print metafile_ts_list[metafile][-1]

        metafile_fd.close()

    return len(metafile_timestamp_list)


if __name__ == '__main__':

    dry_run = True

    print sys.argv
    if len(sys.argv) != 6:
        print('merge-core.py [metafile_start] [metafile_end] [time_start] [time_end] [test|run]')
        sys.exit(0)

    metafile_start = sys.argv[1]
    metafile_end = sys.argv[2]
    time_start = sys.argv[3]
    time_end = sys.argv[4]
    dry_run = (sys.argv[5] != 'run')

    '''
    if metafile_start.startswith('metafile.'):
        print get_metafile_name_timestamp(metafile_start)

    if metafile_end.startswith('metafile.'):
        print get_metafile_name_timestamp(metafile_end)

    if time_start != 0:
        print get_timestamp(time_start)

    if time_end != 0:
        print get_timestamp(time_end)
    '''

    get_metafile_timestamp_list(metafile_start, metafile_end, \
                                time_start, time_end)
    #这里需要重新排序，确保按时间先后循序
    metafiles = metafile_timestamp_list.keys()
    metafiles = sorted(metafiles)

    if dry_run:
        for metafile in metafiles:
            timestamp_list = metafile_timestamp_list[metafile]
            datafile = metafile.replace('meta', 'data')
            print metafile, datafile
            for kv in timestamp_list:
                print "\t", kv

        sys.exit(0)


    targetfile_fd = open(targetfile_path, 'rb+')

    for metafile in metafiles:
        timestamp_list = metafile_timestamp_list[metafile]
        datafile = metafile.replace('meta', 'data')
        print metafile, datafile
        datafile_fd = open(cdpfile_path+'/'+datafile, 'rb')
        for kv in timestamp_list:
            #{'size': 4096, 'sector': 1050712, 'offset': 1921024, 'ts': '2023-12-12-10-38-50', 'ist': 1702377530}
            data = read_datefile_data(datafile_fd, kv['offset'], kv['size'])
            if len(data) > 0:
                ret = write_data_to_img(targetfile_fd, kv['sector']*512, kv['size'], data)
                print ret

        datafile_fd.close()

    targetfile_fd.close()


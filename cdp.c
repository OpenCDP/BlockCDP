/*
 * indent -kr -i4 test.c
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/rtc.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#define CDP_MAJOR			240
#define CDP_MINOR			0
#define CDP_NAME			"cdp"

#define TARGET_DISK_PATH	"/dev/sdb"      //host-disk
#define FILE_PATH		    "/dev/shm"      //bio数据、元数据存放目录
#define META_FILE_NAME      "metafile"      //元数据文件命名
#define DATA_FILE_NAME      "datafile"      //bio数据文件命名
#define MAX_DATA_FILE_SIZE  (1024*1024*10)  //单个bio数据文件最大容量10MB

#define META_BUFFER_SIZE	(512)           //元数据写入文件的缓冲区公用大小512字节

#define BUFFER_COUNT_LINE	(16)            //打印16进制数组显示多少字节一行

#define WRITE_BIO_COUNT_LOOP    (100)       //bio工作线程每次循环处理多少个bio数据写入

static struct gendisk *cdp_disk;
static struct request_queue *cdp_queue;
static struct block_device *target_disk;
struct bio_set *cdp_bio_set;                //启用bio fast clone用到的内存池，暂时没用上
static struct file *meta_file;              //元数据文件句柄
static struct file *data_file;              //bio数据文件句柄
static char *meta_buffer;                   //元数据写入文件的缓冲区公用

mempool_t *page_pool = NULL;                //cdp bio 的页面内存池

//bio工作线程
static struct task_struct *bio_work_thread;
//bio任务元素
struct bio_ctx_t {
    struct rtc_time tm;     //bio请求时间
    //这里直接使用bio作为cdp的记录，因为需要使用内存页面记录
    //落盘的数据，不再自己构造太多字段，直接复用bio结构作为记录
    //包括写入的扇区号、写入的数据大小等等
    struct bio* cdp_bio;    
};
//bio队列，记录需要写入bio数据文件的bio相关记录
struct bio_list_t {
    struct list_head list;
    struct bio_ctx_t *ctx;
};

//引入内存池分配
struct kmem_cache *bio_ctx_cache;
struct kmem_cache *bio_list_cache;
mempool_t *bio_ctx_mempool;
mempool_t *bio_list_mempool;

//submit提交队列，用于记录vfs层提交的bio请求
static LIST_HEAD(bio_submit_list);
//write执行队列，bio工作线程负责从这个队列取出bio数据写入bio数据文件
static LIST_HEAD(bio_write_list);
static unsigned int bio_submit_list_count = 0;  //当前submit队列有多少个bio请求
static unsigned int bio_write_list_count = 0;   //当前write队列有多少个bio请求

//spinlock_t cdp_device_lock;                     //设备锁(暂时用不上)
spinlock_t bio_list_lock;                       //bio队列锁主要是保护submit队列

/*
static void print_bio_buff(unsigned char *data, int size)
{
    int i;
    int count = 0;
    char line[BUFFER_COUNT_LINE * 3 + 1];

    for (i = 0; i < size; i++) {
	if (count == BUFFER_COUNT_LINE) {
	    printk(KERN_INFO "%s\n", line);
	    count = 0;
	}
	snprintf(line + count * 3, 4, "%02x ", data[i]);
	count++;
    }
    if (count > 0) {
	printk(KERN_INFO "%s\n", line);
    }
}
*/

/* 生成当前时间戳 */
static int gen_current_time_str(char *buff)
{
    struct rtc_time tm;

    rtc_time_to_tm(get_seconds() + 8 * 60 * 60, &tm);
    return sprintf(buff, "%u-%02u-%02u-%02u-%02u-%02u",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
}

struct page *bio_page_alloc(int gfp_mask, void *pool_data)
{
	return alloc_page(gfp_mask);
}

void bio_page_free(void *element, void *pool_data)
{
	__free_page(element);
}

/* 释放 cdp bio 实例及里面的的page页面，因为page页面是我们自己手动分配的，所以需要手动释放 */
static void cdp_bio_free(struct bio *bio)
{
    int i;
    for( i = 0; i < bio->bi_vcnt; i++ ) {
        if( bio->bi_io_vec[i].bv_page ) {
            mempool_free(bio->bi_io_vec[i].bv_page, page_pool);
            bio->bi_io_vec[i].bv_page = NULL;
        }
    }
    bio_put(bio);
}

/* 创建 cdp_bio 数据结构，其实里面主要就是 bio 字段 */
static struct bio* cdp_bio_alloc(struct bio *bio)
{
    struct bio *cdp_bio;
    struct bio_vec bvec;
    struct bvec_iter iter;
    struct page *pg;
    //unsigned int i;
    //unsigned int total_size = 0;

    //创建bio结构(默认会用系统内部的 fs_bio_set 分配bio)
    cdp_bio = bio_alloc(GFP_NOIO, bio->bi_vcnt);
    if( ! cdp_bio ) {
        printk(KERN_ERR "cdp_bio_build alloc fail\n");
        return NULL;
    }

    cdp_bio->bi_iter.bi_sector = bio->bi_iter.bi_sector;
    //不需要设定 cdp_bio 写入大小的值，因为下面add_page之后这些值都会一样的了
    //如果这里预先设定了，add_page之后，这个bi_size就翻倍了，vcnt也一样不用搞
   	//cdp_bio->bi_iter.bi_size = bio->bi_iter.bi_size;
    /*
    for( i = 0; i < bio->bi_vcnt; i++ ) {
        //把页面page预先置空
        cdp_bio->bi_io_vec[i].bv_page = NULL;
    }
    */

    //根据 vfs 提交的bio请求，1:1 地复制一份bio请求，主要是page页面
    bio_for_each_segment(bvec, bio, iter) {
        unsigned char *data = page_address(bvec.bv_page);
        unsigned int offset = bvec.bv_offset;
        unsigned int length = bvec.bv_len;

        //vfs bio有多少个页面就创建多少个，然后复制数据
        //这里是不是也需要改成GFP_NOIO方式分配page才行？
        pg = mempool_alloc(page_pool, GFP_NOIO);
        if( ! pg ) {
            printk(KERN_ERR "cdp_bio_alloc mempool_alloc fail");
            goto bio_fail;
        }
        //暂时不复制
        //把bio写入的数据复制一份到bio请求缓冲区，后续用来写入bio数据文件
        memcpy(page_address(pg), data + offset, length);
        bio_add_page(cdp_bio, pg, length, 0);
        //total_size += length;
        //printk(KERN_INFO "bio_add_page %p %d [%d]\n", data, length, total_size);
    }
    //设置完add_page之后，cdp_bio 和 bio 下面这些字段就一致了
    //printk(KERN_INFO "bio_alloc_1 %d %d\n", bio->bi_vcnt, cdp_bio->bi_vcnt);
    //printk(KERN_INFO "bio_alloc_2 %ld %d\n", bio->bi_iter.bi_sector, bio->bi_iter.bi_size);
    //printk(KERN_INFO "bio_alloc_1 %d %d\n", cdp_bio->bi_vcnt, cdp_bio->bi_vcnt);
    //printk(KERN_INFO "bio_alloc_2 %ld %d\n", cdp_bio->bi_iter.bi_sector, cdp_bio->bi_iter.bi_size);

    return cdp_bio;

bio_fail:
    cdp_bio_free(cdp_bio);
    return NULL;
}

/* 生成一个write队列的bio请求记录 */
static struct bio_ctx_t* new_bio_ctx(struct bio *bio)
{
    struct bio_ctx_t *ctx;
    struct bio *cdp_bio;

    //ctx = kmalloc(sizeof(struct bio_ctx_t), GFP_KERNEL);
    ctx = mempool_alloc(bio_ctx_mempool, GFP_NOIO);
    if( ! ctx ) {
        printk(KERN_ERR "kmalloc bio_ctx_t fail");
        return NULL;
    }
    //记录bio请求时间、写入host盘开始扇区号、写入数据长度
    //并创建一个data缓冲区，后续用于存放vfs bio需要写入的数据内容
    rtc_time_to_tm(get_seconds() + 8 * 60 * 60, &ctx->tm);

    cdp_bio = cdp_bio_alloc(bio);
    if( ! cdp_bio ) {
        kfree(ctx);
        return NULL;
    }
    ctx->cdp_bio = cdp_bio;

    return ctx;
}

/* 释放bio请求记录 */
static void free_bio_ctx(struct bio_ctx_t *ctx)
{
    cdp_bio_free(ctx->cdp_bio);
    kfree(ctx);
}

/* 关闭元数据文件 */
static int close_meta_file(void)
{
    if( meta_file ) {
        filp_close(meta_file, NULL);
        meta_file = NULL;
    }
    return 0;
}

/* 打开元数据文件，文件命名格式：metafile.时间戳 */
static int open_meta_file(void)
{
    int ret;
    char time_str[100];
    char filename[100];

    close_meta_file();

    gen_current_time_str(time_str);
    sprintf(filename, "%s/%s.%s", FILE_PATH, META_FILE_NAME, time_str);
    printk(KERN_INFO "create...%s", filename);

    meta_file = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(meta_file)) {
        ret = PTR_ERR(meta_file);
        printk(KERN_ERR "Failed to open metafile: %d\n", ret);
        return ret;
    }

    return 0;
}

/* 关闭bio数据文件 */
static int close_data_file(void)
{
    if( data_file ) {
        filp_close(data_file, NULL);
        data_file = NULL;
    }
    return 0;
}

/* 打开bio数据文件，文件命名格式：datafile.时间戳 */
static int open_data_file(void)
{
    int ret;
    char time_str[100];
    char filename[100];

    close_data_file();

    gen_current_time_str(time_str);
    sprintf(filename, "%s/%s.%s", FILE_PATH, DATA_FILE_NAME, time_str);
    printk(KERN_INFO "create...%s", filename);

    data_file = filp_open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (IS_ERR(data_file)) {
        ret = PTR_ERR(data_file);
        printk(KERN_ERR "Failed to open datafile: %d\n", ret);
        return ret;
    }

    return 0;
}

/*
static int gen_meta_log_1(unsigned int start_sector, unsigned int end_sector,
                	       unsigned int segments, unsigned int length,
                	       unsigned char *buff)
{
    struct rtc_time tm;
    int ret;

    rtc_time_to_tm(get_seconds() + 8 * 60 * 60, &tm);	// 东八区加8小时
    ret =
	sprintf(buff, "%u-%02u-%02u-%02u-%02u-%02u:[%u-%u][%u][%u]\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, start_sector,
		end_sector, segments, length);
    return ret;
}
*/

/* 生成一个元数据字符串， 年-月-日-时-分-秒:[写入host扇区号][写入数据长度][写入数据在bio数据文件偏移] */
static int gen_meta_log_2(unsigned int start_sector, unsigned int length,
                          unsigned int data_file_pos, unsigned char *buff)
{
    struct rtc_time tm;
    int ret;

    rtc_time_to_tm(get_seconds() + 8 * 60 * 60, &tm);	// 东八区加8小时
    ret =
	sprintf(buff, "%u-%02u-%02u-%02u-%02u-%02u:[%u][%u][%u]\n",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec, start_sector, length, data_file_pos);
    return ret;
}

/*
static int write_meta_log_1(unsigned int start_sector, unsigned int end_sector, 
                            unsigned int num_segments, unsigned int data_size)
{
    int ret;

    if( ! meta_file ) { 
        return -1; 
    }

    ret = gen_meta_log_1(start_sector, end_sector, num_segments, data_size, meta_buffer);
    printk(KERN_INFO "kernel_write_1 %s", meta_buffer);

    ret = kernel_write(meta_file, meta_buffer, ret, &meta_file->f_pos);
    printk(KERN_INFO "kernel_write_1_ret %d\n", ret);
    return ret;
}
*/

/* 写入一条元数据记录 */
static int write_meta_log_2(unsigned int start_sector, unsigned int length, 
                            int data_file_pos)
{
    int ret;

    if( ! meta_file ) { 
        return -1; 
    }

    ret = gen_meta_log_2(start_sector, length, data_file_pos, meta_buffer);
    //printk(KERN_INFO "kernel_write_2 %s", meta_buffer);

    ret = kernel_write(meta_file, meta_buffer, ret, &meta_file->f_pos);
    //printk(KERN_INFO "kernel_write_2_ret %d\n", ret);
    return ret;
}

/* 检查bio数据文件是否需超过大小，重新再生成一个新的 */
static int check_log_file(unsigned int data_size)
{
    if( data_file->f_pos > MAX_DATA_FILE_SIZE ||
        meta_file->f_pos > MAX_DATA_FILE_SIZE ) {
        printk(KERN_INFO "check_log_file: meta:%llu data:%llu\n", 
                        meta_file->f_pos, data_file->f_pos);
        close_data_file();
        close_meta_file();
        open_meta_file();
        open_data_file();
        return 0;
    }
    return data_file->f_pos;
}
/*
static unsigned int get_data_file_pos(void)
{
    return data_file->f_pos;
}
*/

/* 写入一个bio数据到bio数据文件 */
static int write_data_file_bio(struct bio *bio)
{
    //struct bio_vec bvec;
    //struct bvec_iter iter;
    int i = 0, wr= 0, ret = 0;

    if( ! data_file ) {
        return -1;
    }

    //循环把bio里面的page写入bio数据文件，这里不能用
    //bio_for_each_segment去迭代，因为我们的cdp bio是自己手动构建的，
    //不是fastclone，有一些字段并没有复制，所以这里只能用for
    for( i = 0; i < bio->bi_vcnt; i++ ) {
        struct page *pg;
        unsigned char *data;
        unsigned int offset;
        unsigned int length;

        pg = bio->bi_io_vec[i].bv_page;
        length = bio->bi_io_vec[i].bv_len;
        offset = bio->bi_io_vec[i].bv_offset;
        data = page_address(pg);
        wr = kernel_write(data_file, data, length, &data_file->f_pos);
        //printk(KERN_INFO "kernel_write %p %d %lld %d\n", data, length, data_file->f_pos, wr);
        if( wr <=0 ) {
            printk(KERN_ERR "write_data_file_bio fail %d", wr);
        } else {
            ret += wr;
        }
    }

    return ret;
}
/*
static void bio_end_io_cb(struct bio *bio)
{
    struct bio *cdp_bio;

    blk_status_t status = bio->bi_status;
    printk(KERN_INFO "bio_end_read %p %p %d %d", 
                    bio, bio->bi_private, status,
                    bio->bi_iter.bi_size);

    if( bio->bi_iter.bi_size ) {
        printk(KERN_INFO "bio_end_read_1 %p %p %d %d", 
                    bio, bio->bi_private, status,
                    bio->bi_iter.bi_size);
        return;
    }

    cdp_bio = bio->bi_private;
    bio_put(bio);
    bio_endio(cdp_bio);
}
*/

/* 把来自于 vfs 的submit队列中的bio请求 move 到 write队列 */
static int move_submit_to_write_list(void)
{
    struct bio_list_t *bio_item, *tmp;
    int i = 0;

    spin_lock_irq(&bio_list_lock);

    list_for_each_entry_safe(bio_item, tmp, &bio_submit_list, list) {
        list_del(&bio_item->list);
        list_add_tail(&bio_item->list, &bio_write_list);
        i++;
    }
    printk(KERN_INFO "move_submit_to_write_list [%d]==[%d]", i, bio_submit_list_count);
    bio_submit_list_count = 0;

    spin_unlock_irq(&bio_list_lock);

    return i;
}

/* 处理来自于 vfs 层的bio请求，生成对应的bio请求记录添加到 submit 队列 */
static int handle_request_bio(struct request_queue *q, struct bio *bio)
{
    struct bio_list_t *bio_item;
    struct bio_ctx_t *ctx;
    
    if (bio_data_dir(bio) == READ) {
        return 0;
    }

    //bio_item = kmalloc(sizeof(struct bio_list_t), GFP_KERNEL);
    bio_item = mempool_alloc(bio_list_mempool, GFP_NOIO);
    if( ! bio_item ) {
        return -ENOMEM;
    }

    ctx = new_bio_ctx(bio);
    if( ! ctx ) {
        kfree(bio_item);
        return -ENOMEM;
    }
    bio_item->ctx = ctx;

    //提交到 submit 队列
    spin_lock_irq(&bio_list_lock);
    list_add_tail(&bio_item->list, &bio_submit_list);
    bio_submit_list_count++;
    spin_unlock_irq(&bio_list_lock);

    return 0;
}

/* 
  bio工作线程，负责把 submit队列的bio请求 move 到自己的 write 队列
  然后把这些bio请求写入bio数据文件
*/
static int bio_work_thread_run(void *data)
{
    struct bio_list_t *bio_item, *tmp;
    struct bio_ctx_t *ctx;
    struct bio *cdp_bio;
    int ret, ret1, ret2;
    int write_bio_count;
    int data_file_pos;

    while (!kthread_should_stop()) {
        ret = move_submit_to_write_list();
        if( ret == 0 && bio_write_list_count == 0 ) { 
            //如果当前 submit、write 队列都为空，释放一下cpu防止空转
            ssleep(1); 
        }
        ctx = NULL;
        write_bio_count = 0;
        bio_write_list_count += ret;

        //mutex_lock(&bio_list_lock);

        list_for_each_entry_safe(bio_item, tmp, &bio_write_list, list) {
            write_bio_count++;
            ctx = bio_item->ctx;
            list_del(&bio_item->list);
            kfree(bio_item);
            bio_write_list_count--;

            cdp_bio = ctx->cdp_bio;
            //准备写入数据前，看看bio文件是否超过额定大小
            data_file_pos = check_log_file(cdp_bio->bi_iter.bi_size);
            //写入元数据，写入bio数据，这里后续需要调整一下顺序，先保证bio数据写入成功再写元数据
            ret1 = write_meta_log_2(cdp_bio->bi_iter.bi_sector, 
                                    cdp_bio->bi_iter.bi_size, 
                                    data_file_pos);
            ret2 = write_data_file_bio(cdp_bio);
            if( ret1 <=0 || ret2 <= 0 ) {
                printk(KERN_INFO "write_data_file_bio [%lu][%d]=[%d][%d]", 
                                cdp_bio->bi_iter.bi_sector, cdp_bio->bi_iter.bi_size, 
                                ret1, ret2);
            }
            free_bio_ctx(ctx);

            if( write_bio_count >= WRITE_BIO_COUNT_LOOP ) {
                //如果已经处理过一定数量的bio请求，那么这个时候需要跳出循环
                //去取一下submit队列的请求，防止submit队列撑爆
                break;
            }
        }
        printk(KERN_INFO "bio_write_list [%d]", bio_write_list_count);

        //mutex_unlock(&bio_list_lock);
    }
    return 0;
}

static blk_qc_t make_request(struct request_queue *q, struct bio *bio)
{
    handle_request_bio(q, bio);
    bio_set_dev(bio, target_disk->bd_contains);
    generic_make_request(bio);
    return 0;
}

static int cdp_open(struct block_device *bdev, fmode_t mode)
{
    return 0;
}

static void cdp_release(struct gendisk *gd, fmode_t mode)
{

}

static struct block_device_operations cdp_fops = {
    .owner = THIS_MODULE,
    .open = cdp_open,
    .release = cdp_release,
};

static int __init cdp_init(void)
{
    int ret;

    meta_file = NULL;
    data_file = NULL;

    meta_buffer = NULL;

    cdp_bio_set = NULL;

    target_disk = blkdev_get_by_path(TARGET_DISK_PATH, FMODE_READ | FMODE_WRITE, THIS_MODULE);
    if( IS_ERR(target_disk) ) {
    	printk(KERN_ERR "cdp: Failed to get target disk\n");
	    return PTR_ERR(target_disk);
    }

    cdp_queue = blk_alloc_queue(GFP_KERNEL);
    if (!cdp_queue) {
    	printk(KERN_ERR "cdp: Failed to allocate request queue\n");
	    ret = -ENOMEM;
    	goto err_put_target_disk;
    }

    blk_queue_make_request(cdp_queue, make_request);
    blk_queue_max_hw_sectors(cdp_queue, queue_max_hw_sectors(target_disk->bd_queue));
    blk_queue_logical_block_size(cdp_queue, queue_logical_block_size(target_disk->bd_queue));

    cdp_disk = alloc_disk(1);
    if( !cdp_disk ) {
    	printk(KERN_ERR "cdp: Failed to allocate gendisk\n");
	    ret = -ENOMEM;
    	goto err_release_queue;
    }

    cdp_disk->major = CDP_MAJOR;
    cdp_disk->first_minor = CDP_MINOR;
    cdp_disk->fops = &cdp_fops;
    cdp_disk->private_data = target_disk;
    strcpy(cdp_disk->disk_name, CDP_NAME);
    set_capacity(cdp_disk, get_capacity(target_disk->bd_disk));
    cdp_disk->queue = cdp_queue;

    add_disk(cdp_disk);

    if( open_meta_file() ) {
        goto err_release_queue;
    }
    if( open_data_file() ) {
        goto err_release_queue;
    }

    //spin_lock_init(&cdp_device_lock);
    spin_lock_init(&bio_list_lock);

    meta_buffer = kmalloc(META_BUFFER_SIZE, GFP_KERNEL);

   	bio_ctx_cache = kmem_cache_create("bio_ctx_cache", sizeof(struct bio_ctx_t), 0, 0, NULL);
    if( ! bio_ctx_cache ) {
        printk(KERN_ERR "kmem_cache_create fail");    
        return -ENOMEM;
    }
    bio_list_cache = kmem_cache_create("bio_ctx_cache", sizeof(struct bio_list_t), 0, 0, NULL);
    if( ! bio_ctx_cache ) {
        printk(KERN_ERR "kmem_cache_create fail");    
        return -ENOMEM;
    }
    bio_ctx_mempool = mempool_create_slab_pool(1024, bio_ctx_cache);
    if( ! bio_ctx_mempool ) {
        printk(KERN_ERR "mempool_create_slab_pool fail");    
        return -ENOMEM;
    }
    bio_list_mempool = mempool_create_slab_pool(1024, bio_list_cache);
    if( ! bio_list_mempool ) {
        printk(KERN_ERR "mempool_create_slab_pool fail");    
        return -ENOMEM;
    }    

    page_pool = mempool_create(2048, (mempool_alloc_t *)bio_page_alloc, (mempool_free_t *)bio_page_free, NULL);
    if( ! page_pool ) {
        printk(KERN_ERR "mempool_create fail");    
        return -ENOMEM;
    }

    cdp_bio_set = bioset_create(BIO_POOL_SIZE, 0, 0);
    if( ! cdp_bio_set ) {
        printk(KERN_ERR "bioset_create fail");    
        return -ENOMEM;        
    }

    bio_work_thread = kthread_run(bio_work_thread_run, NULL, "bio_work_thread");

    printk(KERN_INFO "cdp: cdp_init %d\n", ret);

    return 0;

err_release_queue:
    blk_cleanup_queue(cdp_queue);
err_put_target_disk:
    blkdev_put(target_disk, FMODE_READ | FMODE_WRITE);
    return ret;
}

static void __exit cdp_exit(void)
{
    close_data_file();
    close_meta_file();

    if( meta_buffer ) {
        kfree(meta_buffer);
    }

	if (bio_ctx_mempool) {
		mempool_destroy(bio_ctx_mempool);
    }
	if (bio_list_mempool) {
		mempool_destroy(bio_list_mempool);
    }    
   	if (bio_ctx_cache) {
		kmem_cache_destroy(bio_ctx_cache);
    }
   	if (bio_list_cache) {
		kmem_cache_destroy(bio_list_cache);
    }
    
    if( page_pool ) {
        mempool_destroy(page_pool);
    }

    if( cdp_bio_set ) {
        bioset_free(cdp_bio_set);
    }

    del_gendisk(cdp_disk);
    blk_cleanup_queue(cdp_queue);
    put_disk(cdp_disk);
    blkdev_put(target_disk, FMODE_READ | FMODE_WRITE);

    printk(KERN_INFO "cdp: cdp_exit");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("CDP Driver");

module_init(cdp_init);
module_exit(cdp_exit);

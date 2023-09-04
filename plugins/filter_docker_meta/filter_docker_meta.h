#ifndef FLB_FILTER_DOCKER_META_H
#define FLB_FILTER_DOCKER_META_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_filter.h>

/*
 * Since this filter might get a high number of request per second,
 * we need to keep some cached data to perform filtering, e.g:
 *
 *  tag -> regex: pod name, container ID, container name, etc
 *
 * By default, we define a hash table for 256 entries.
 */
#define FLB_HASH_TABLE_SIZE 256

/*
 * When merging nested JSON strings from Docker logs, we need a temporary
 * buffer to perform the convertion. To optimize the process, we pre-allocate
 * a buffer for that purpose. The FLB_MERGE_BUF_SIZE defines the buffer size.
 *
 * Note: this is only the initial buffer size, it can grow depending on needs
 * for every incoming json-string.
 */
#define FLB_MERGE_BUF_SIZE  2048  /* 2KB */


struct filter_docker_ctx
{
    int rules_cnt;
    struct flb_filter_instance *ins;
    struct flb_hash_table *hash_table;
};

struct flb_docker_meta
{
    char *container_id;
    size_t container_id_len;
    char *container_name;
    size_t container_name_len;
};

#endif /* FLB_FILTER_DOCKER_META_H */

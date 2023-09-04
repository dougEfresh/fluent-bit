
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_file.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_log_event_encoder.h>


#include "filter_docker_meta.h"

#define PLUGIN_NAME "filter_docker_meta"


/*
static inline int add_docker_meta(
        struct flb_log_event_encoder *log_encoder,
        struct flb_log_event *log_event,
        struct filter_docker_ctx *ctx) {

    int ret;
    int records_in;
    msgpack_object map;
    struct modify_rule *rule;
    msgpack_sbuffer sbuffer;
    msgpack_packer in_packer;
    msgpack_unpacker unpacker;
    msgpack_unpacked unpacked;
    int initial_buffer_size = 1024 * 8;
    int new_buffer_size = 0;
    struct mk_list *tmp;
    struct mk_list *head;
    bool has_modifications = false;

    map = *log_event->body;
    records_in = map.via.map.size;


    msgpack_sbuffer_init(&sbuffer);
    msgpack_packer_init(&in_packer, &sbuffer, msgpack_sbuffer_write);
    msgpack_unpacked_init(&unpacked);

    msgpack_pack_map(&tmp_pck, obj->via.map.size + 1);
    kv = obj->via.map.ptr;
    for (int i = 0; i < obj->via.map.size; i++) {
        msgpack_pack_object(&tmp_pck, kv->key);
        msgpack_pack_object(&tmp_pck, kv->value);
        kv++;
    }


    msgpack_unpacked_destroy(&unpacked);
    msgpack_unpacker_destroy(&unpacker);
    msgpack_sbuffer_destroy(&sbuffer);

    return 0;
}
*/

static struct flb_docker_meta *fetch_docker_metadata(const char *container_id,
                                                     int id_len,
                                                     struct filter_docker_ctx *ctx) {
    char path[256];
    flb_sds_t contents;
    char *json_buffer;
    size_t json_size;
    int root_type;
    size_t consumed;
    struct flb_docker_meta *meta;
    msgpack_object root;
    msgpack_unpacked result;

    // Construct the path to config.v2.json
    snprintf(path, sizeof(path), "/var/lib/docker/containers/%s/config.v2.json", container_id);

    // Read the json file
    contents = flb_file_read(path);
    if (contents == NULL) {
        flb_plg_error(ctx->ins, "Error reading JSON file: %s", path);
        return NULL;
    }

    if (flb_pack_json(contents, strlen(contents), &json_buffer, &json_size, &root_type, &consumed) != 0) {
        flb_plg_error(ctx->ins, "Error parsing JSON from: %s", path);
        flb_sds_destroy(contents);
        return NULL;
    }
    flb_sds_destroy(contents);

    // Use msgpack to find the 'Name' property
    msgpack_unpacked_init(&result);
    msgpack_unpack_next(&result, json_buffer, json_size, NULL);
    root = result.data;

    msgpack_object_kv *kv;
    for (int i = 0; i < root.via.map.size; i++) {
        kv = &root.via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR &&
            strncmp(kv->key.via.str.ptr, "Name", kv->key.via.str.size) == 0) {
            meta = flb_calloc(1, sizeof(struct flb_docker_meta));
            if (!meta) {
                flb_errno();
                free(json_buffer);
                return NULL;
            }

            meta->container_id = flb_strdup(container_id);
            meta->container_id_len = id_len;
            meta->container_name = flb_strndup(kv->val.via.str.ptr, kv->val.via.str.size);
            meta->container_name_len = kv->val.via.str.size;

            // Update the local cache
            flb_hash_table_add(ctx->hash_table, container_id, id_len, meta, 0);

            free(json_buffer);
            return meta;
        }
    }

    free(json_buffer);
    return NULL;
}


static int cb_docker_filter(const void *data, size_t bytes,
                              const char *tag, int tag_len,
                              void **out_buf, size_t *out_size,
                              struct flb_filter_instance *f_ins,
                              struct flb_input_instance *i_ins,
                              void *context,
                              struct flb_config *config) {

    struct flb_log_event_encoder log_encoder;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct filter_docker_ctx *ctx = context;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    int modifications = 0;
    int total_modifications = 0;
    int ret;

    // Extract docker id from tag, e.g. docker.891d4cd1dadf4ba45a611e5e60667a6ebd4d3c6112eb31f59dd1bd0d75d82ebb
    const char *prefix = "docker.";
    if (tag_len <= strlen(prefix)) {
        flb_plg_error(ctx->ins, "Tag is shorter than expected");
        return FLB_FILTER_NOTOUCH;
    }

    char container_id[tag_len - strlen(prefix) + 1];
    strncpy(container_id, tag + strlen(prefix), tag_len - strlen(prefix));
    container_id[tag_len - strlen(prefix)] = '\0';


    struct flb_docker_meta *meta = NULL;
    meta = (struct flb_docker_meta *) flb_hash_table_get_ptr(ctx->hash_table, container_id, strlen(container_id));

    if (!meta) {
        flb_plg_debug(ctx->ins, "getting metadata for %s", container_id);
        // Cache miss
        meta = fetch_docker_metadata(container_id, strlen(container_id), ctx);
        if (!meta) {
            flb_plg_error(ctx->ins, "Failed to fetch docker metadata for container: %s", container_id);
            return FLB_FILTER_NOTOUCH;
        }
    }

    //ret = flb_hash_table_add(ctx->hash_table, container_id, strlen(container_id), meta, 0);
    if (ret == -1) {
        flb_plg_error(ctx->ins, "Could not add container ID %s to metadata hash table", container_id);
        flb_free(meta);
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder,
                                     FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);

        return FLB_FILTER_NOTOUCH;
    }

    while ((ret = flb_log_event_decoder_next(
            &log_decoder,
            &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        // TODO add key component with value of 'infra'
        obj = log_event.body;
        if (obj->type != MSGPACK_OBJECT_MAP) {
            continue;
        }

        //add_docker_meta(&log_encoder, &log_event, ctx);
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    //return FLB_FILTER_MODIFIED;
    return 0;
}

static int cb_docker_init(struct flb_filter_instance *f_ins,
                            struct flb_config *config,
                            void *data)
{

    struct filter_docker_ctx *ctx;

    // Create context
    ctx = flb_malloc(sizeof(struct filter_docker_ctx));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;
    ctx->rules_cnt = 0;
    ctx->hash_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_RANDOM,
                                            FLB_HASH_TABLE_SIZE,
                                            FLB_HASH_TABLE_SIZE);

    // Set context
    flb_filter_set_context(f_ins, ctx);
    return 0;
}
static int cb_docker_exit(void *data, struct flb_config *config)
{
    struct record_docker_ctx *ctx = data;
    if (ctx != NULL) {
        flb_free(ctx);
    }
    return 0;
}

static struct flb_config_map config_map[] = {
};

struct flb_filter_plugin filter_docker_meta_plugin = {
        .name         = "docker_meta",
        .description  = "get docker metadata",
        .cb_init      = cb_docker_init,
        .cb_filter    = cb_docker_filter,
        .cb_exit      = cb_docker_exit,
        .config_map   = config_map,
        .flags        = 0
};


#include <fluent-bit/flb_info.h>
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

#include "docker_meta.h"
#include <msgpack.h>
#include <stdlib.h>
#include <errno.h>

#define PLUGIN_NAME "filter_docker_meta"
#define DOCKER_TAG_PREFIX "docker."

static int fetch_docker_metadata(const char *container_id,
                                                     int id_len,
                                                     struct flb_filter_docker *ctx) {
    int ret;
    flb_sds_t path;
    flb_sds_t contents;
    flb_sds_t tmp;
    int found_name = FLB_FALSE;
    char *json_buffer;
    size_t json_size;
    size_t off = 0;
    int root_type;
    size_t consumed;
    struct flb_docker_meta meta;
    msgpack_object root;
    msgpack_unpacked result;

    // Construct the path to config.v2.json
    tmp = flb_sds_create_size(256);
    path = flb_sds_printf(&tmp, FLB_DOCKER_FILTER_PATH_FORMAT, "test/containers", container_id);
    //path = flb_sds_printf(&tmp, FLB_DOCKER_FILTER_PATH_FORMAT, ctx->docker_dir, container_id);

    if (!path) {
        flb_sds_destroy(tmp);
        return -1;
    }
    // Read the json file
    contents = flb_file_read(path);
    if (!contents) {
        flb_plg_warn(ctx->ins, "Error reading JSON file: %s", path);
        //flb_sds_destroy(path);
        return -1;
    }


    ret = flb_pack_json(contents, flb_sds_len(contents), &json_buffer, &json_size,
                        &root_type, &consumed);
    if (ret < 0) {
        flb_plg_error(ctx->ins, "Error parsing JSON from: %s", path);
        flb_sds_destroy(contents);
        flb_sds_destroy(path);
        return -1;
    }
    flb_sds_destroy(contents);


    // Use msgpack to find the 'Name' property
    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, json_buffer, json_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_plg_error(ctx->ins, "Cannot unpack %s response to find metadata",
                      path);
        flb_free(json_buffer);
        flb_sds_destroy(path);
        msgpack_unpacked_destroy(&result);
    }
    root = result.data;
    if (root.type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "%s response parsing failed, msgpack_type=%i",
                      path,
                      root.type);
        flb_free(json_buffer);
        flb_sds_destroy(path);
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    /* config.v2.json
{
  "StreamConfig": {},
  "State": {
    "Running": true,
    "Pid": 9094,
    "ExitCode": 0,
    "Error": "",
    "StartedAt": "2023-07-23T11:25:20.272441989Z",
    "FinishedAt": "0001-01-01T00:00:00Z",
    "Health": null
  },
  "ID": "ad10359af6b4c215ba1c57c287373b92c6a376cb6c2e05aa2b58d19d12d455ff",
     ...
 }
    */

    msgpack_object_kv *kv;
    for (int i = 0; i < root.via.map.size; i++) {
        kv = &root.via.map.ptr[i];
        if (kv->key.type == MSGPACK_OBJECT_STR) {
            if (kv->key.via.str.size == 4 && strncmp(kv->key.via.str.ptr, "Name", kv->key.via.str.size) == 0) {
                meta.container_name = kv->val.via.str.ptr;
                meta.container_name_len = (int) kv->val.via.str.size;
                found_name = FLB_TRUE;
                // Update the local cache
                //
                //free(json_buffer);
                //return meta;
            }
        }
    }

    if (found_name == FLB_FALSE) {
        flb_sds_destroy(path);
        flb_free(json_buffer);
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    flb_sds_destroy(path);
    flb_free(json_buffer);
    msgpack_unpacked_destroy(&result);

    return flb_hash_table_add(ctx->hash_table, container_id, id_len, &meta, 0);
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
    struct flb_filter_docker *ctx = context;
    msgpack_object  *obj;
    msgpack_object_kv *kv;
    int modifications = 0;
    int total_modifications = 0;
    int ret = 0;

    // Extract docker id from tag, e.g. docker.891d4cd1dadf4ba45a611e5e60667a6ebd4d3c6112eb31f59dd1bd0d75d82ebb
    if (tag_len <= strlen(DOCKER_TAG_PREFIX)) {
        flb_plg_error(ctx->ins, "Tag is shorter than expected");
        return FLB_FILTER_NOTOUCH;
    }

    char container_id[tag_len - strlen(DOCKER_TAG_PREFIX) + 1];
    strncpy(container_id, tag + strlen(DOCKER_TAG_PREFIX), tag_len - strlen(DOCKER_TAG_PREFIX));
    container_id[tag_len - strlen(DOCKER_TAG_PREFIX)] = '\0';

    struct flb_docker_meta *meta = NULL;
    meta = (struct flb_docker_meta *) flb_hash_table_get_ptr(ctx->hash_table, container_id, (int) strlen(container_id));

    if (!meta) {
        flb_plg_debug(ctx->ins, "getting metadata for %s", container_id);
        // Cache miss
        ret = fetch_docker_metadata(container_id, (int) strlen(container_id), ctx);
        if (!ret) {
            flb_plg_error(ctx->ins, "Failed to fetch docker metadata for container: %s", container_id);
            return FLB_FILTER_NOTOUCH;
        }

        meta = (struct flb_docker_meta *) flb_hash_table_get_ptr(ctx->hash_table, container_id, (int) strlen(container_id));
        if (!meta) {
            flb_plg_error(ctx->ins, "Failed to get docker metadata from hash table for container: %s", container_id);
            return FLB_FILTER_NOTOUCH;
        }
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        return FLB_FILTER_NOTOUCH;
    }

    ret = flb_log_event_encoder_init(&log_encoder, FLB_LOG_EVENT_FORMAT_DEFAULT);

    if (ret != FLB_EVENT_ENCODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event encoder initialization error : %d", ret);

        flb_log_event_decoder_destroy(&log_decoder);
        return FLB_FILTER_NOTOUCH;
    }

    while ((flb_log_event_decoder_next(
            &log_decoder,
            &log_event)) == FLB_EVENT_DECODER_SUCCESS) {

        ret = flb_log_event_encoder_begin_record(&log_encoder);
        if (ret != FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_decoder_destroy(&log_decoder);
            return FLB_FILTER_NOTOUCH;
        }

        flb_plg_debug(ctx->ins,"Adding container_name=%s", meta->container_name);
        ret = flb_log_event_encoder_append_body_values(
                      &log_encoder,
                      FLB_LOG_EVENT_STRING_VALUE("container_name", strlen("container_name")),
                      FLB_LOG_EVENT_STRING_VALUE("blah", strlen("blah")));
        if (ret == FLB_EVENT_ENCODER_SUCCESS) {
            flb_log_event_encoder_commit_record(&log_encoder);
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);
    flb_log_event_encoder_destroy(&log_encoder);

    return FLB_FILTER_MODIFIED;
}

static void flb_filter_docker_destroy(struct flb_filter_docker *ctx) {
    if (ctx) {
        if (ctx->hash_table) {
            flb_hash_table_destroy(ctx->hash_table);
        }
        flb_free(ctx);
    }
}

static int cb_docker_init(struct flb_filter_instance *f_ins,
                            struct flb_config *config,
                            void *data)
{

    struct flb_filter_docker *ctx;

    // Create context
    ctx = flb_calloc(1, sizeof(struct flb_filter_docker));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = f_ins;
    ctx->hash_table = flb_hash_table_create(FLB_HASH_TABLE_EVICT_RANDOM,
                                            FLB_HASH_TABLE_SIZE,
                                            FLB_HASH_TABLE_SIZE);
    if (!ctx->hash_table) {
        flb_plg_error(f_ins, "failed to create container_hash_table");
        goto error;
    }
    // Set context
    flb_filter_set_context(f_ins, ctx);
    return 0;
error:
    flb_plg_error(ctx->ins, "Initialization failed.");
    flb_filter_docker_destroy(ctx);
    return -1;
}

static int cb_docker_exit(void *data, struct flb_config *config)
{
    struct flb_filter_docker *ctx = data;
    if (ctx != NULL) {
        flb_filter_docker_destroy(ctx);
    }
    return 0;
}

static struct flb_config_map config_map[] = {
        {
                FLB_CONFIG_MAP_STR, "docker_dir", "/var/lib/docker/containers",
                0, FLB_TRUE, offsetof(struct flb_filter_docker, docker_dir),
                "Directory location of the config.v2.json"
                "Defaults to /var/lib/docker/containers"
        },
        {0}
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

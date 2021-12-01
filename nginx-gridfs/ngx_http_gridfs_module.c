#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_md5.h>
#include <ngx_http.h>
#include <mongoc.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>

#define TRUE 1
#define FALSE 0
#define ALLOC_BUFFER_SIZE 4096

/* Parse config directive */
static char * ngx_http_mongo(ngx_conf_t *cf, ngx_command_t *cmd, void *dummy);

/* Parse config directive */
static char* ngx_http_gridfs(ngx_conf_t* directive, ngx_command_t* command, void* gridfs_conf);

static void* ngx_http_gridfs_create_main_conf(ngx_conf_t* directive);

static void* ngx_http_gridfs_create_loc_conf(ngx_conf_t* directive);

static char* ngx_http_gridfs_merge_loc_conf(ngx_conf_t* directive, void* parent, void* child);

static ngx_int_t ngx_http_gridfs_init_worker(ngx_cycle_t* cycle);

static ngx_int_t ngx_http_gridfs_handler(ngx_http_request_t* request);

static void ngx_http_gridfs_post_read(ngx_http_request_t* request);

typedef struct {
    ngx_str_t db;
    ngx_str_t root_collection;
    ngx_str_t field;
    ngx_uint_t type;
    ngx_str_t mongo;
} ngx_http_gridfs_loc_conf_t;

typedef struct {
    ngx_str_t name;
    mongoc_client_t* conn;
} ngx_http_mongo_connection_t;

typedef struct {
    ngx_array_t loc_confs; /* ngx_http_gridfs_loc_conf_t */
} ngx_http_gridfs_main_conf_t;


/* Array specifying how to handle configuration directives. */
static ngx_command_t ngx_http_gridfs_commands[] = {

    {
        ngx_string("mongo"),
        NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_http_mongo,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    {
        ngx_string("gridfs"),
        NGX_HTTP_LOC_CONF | NGX_CONF_1MORE,
        ngx_http_gridfs,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },

    ngx_null_command
};

/* Module context. */
static ngx_http_module_t ngx_http_gridfs_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */
    ngx_http_gridfs_create_main_conf,
    NULL, /* init main configuration */
    NULL, /* create server configuration */
    NULL, /* init serever configuration */
    ngx_http_gridfs_create_loc_conf,
    ngx_http_gridfs_merge_loc_conf
};

/* Module definition. */
ngx_module_t ngx_http_gridfs_module = {
    NGX_MODULE_V1,
    &ngx_http_gridfs_module_ctx,
    ngx_http_gridfs_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    ngx_http_gridfs_init_worker,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};

ngx_array_t ngx_http_mongo_connections;

/* Parse the 'mongo' directive. */
static char * ngx_http_mongo(ngx_conf_t *cf, ngx_command_t *cmd, void *void_conf) {
    ngx_str_t *value;
    ngx_http_gridfs_loc_conf_t *gridfs_loc_conf;

    gridfs_loc_conf = void_conf;

    value = cf->args->elts;
    gridfs_loc_conf->mongo = value[1];

    return NGX_CONF_OK;
}

/* Parse the 'gridfs' directive. */
static char* ngx_http_gridfs(ngx_conf_t* cf, ngx_command_t* command, void* void_conf) {
    ngx_http_gridfs_loc_conf_t *gridfs_loc_conf = void_conf;
    ngx_http_core_loc_conf_t* core_conf;
    ngx_str_t *value, type;
    volatile ngx_uint_t i;

    core_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_conf-> handler = ngx_http_gridfs_handler;

    value = cf->args->elts;
    gridfs_loc_conf->db = value[1];

    /* Parse the parameters */
    for (i = 2; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "root_collection=", 16) == 0) {
            gridfs_loc_conf->root_collection.data = (u_char *) &value[i].data[16];
            gridfs_loc_conf->root_collection.len = ngx_strlen(&value[i].data[16]);
            continue;
        }

        if (ngx_strncmp(value[i].data, "field=", 6) == 0) {
            gridfs_loc_conf->field.data = (u_char *) &value[i].data[6];
            gridfs_loc_conf->field.len = ngx_strlen(&value[i].data[6]);

            /* Currently only support for "_id" and "filename" */
            if (gridfs_loc_conf->field.data != NULL
                && ngx_strcmp(gridfs_loc_conf->field.data, "filename") != 0
                && ngx_strcmp(gridfs_loc_conf->field.data, "_id") != 0) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "Unsupported Field: %s", gridfs_loc_conf->field.data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        if (ngx_strncmp(value[i].data, "type=", 5) == 0) {
            type = (ngx_str_t) ngx_string(&value[i].data[5]);

            /* Currently only support for "objectid", "string", and "int" */
            if (type.len == 0) {
                gridfs_loc_conf->type = NGX_CONF_UNSET_UINT;
            } else if (ngx_strcasecmp(type.data, (u_char *)"objectid") == 0) {
                gridfs_loc_conf->type = BSON_TYPE_OID;
            } else if (ngx_strcasecmp(type.data, (u_char *)"string") == 0) {
                gridfs_loc_conf->type = BSON_TYPE_UTF8;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "Unsupported Type: %s", (char *)value[i].data);
                return NGX_CONF_ERROR;
            }

            continue;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[i]);
        return NGX_CONF_ERROR;
    }

    if (gridfs_loc_conf->field.data != NULL
        && ngx_strcmp(gridfs_loc_conf->field.data, "filename") == 0
        && gridfs_loc_conf->type != BSON_TYPE_UTF8) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Field: filename, must be of Type: string");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void *ngx_http_gridfs_create_main_conf(ngx_conf_t *cf) {
    ngx_http_gridfs_main_conf_t  *gridfs_main_conf;

    gridfs_main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_gridfs_main_conf_t));
    if (gridfs_main_conf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&gridfs_main_conf->loc_confs, cf->pool, 4,
                       sizeof(ngx_http_gridfs_loc_conf_t *))
        != NGX_OK) {
        return NULL;
    }

    return gridfs_main_conf;
}

static void* ngx_http_gridfs_create_loc_conf(ngx_conf_t* directive) {
    ngx_http_gridfs_loc_conf_t* gridfs_conf;
    gridfs_conf = ngx_pcalloc(directive->pool, sizeof(ngx_http_gridfs_loc_conf_t));
    if (gridfs_conf == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, directive, 0,
                           "Failed to allocate memory for GridFS Location Config.");
        return NGX_CONF_ERROR;
    }

    gridfs_conf->db.data = NULL;
    gridfs_conf->db.len = 0;
    gridfs_conf->root_collection.data = NULL;
    gridfs_conf->root_collection.len = 0;
    gridfs_conf->mongo.data = NULL;
    gridfs_conf->mongo.len = 0;
    gridfs_conf->field.data = NULL;
    gridfs_conf->field.len = 0;
    gridfs_conf->type = NGX_CONF_UNSET_UINT;

    return gridfs_conf;
}

static char* ngx_http_gridfs_merge_loc_conf(ngx_conf_t* cf, void* void_parent, void* void_child) {
    ngx_http_gridfs_loc_conf_t *parent = void_parent;
    ngx_http_gridfs_loc_conf_t *child = void_child;
    ngx_http_gridfs_main_conf_t *gridfs_main_conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_gridfs_module);
    ngx_http_gridfs_loc_conf_t **gridfs_loc_conf;

    ngx_conf_merge_str_value(child->db, parent->db, NULL);
    ngx_conf_merge_str_value(child->root_collection, parent->root_collection, "fs");
    ngx_conf_merge_str_value(child->field, parent->field, "_id");
    ngx_conf_merge_uint_value(child->type, parent->type, BSON_TYPE_OID);
    ngx_conf_merge_str_value(child->mongo, parent->mongo, "127.0.0.1:27017");


    // Add the local gridfs conf to the main gridfs conf
    if (child->db.data) {
        gridfs_loc_conf = ngx_array_push(&gridfs_main_conf->loc_confs);
        *gridfs_loc_conf = child;
    }

    return NGX_CONF_OK;
}

ngx_http_mongo_connection_t* ngx_http_get_mongo_connection( ngx_str_t name ) {
    ngx_http_mongo_connection_t *mongo_conns;
    ngx_uint_t i;

    mongo_conns = ngx_http_mongo_connections.elts;

    for ( i = 0; i < ngx_http_mongo_connections.nelts; i++ ) {
        if ( name.len == mongo_conns[i].name.len
             && ngx_strncmp(name.data, mongo_conns[i].name.data, name.len) == 0 ) {
            return &mongo_conns[i];
        }
    }

    return NULL;
}


static ngx_int_t ngx_http_mongo_add_connection(ngx_cycle_t* cycle, ngx_http_gridfs_loc_conf_t* gridfs_loc_conf) {
    ngx_http_mongo_connection_t* mongo_conn;
    u_char host[255];
    mongo_conn = ngx_http_get_mongo_connection( gridfs_loc_conf->mongo );
    if (mongo_conn != NULL) {
        return NGX_OK;
    }

    mongo_conn = ngx_array_push(&ngx_http_mongo_connections);
    if (mongo_conn == NULL) {
        return NGX_ERROR;
    }
    ngx_cpystrn( host, gridfs_loc_conf->mongo.data, gridfs_loc_conf->mongo.len + 1 );
    mongo_conn->name = gridfs_loc_conf->mongo;
    mongo_conn->conn = mongoc_client_new((const char*)host);
    if(!mongo_conn->conn){
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "Mongo Exception: Failed to parse URI");
        return NGX_ERROR;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_gridfs_init_worker(ngx_cycle_t* cycle) {
    ngx_http_gridfs_main_conf_t* gridfs_main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_gridfs_module);
    ngx_http_gridfs_loc_conf_t** gridfs_loc_confs;
    ngx_uint_t i;

    signal(SIGPIPE, SIG_IGN);

    mongoc_init();

    gridfs_loc_confs = gridfs_main_conf->loc_confs.elts;

    ngx_array_init(&ngx_http_mongo_connections, cycle->pool, 4, sizeof(ngx_http_mongo_connection_t));

    for (i = 0; i < gridfs_main_conf->loc_confs.nelts; i++) {
        if (ngx_http_mongo_add_connection(cycle, gridfs_loc_confs[i]) == NGX_ERROR) {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}

static char h_digit(char hex) {
    return (hex >= '0' && hex <= '9') ? hex - '0': ngx_tolower(hex)-'a'+10;
}

static int htoi(char* h) {
    char ok[] = "0123456789AaBbCcDdEeFf";

    if (ngx_strchr(ok, h[0]) == NULL || ngx_strchr(ok,h[1]) == NULL) { return -1; }
    return h_digit(h[0])*16 + h_digit(h[1]);
}

static int url_decode(char * filename) {
    char * read = filename;
    char * write = filename;
    char hex[3];
    int c;

    hex[2] = '\0';
    while (*read != '\0'){
        if (*read == '%') {
            hex[0] = *(++read);
            if (hex[0] == '\0') return 0;
            hex[1] = *(++read);
            if (hex[1] == '\0') return 0;
            c = htoi(hex);
            if (c == -1) return 0;
            *write = (char)c;
        }
        else *write = *read;
        read++;
        write++;
    }
    *write = '\0';
    return 1;
}

static void ngx_http_gridfs_set_header(ngx_http_request_t* request, char* key, u_char* value) {
    ngx_table_elt_t *h;
    h = ngx_list_push(&request->headers_out.headers);
    if (h == NULL) {
        return ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
    }
    h->hash = 1;
    ngx_str_set(&h->key, key);
    h->key.len = ngx_strlen(key);
    ngx_str_set(&h->value, value);
    h->value.len = ngx_strlen(value);
    return;
}
static void ngx_http_gridfs_post_read(ngx_http_request_t* request) {
    ngx_http_gridfs_loc_conf_t* gridfs_conf;
    ngx_http_core_loc_conf_t* core_conf;
    ngx_str_t location_name;
    ngx_str_t full_uri;
    u_char* value;
    ngx_http_mongo_connection_t *mongo_conn;
    mongoc_gridfs_file_t *gfile = NULL;
    mongoc_gridfs_file_opt_t opt = {0};
    mongoc_gridfs_t *gridfs;
    bson_error_t error;
    int64_t gfile_length;
    mongoc_stream_t *stream;
    bson_oid_t oid;
    bson_value_t new_file_id;
    const bson_value_t *file_id;
    ngx_chain_t* in;
    ngx_chain_t out;
    ngx_buf_t* buffer;
    const char *response = "OK";
    int len;
    ssize_t size;
    u_char* p;
    ngx_md5_t     md5;
    u_char md5_buf[16], md5_buf_hex[32], file_id_buf[25];

    if (!request->request_body || !request->request_body->bufs) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    gridfs_conf = ngx_http_get_module_loc_conf(request, ngx_http_gridfs_module);
    core_conf = ngx_http_get_module_loc_conf(request, ngx_http_core_module);

    // ---------- ENSURE MONGO CONNECTION ---------- //

    mongo_conn = ngx_http_get_mongo_connection( gridfs_conf->mongo );
    if (mongo_conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Mongo Connection not found: \"%V\"", &gridfs_conf->mongo);
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    // ---------- RETRIEVE KEY ---------- //

    location_name = core_conf->name;
    full_uri = request->uri;

    if (full_uri.len < location_name.len) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Invalid location name or uri.");
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    value = ngx_pcalloc(request->pool,sizeof(char) * (full_uri.len - location_name.len + 1));
    if (value == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for value buffer.");
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    memcpy(value, full_uri.data + location_name.len, full_uri.len - location_name.len);
    value[full_uri.len - location_name.len] = '\0';

    if (!url_decode((char*)value)) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Malformed request.");
        ngx_http_finalize_request(request, NGX_HTTP_BAD_REQUEST);
    }

    // ---------- RETRIEVE GRIDFILE ---------- //
    gridfs = mongoc_client_get_gridfs(mongo_conn->conn,
    				(const char*)gridfs_conf->db.data,
				(const char*)gridfs_conf->root_collection.data,
				&error);
    if (!gridfs) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "cannot access gridfs");
        ngx_http_finalize_request(request, NGX_HTTP_BAD_REQUEST);
        return;
    }

    opt.content_type = (const char*)request->headers_in.content_type->value.data;
    gfile = mongoc_gridfs_create_file(gridfs, &opt);

    if(!gfile){
        mongoc_gridfs_destroy(gridfs);
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    // set id or name
    switch (gridfs_conf->type) {
    case  BSON_TYPE_OID:
        bson_oid_init_from_string(&oid, (const char*)value);
        new_file_id.value_type = BSON_TYPE_OID;
        new_file_id.value.v_oid = oid;
        mongoc_gridfs_file_set_id(gfile, &new_file_id, &error);
        break;
    case BSON_TYPE_UTF8:
        mongoc_gridfs_file_set_filename(gfile, (const char*)value);
        break;
    }

    stream = mongoc_stream_gridfs_new(gfile);
    assert (stream);

    ngx_md5_init(&md5);

    ngx_buf_t *temp_buf;
    for (in = request->request_body->bufs; in; in = in->next) {
        len = ngx_buf_size(in->buf);
        if (in->buf->in_file) {
            temp_buf = ngx_create_temp_buf(request->pool, len);
            if (NULL == temp_buf) {
                return ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
            }
            ssize_t read_n;
            read_n = ngx_read_file(in->buf->file, temp_buf->start, len, 0);
            if (read_n < 0) {
                /* Problem already logged by read_file. */
                return ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
            } else {
                temp_buf->last = temp_buf->start + read_n;
            }
        } else {
            temp_buf = in->buf;
        }
        size = mongoc_stream_write(stream, temp_buf->pos, len, 500);
	    ngx_md5_update(&md5, temp_buf->pos, len);
        ngx_log_debug(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "mongoc_stream_write %d %d", size, in->buf->in_file);
    }
	ngx_md5_final(md5_buf, &md5);
    ngx_hex_dump(md5_buf_hex, md5_buf, 16);

    mongoc_gridfs_file_set_md5(gfile, (const char*)md5_buf_hex);
    mongoc_gridfs_file_save(gfile);
    // ngx_log_debug(NGX_LOG_DEBUG, request->connection->log, 0, "save gridfs");
    /* Get information about the file */
    gfile_length = mongoc_gridfs_file_get_length(gfile);
    // ngx_log_debug(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "save_file %O", gfile_length);
    file_id = mongoc_gridfs_file_get_id(gfile);

    if (file_id == NULL) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    bson_oid_to_string((const bson_oid_t*)&file_id->value, (char*)file_id_buf);

    p = ngx_palloc(request->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    ngx_sprintf(p, "%d", gfile_length);
    ngx_http_gridfs_set_header(request, "X-File-Size", p);

    ngx_http_gridfs_set_header(request, "X-File-MD5", md5_buf_hex);

    ngx_http_gridfs_set_header(request, "X-File-Id", file_id_buf);

    // ---------- SEND THE HEADERS ---------- //
    request->headers_out.status = NGX_HTTP_CREATED;
    ngx_str_t t = ngx_string("text/plain");
    request->headers_out.content_type = t;

    buffer = ngx_create_temp_buf(request->pool, 16);
    if (buffer == NULL) {
        ngx_http_finalize_request(request, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }
    buffer->in_file = 0;
    buffer->memory = 1;
    buffer->last_buf = buffer->last_in_chain = buffer->flush = 1;

    buffer->last = ngx_copy(buffer->pos, response, 2);;
    out.buf = buffer;
    out.next = NULL;
    request->headers_out.content_length_n = buffer->last - buffer->pos;
    ngx_http_send_header(request);

    mongoc_stream_destroy(stream);
    mongoc_gridfs_destroy(gridfs);
    // ngx_log_debug(NGX_LOG_DEBUG_HTTP, request->connection->log, 0, "save gridfs");
    ngx_http_finalize_request(request, ngx_http_output_filter(request, &out));
    return;
}

static ngx_int_t ngx_http_gridfs_handler(ngx_http_request_t* request) {
    ngx_http_gridfs_loc_conf_t* gridfs_conf;
    ngx_http_core_loc_conf_t* core_conf;
    ngx_buf_t* buffer=NULL;
    ngx_chain_t out;
    ngx_str_t location_name;
    ngx_str_t full_uri;
    u_char* value;
    ngx_http_mongo_connection_t *mongo_conn;
    mongoc_gridfs_file_t *gfile = NULL;
    mongoc_gridfs_t *gridfs;
    bson_error_t error;
    int64_t gfile_length;
    char* gfile_contenttype;
    u_char * gbuffer;
    mongoc_stream_t *stream;
    mongoc_iovec_t iov;
    volatile ssize_t r;
    volatile ssize_t recv_length=0;
    ngx_int_t rc = NGX_OK;
    bson_t filter;
    bson_oid_t oid;
    bson_t *opts;

    if (!(request->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    // --------- upload file ---------
    if (request->method & NGX_HTTP_POST) {
        rc = ngx_http_read_client_request_body(request, ngx_http_gridfs_post_read);
        if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
            return rc;
        }
        return NGX_DONE;
    }

    gridfs_conf = ngx_http_get_module_loc_conf(request, ngx_http_gridfs_module);
    core_conf = ngx_http_get_module_loc_conf(request, ngx_http_core_module);

    // ---------- ENSURE MONGO CONNECTION ---------- //

    mongo_conn = ngx_http_get_mongo_connection( gridfs_conf->mongo );
    if (mongo_conn == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Mongo Connection not found: \"%V\"", &gridfs_conf->mongo);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // ---------- RETRIEVE KEY ---------- //

    location_name = core_conf->name;
    full_uri = request->uri;

    if (full_uri.len < location_name.len) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Invalid location name or uri.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    value = ngx_pcalloc(request->pool,sizeof(char) * (full_uri.len - location_name.len + 1));
    if (value == NULL) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Failed to allocate memory for value buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    memcpy(value, full_uri.data + location_name.len, full_uri.len - location_name.len);
    value[full_uri.len - location_name.len] = '\0';

    if (!url_decode((char*)value)) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "Malformed request.");
        return NGX_HTTP_BAD_REQUEST;
    }

    // ---------- RETRIEVE GRIDFILE ---------- //
    gridfs = mongoc_client_get_gridfs(mongo_conn->conn,
    				(const char*)gridfs_conf->db.data,
				(const char*)gridfs_conf->root_collection.data,
				&error);
    if (!gridfs) {
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
                      "cannot access gridfs");
        return NGX_HTTP_BAD_REQUEST;
    }
    switch (gridfs_conf->type) {
    case  BSON_TYPE_OID:
        bson_init(&filter);
        bson_oid_init_from_string(&oid, (const char*)value);
        bson_append_oid(&filter, "_id", -1, &oid);
        opts = BCON_NEW ( "sort", "{", "_id", BCON_INT32 (-1), "}");
        gfile = mongoc_gridfs_find_one_with_opts(gridfs, &filter, opts, &error);
        bson_destroy (&filter);
        bson_destroy (opts);
        break;
    case BSON_TYPE_UTF8:
        gfile = mongoc_gridfs_find_one_by_filename(gridfs, (const char*)value, &error);
        break;
    }

    if(!gfile){
        ngx_log_error(NGX_LOG_ERR, request->connection->log, 0, error.message);
        mongoc_gridfs_destroy(gridfs);
        return NGX_HTTP_NOT_FOUND;
    }

    /* Get information about the file */
    gfile_length = mongoc_gridfs_file_get_length(gfile);
    gfile_contenttype = (char*)mongoc_gridfs_file_get_content_type(gfile);

    // ---------- SEND THE HEADERS ---------- //

    request->headers_out.status = NGX_HTTP_OK;
    request->headers_out.content_length_n = gfile_length;
    if (gfile_contenttype != NULL) {
        request->headers_out.content_type.len = strlen(gfile_contenttype);
        request->headers_out.content_type.data = (u_char*)gfile_contenttype;
    }
    else ngx_http_set_content_type(request);

    ngx_http_send_header(request);

    // --------- HEAD  ------------//
    if (request->method & NGX_HTTP_HEAD) {
        mongoc_gridfs_file_destroy(gfile);
        mongoc_gridfs_destroy(gridfs);
        ngx_http_finalize_request(request, NGX_OK);
        return NGX_OK;
    }

    // ---------- SEND THE BODY ---------- //
    stream = mongoc_stream_gridfs_new (gfile);
    assert (stream);
    for (;;) {
    		gbuffer = ngx_pcalloc(request->pool,ALLOC_BUFFER_SIZE);
    		if(gbuffer==NULL){
    			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
    						  "Failed to allocate response buffer");
                mongoc_stream_destroy(stream);
                mongoc_gridfs_file_destroy(gfile);
                mongoc_gridfs_destroy(gridfs);
    			return NGX_HTTP_INTERNAL_SERVER_ERROR;
    		}
    	    iov.iov_base = (void *) gbuffer;
    	    iov.iov_len = ALLOC_BUFFER_SIZE;
    		r = mongoc_stream_readv(stream, &iov, 1, -1, 0);
    		assert (r>=0);
    		if (r==0){
   			break;
    		}
    		recv_length += r;
    		buffer = ngx_pcalloc(request->pool, sizeof(ngx_buf_t));
		if (buffer == NULL) {
			ngx_log_error(NGX_LOG_ERR, request->connection->log, 0,
						  "Failed to allocate response buffer");
            mongoc_stream_destroy(stream);
            mongoc_gridfs_file_destroy(gfile);
            mongoc_gridfs_destroy(gridfs);
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		buffer->pos = (u_char*)iov.iov_base;
		buffer->last = (u_char*)iov.iov_base + r;
		buffer->memory = 1;
		buffer->last_buf = (recv_length==gfile_length);
		out.buf = buffer;
		out.next = NULL;
        rc = ngx_http_output_filter(request, &out);
        if (rc == NGX_ERROR) {
            mongoc_stream_destroy(stream);
            mongoc_gridfs_file_destroy(gfile);
            mongoc_gridfs_destroy(gridfs);
            return NGX_ERROR;
        }
    }
    mongoc_stream_destroy(stream);
    mongoc_gridfs_file_destroy(gfile);
    mongoc_gridfs_destroy(gridfs);
    return NGX_OK;
}

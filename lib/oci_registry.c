#include <stdio.h>
#include <curl/curl.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>
#include "erofs/io.h"

#define TOKEN_MODE 1
#define IMAGE_INDEX_MODE 2
#define MANIFEST_MODE 3
#define BLOB_MODE 4 

struct erofs_oci_registry_memory {
    char *memory;
    size_t size;
};

CURLM *erofs_oci_registry_get_multi_handle(void) {
    static CURLM *multi_handle = NULL;
    if (multi_handle == NULL) 
        multi_handle = curl_multi_init();
    return multi_handle;
}

static size_t erofs_oci_registry_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realSize = size * nmemb;
    struct erofs_oci_registry_memory *mem = (struct erofs_oci_registry_memory *)userp;

    char *ptr = realloc(mem->memory, mem->size + realSize + 1); 
    if (ptr == NULL) {
        fprintf(stderr, "realloc failed\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realSize);
    mem->size += realSize;
    mem->memory[mem->size] = 0;
    return realSize;
}

ssize_t oci_registry_read(struct erofs_vfile *vf, void *buf, size_t len) {
    struct erofs_oci_registry_memory *memoryStruct = (struct erofs_oci_registry_memory *)(vf->payload);

    if (len > memoryStruct->size) {
        len = memoryStruct->size;
    }

    memcpy(buf, memoryStruct->memory, len);

    return len;
}

ssize_t oci_registry_pread(struct erofs_vfile *vf, void *buf, u64 offset, size_t len) {
    struct erofs_oci_registry_memory *memoryStruct = (struct erofs_oci_registry_memory *)(vf->payload);

    if (offset >= memoryStruct->size)
        return 0;

    if (offset + len > memoryStruct->size)
        len = memoryStruct->size - offset;

    memcpy(buf, memoryStruct->memory + offset, len);

    return len;
}

off_t oci_registry_lseek(struct erofs_vfile *vf, u64 offset, int whence) {
    struct erofs_oci_registry_memory *memoryStruct = (struct erofs_oci_registry_memory *)(vf->payload);

    u64 new_offset = 0;

    switch (whence) {
        case SEEK_SET:
            new_offset = offset;
            break;
        case SEEK_CUR:
            new_offset = vf->offset + offset;
            break;
        case SEEK_END:
            new_offset = memoryStruct->size + offset;
            break;
        default:
            return -1;
    }

    if (new_offset > memoryStruct->size)
        return -1;

    vf->offset = new_offset;

    return new_offset;
}

char *erofs_oci_registry_get_token(struct erofs_oci_registry_memory *data) {
    if (data->memory == NULL) {
        fprintf(stderr, "No data received\n");
        return NULL;
    }
    json_object *parsed_json = json_tokener_parse(data->memory);
    if (parsed_json == NULL) {
        fprintf(stderr, "Failed to parse JSON\n");
        return NULL;
    }
    json_object *token_json;
    if (!json_object_object_get_ex(parsed_json, "token", &token_json)) {
        fprintf(stderr, "Token not found in JSON\n");
        json_object_put(parsed_json);
        return NULL;
    }
    const char *token = json_object_get_string(token_json);

    char *auth_header = malloc(strlen("Authorization: Bearer ") + strlen(token) + 1);
    if (auth_header == NULL) {
        fprintf(stderr, "Failed to allocate memory for authorization header\n");
        json_object_put(parsed_json);
        return NULL;
    }
    strcpy(auth_header, "Authorization: Bearer ");
    strcat(auth_header, token);

    json_object_put(parsed_json);
    free(data->memory);
    data->memory = NULL;
    data->size = 0;
    return auth_header;
}

char *erofs_oci_registry_get_image_index(struct erofs_oci_registry_memory *data, const char *arch, const char *os, char *mediaType) {
    if (data->memory == NULL) {
        fprintf(stderr, "No data receive\n");
        return NULL;
    }

    json_object *parsed_json = json_tokener_parse(data->memory);
    if (parsed_json == NULL) {
        fprintf(stderr, "Parse JSON failed\n");
        return NULL;
    }

    json_object *manifests_array;
    if (!json_object_object_get_ex(parsed_json, "manifests", &manifests_array)) {
        fprintf(stderr, "Can not JSON find manifests\n");
        json_object_put(parsed_json);
        return NULL;
    }

    int len = json_object_array_length(manifests_array);
    for (int i = 0; i < len; i++) {
        json_object *manifest = json_object_array_get_idx(manifests_array, i);
        json_object *platform_json;
        
        if (json_object_object_get_ex(manifest, "platform", &platform_json)) {
            json_object *arch_json, *os_json, *digest_json, *mediaType_json;
            
            if (json_object_object_get_ex(platform_json, "architecture", &arch_json) &&
                json_object_object_get_ex(platform_json, "os", &os_json) &&
                json_object_object_get_ex(manifest, "digest", &digest_json)) {
                
                const char *manifest_arch = json_object_get_string(arch_json);
                const char *manifest_os = json_object_get_string(os_json);

                if (strcmp(manifest_arch, arch) == 0 && strcmp(manifest_os, os) == 0) {
                    char *digest = strdup(json_object_get_string(digest_json));
                    if (json_object_object_get_ex(manifest, "mediaType", &mediaType_json)) {
                        const char* manifest_mediaType = json_object_get_string(mediaType_json);
                        sprintf(mediaType, "Accept: %s", manifest_mediaType);
                    }
                    json_object_put(parsed_json);
                    free(data->memory);
                    data->memory = NULL;
                    data->size = 0;
                    return digest;
                }
            }
        }
    }

    json_object_put(parsed_json);
    free(data->memory);
    data->memory = NULL;
    data->size = 0;

    fprintf(stderr, "Not find matched arch and os\n");
    return NULL;
}

char* erofs_oci_registry_get_manifest(struct erofs_oci_registry_memory *data, char *mediaType, int count) {
    json_object *parsed_json = json_tokener_parse(data->memory);
    if (!parsed_json) {
        fprintf(stderr, "Failed to parse JSON\n");
        return NULL;
    }

    json_object *layers_array;
    if (!json_object_object_get_ex(parsed_json, "layers", &layers_array) || 
        json_object_get_type(layers_array) != json_type_array) {
        fprintf(stderr, "Layers key not found or is not an array in JSON\n");
        json_object_put(parsed_json);
        return NULL;
    }

    int len = json_object_array_length(layers_array);
    if (count < 0 || count >= len) {
        fprintf(stderr, "Count %d is out of bounds (0-%d)\n", count, len - 1);
        json_object_put(parsed_json);
        return NULL;
    }

    json_object *layer = json_object_array_get_idx(layers_array, count);
    json_object *digest_json, *mediaType_json;
    char *digest = NULL;
    if (!json_object_object_get_ex(layer, "digest", &digest_json))
        fprintf(stderr, "Digest not found in layer #%d\n", count);
    else {
        digest = strdup(json_object_get_string(digest_json));
        if (json_object_object_get_ex(layer, "mediaType", &mediaType_json)) {
            const char* manifest_mediaType = json_object_get_string(mediaType_json);
            sprintf(mediaType, "Accept: %s", manifest_mediaType);
        }
    }

    json_object_put(parsed_json);
    return digest;
}

void erofs_oci_registry_curl_io(CURLM *multi_handle, int *still_running) {
    CURLMcode mc;
    do {
        mc = curl_multi_perform(multi_handle, still_running);
        if (mc != CURLM_OK) {
            fprintf(stderr, "curl_multi_perform() failed: %s\n", curl_multi_strerror(mc));
            break;
        }
        if (*still_running) {
            int numfds;
            mc = curl_multi_poll(multi_handle, NULL, 0, 1000, &numfds);
            if (mc != CURLM_OK) {
                fprintf(stderr, "curl_multi_poll failed: %s\n", curl_multi_strerror(mc));
                break;
            }
        }
    } while (*still_running > 0);
}

struct erofs_oci_registry_memory* erofs_oci_registry_curl_setopt(CURLM *multi_handle, CURL* curl, const char* auth_header, const char* mediaType, const char* url, int mode){
    struct erofs_oci_registry_memory *data = malloc(sizeof(struct erofs_oci_registry_memory));
    struct curl_slist *headers = NULL;
    if (data == NULL) {
        fprintf(stderr, "Failed to allocate memory for erofs_oci_registry_memory\n");
        return NULL;
    }
    data->memory = NULL;
    data->size = 0;
    switch (mode)
    {
        case TOKEN_MODE:
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, erofs_oci_registry_write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_multi_add_handle(multi_handle, curl);
            break;
        case IMAGE_INDEX_MODE:
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, erofs_oci_registry_write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data);
            headers = curl_slist_append(headers, auth_header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_multi_add_handle(multi_handle, curl);
            break;
        case MANIFEST_MODE:
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, erofs_oci_registry_write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data);
            headers = curl_slist_append(headers, auth_header);
            headers = curl_slist_append(headers, mediaType);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_multi_add_handle(multi_handle, curl);		
            break;
        case BLOB_MODE:
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, erofs_oci_registry_write_callback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)data);
            headers = curl_slist_append(headers, auth_header);
            headers = curl_slist_append(headers, mediaType);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_multi_add_handle(multi_handle, curl);
            break;
        default:
            break;
    }
    return data;
}

struct erofs_vfile* open_oci_registry(const char* url) {
    char url_front[256];
    char repository[256];
    char arch[256];
    char os[256];
    char digest_value[128];
    char mediaType_value[512];
    char mediaType_blob[512];
    char url_blob[512];
    int digest = 0;
    int still_running;
    int mode = 0;

    const char* repo_start = strstr(url, "/library/");
    if (repo_start == NULL) {
        printf("Invalid URL: missing /library/\n");
        return NULL;
    }
    repo_start += strlen("/library/");

    const char* repo_end = strchr(repo_start, '/');
    if (repo_end == NULL) {
        printf("Invalid URL: missing repository name\n");
        return NULL;
    }
    
    strncpy(repository, repo_start, repo_end - repo_start);
    repository[repo_end - repo_start] = '\0';

    strncpy(url_front, url, repo_start - url);
    url_front[repo_start - url] = '\0';

    char url_token[512];
    snprintf(url_token, sizeof(url_token), "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/%s:pull", repository);
    CURL* curl_token = curl_easy_init();
    struct erofs_oci_registry_memory* data_token = erofs_oci_registry_curl_setopt(erofs_oci_registry_get_multi_handle(), curl_token, NULL, NULL, url_token, TOKEN_MODE);
    erofs_oci_registry_curl_io(erofs_oci_registry_get_multi_handle(), &still_running);
    char *token_header = erofs_oci_registry_get_token(data_token);
    curl_multi_remove_handle(erofs_oci_registry_get_multi_handle(), curl_token);
    curl_easy_cleanup(curl_token);
    if (data_token) 
        free(data_token);

    const char* blob_start = strstr(repo_end, "/blobs/");
    if (blob_start != NULL) {
        const char* digest_start = blob_start + strlen("/blobs/");
        const char* digest_end = strchr(digest_start, '/');
        if (digest_end == NULL)
            digest_end = digest_start + strlen(digest_start);

        strncpy(digest_value, digest_start, digest_end - digest_start);
        digest_value[digest_end - digest_start] = '\0';

        const char* mediaType_start = strstr(digest_end, "Accept: ");
        if (mediaType_start != NULL) 
            strcpy(mediaType_value, mediaType_start);
        else 
            strcpy(mediaType_value, "");

        snprintf(url_blob, sizeof(url_blob), "%s%s/blobs/%s", url_front, repository, digest_value);
        mode = 1;
        goto pull_blob_mode;
    } 
    else {
        strcpy(arch, "amd64");
        strcpy(os, "linux");
        digest = 0;

        const char* params = repo_end + 1;
        while (params && *params != '\0') {
            if (strncmp(params, "arch-", 5) == 0) {
                params += 5;
                const char* param_end = strchr(params, '/');
                if (param_end) {
                    strncpy(arch, params, param_end - params);
                    arch[param_end - params] = '\0';
                    params = param_end + 1;
                } else {
                    strcpy(arch, params);
                    break;
                }
            } else if (strncmp(params, "os-", 3) == 0) {
                params += 3;
                const char* param_end = strchr(params, '/');
                if (param_end) {
                    strncpy(os, params, param_end - params);
                    os[param_end - params] = '\0';
                    params = param_end + 1;
                } else {
                    strcpy(os, params);
                    break;
                }
            } else if (strncmp(params, "digest-", 7) == 0) {
                params += 7;
                digest = atoi(params) - 1;
                break;
            } else {
                params = strchr(params, '/');
                if (params) 
                    params++;
            }
        }
	/*
        printf("URL Front: %s\n", url_front);
        printf("Repository: %s\n", repository);
        printf("Arch: %s\n", arch);
        printf("OS: %s\n", os);
        printf("Digest: %d\n", digest);
	*/
        char url_image_index[512], mediaType[512];
        snprintf(url_image_index, sizeof(url_image_index), "%s%s/manifests/latest", url_front, repository);
        CURL* curl_image_index = curl_easy_init();
        struct erofs_oci_registry_memory* data_image_index = erofs_oci_registry_curl_setopt(erofs_oci_registry_get_multi_handle(), curl_image_index, token_header, NULL, url_image_index, IMAGE_INDEX_MODE);
        erofs_oci_registry_curl_io(erofs_oci_registry_get_multi_handle(), &still_running);
        char* digest_image_index = erofs_oci_registry_get_image_index(data_image_index, arch, os, mediaType);
        if (data_image_index) 
            free(data_image_index);
        
        curl_multi_remove_handle(erofs_oci_registry_get_multi_handle(), curl_image_index);
        curl_easy_cleanup(curl_image_index);

        char url_manifest[512];
        snprintf(url_manifest, sizeof(url_manifest), "%s%s/manifests/%s", url_front, repository, digest_image_index);
        if (digest_image_index) 
            free(digest_image_index);
        
        CURL* curl_manifest = curl_easy_init();
        struct erofs_oci_registry_memory* data_manifest = erofs_oci_registry_curl_setopt(erofs_oci_registry_get_multi_handle(), curl_manifest, token_header, mediaType, url_manifest, MANIFEST_MODE);
        erofs_oci_registry_curl_io(erofs_oci_registry_get_multi_handle(), &still_running);
        char* digest_manifest = erofs_oci_registry_get_manifest(data_manifest, mediaType_blob, digest);
        if (data_manifest) 
            free(data_manifest);
        
        curl_multi_remove_handle(erofs_oci_registry_get_multi_handle(), curl_manifest);
        curl_easy_cleanup(curl_manifest);

        snprintf(url_blob, sizeof(url_blob), "%s%s/blobs/%s", url_front, repository, digest_manifest);
        if (digest_manifest) 
            free(digest_manifest);
    }

pull_blob_mode:
    CURL* curl_blob = curl_easy_init();
    struct erofs_oci_registry_memory* data_blob;
    if (mode == 1)
        data_blob = erofs_oci_registry_curl_setopt(erofs_oci_registry_get_multi_handle(), curl_blob, token_header, mediaType_value, url_blob, BLOB_MODE);
    else
        data_blob = erofs_oci_registry_curl_setopt(erofs_oci_registry_get_multi_handle(), curl_blob, token_header, mediaType_blob, url_blob, BLOB_MODE);
    
    erofs_oci_registry_curl_io(erofs_oci_registry_get_multi_handle(), &still_running); 
    curl_multi_remove_handle(erofs_oci_registry_get_multi_handle(), curl_blob);
    curl_easy_cleanup(curl_blob);

    struct erofs_vfile* vf = malloc(sizeof(struct erofs_vfile));
    vf->ops = malloc(sizeof(struct erofs_vfops));
    vf->ops->read = oci_registry_read;
    vf->ops->pread = oci_registry_pread;
    vf->ops->lseek = oci_registry_lseek;
    *((struct erofs_oci_registry_memory**)(vf->payload)) = data_blob;

    if (mode == 1) {
    /*
        printf("Digest: %s\n", digest_value);
        printf("MediaType: %s\n", mediaType_value);
        printf("URL Blob: %s\n", url_blob);
    */
        printf("%s is open\n",repository);
    
        return vf;
    }
    
    
    
    if (token_header) 
        free(token_header);
    printf("%s is open\n",repository);
    return vf;
}

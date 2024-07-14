// -*- coding: utf-8 -*-
#define _CRT_SECURE_NO_WARNINGS
#define _TIMESPEC_DEFINED

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <wchar.h>
#include <locale.h>

#define MAX_PLAYERS 10
#define MAX_THREADS 10



// 区分操作系统
#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#else
#include <unistd.h>
#include <uuid/uuid.h>
#define _strdup strdup
#define sprintf_s snprintf
#define strtok_s strtok_r
#define scanf_s scanf
#define sscanf_s sscanf
#define _countof(arr) (sizeof(arr) / sizeof(arr[0]))
//本地化函数
int strcpy_s(char* dest, size_t destsz, const char* src) {
    if (dest == NULL || src == NULL) {
        return 2;
    }
    if (destsz == 0) {
        return 2;
    }

    size_t src_len = strlen(src);


    if (src_len >= destsz) {
        if (destsz > 0) {

            strncpy(dest, src, destsz - 1);
            dest[destsz - 1] = '\0';
        }
        return 80;
    }

    strcpy(dest, src);
    return 0;
}
#endif
//保存配置
int save_config_json(const char* filename, long long gameID, int operation, const char* sessionId, int* numbers, int count) {
    json_t* root = json_object();

    json_object_set_new(root, "gameID", json_integer(gameID));
    json_object_set_new(root, "operation", json_integer(operation));
    json_object_set_new(root, "sessionId", json_string(sessionId));
    json_object_set_new(root, "count", json_integer(count));

    json_t* numbers_array = json_array();
    for (int i = 0; i < count; i++) {
        json_array_append_new(numbers_array, json_integer(numbers[i]));
    }
    json_object_set_new(root, "numbers", numbers_array);

    if (json_dump_file(root, filename, JSON_INDENT(4)) != 0) {
        perror("Failed to save JSON config file");
        json_decref(root);
        return -1;  // 返回-1表示失败
    }

    json_decref(root);
    return 0;  // 返回0表示成功
}
//读取配置
int read_config_json(const char* filename, long long* gameID, int* operation, char* sessionId, int* numbers, int* count) {
    json_error_t error;
    json_t* root = json_load_file(filename, 0, &error);

    if (!root) {
        fprintf(stderr, "Error loading JSON: %s\n", error.text);
        return -1;  // 返回-1表示失败
    }

    *gameID = json_integer_value(json_object_get(root, "gameID"));
    *operation = json_integer_value(json_object_get(root, "operation"));
    strncpy(sessionId, json_string_value(json_object_get(root, "sessionId")), 100);

    *count = json_integer_value(json_object_get(root, "count"));
    json_t* numbers_array = json_object_get(root, "numbers");
    for (int i = 0; i < *count; i++) {
        numbers[i] = json_integer_value(json_array_get(numbers_array, i));
    }

    json_decref(root);
    return 0;  // 返回0表示成功
}
// 定义一个未使用的线程ID的常量
const pthread_t THREAD_ID_UNUSED = { 0 };
long long gameID;  // 用于存储游戏ID
// 监控参数结构体
typedef struct {
    pthread_t threadId;
    unsigned long long  playerid[MAX_PLAYERS];
    unsigned int teamid[MAX_PLAYERS];
    int count;
} MonitorArgs;

// 全局变量
char url[256];     // 用于存储生成的URL
char sessionId[100] = "";
pthread_mutex_t lock;
pthread_cond_t cond;
MonitorArgs monitorArgsArray[MAX_THREADS];
int activeThreads = 0;
int liveflag = 1;
int jiankongflag = 0;
int attackwinflag = 0;
int createflag = 1;
int operation = 0;
const char* MAP_NAME[10] = {
    "加利西亞",
    "凡爾登高地",
    "海麗斯岬",
    "蘇伊士",
    "蘇瓦松",
    "窩瓦河",
    "流血宴廳",
    "聖康坦的傷痕",
    "法歐堡",
    "格拉巴山"
};

typedef struct {
    char* mapPrettyName;
    char* modePrettyName;
    int mapId;
} MapItem;

typedef struct {
    char* serverId;
    char* persistedGameId;
    MapItem* maps;
    size_t num_maps;
} ServerDetails;

typedef struct {
    ServerDetails serverDetails;
} FullServerDetails;

// 用于存储从HTTP响应中接收到的数据
struct MemoryStruct {
    char* memory;
    size_t size;
};

// 解析响应并返回数据结构的声明
typedef struct {
    int rank;
    char* name;
    char* platoon;
    unsigned long long playerid;  // 使用无符号长整型
} PlayerInfo;

typedef struct {
    char* teamid;
    PlayerInfo* players; // 动态数组
    size_t player_count;
} TeamInfo;

typedef struct {
    char* name;
    char* description;
    char* region;
    TeamInfo* teams; // 动态数组
    size_t team_count;
} ServerInfoRoot;
// 结构体用于存储响应内容
typedef struct {
    char* content; // 存储返回的JSON字符串或错误消息
    int is_success;
    double exec_time;
} RespContent;


// 结构体用于从CURL接收数据的回调
struct string {
    char* ptr;
    size_t len;
};
//缓存
ServerInfoRoot* cachedServerInfo = NULL;
int cacheValid = 0;
pthread_mutex_t cacheMutex = PTHREAD_MUTEX_INITIALIZER;

// 解析地图
int parse_maps(json_t* json_array, ServerDetails* serverDetails) {
    size_t index;
    json_t* value;
    MapItem* map;

    serverDetails->num_maps = json_array_size(json_array);
    serverDetails->maps = malloc(serverDetails->num_maps * sizeof(MapItem));
    if (!serverDetails->maps) {
        return -1; // 内存分配失败
    }

    json_array_foreach(json_array, index, value) {
        map = &serverDetails->maps[index];
        map->mapPrettyName = _strdup(json_string_value(json_object_get(value, "mapPrettyName")));
        map->modePrettyName = _strdup(json_string_value(json_object_get(value, "modePrettyName")));
        map->mapId = index;
    }

    return 0;
}

// 解析完整服务器详情
int parse_full_server_details(const char* text, FullServerDetails* details) {
    json_t* root;
    json_error_t error;
    json_t* result, * serverInfo, * maps;

    root = json_loads(text, 0, &error);
    if (!root) {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return 1;
    }

    result = json_object_get(root, "result");
    serverInfo = json_object_get(result, "serverInfo");
    details->serverDetails.serverId = _strdup(json_string_value(json_object_get(serverInfo, "guid")));
    details->serverDetails.persistedGameId = _strdup(json_string_value(json_object_get(serverInfo, "gameId")));

    maps = json_object_get(serverInfo, "rotation");
    if (parse_maps(maps, &details->serverDetails) != 0) {
        json_decref(root);
        return -1; // 解析地图信息失败
    }

    json_decref(root);
    return 0;
}

// 清理内存
void free_full_server_details(FullServerDetails* details) {
    if (details == NULL) return;

    free(details->serverDetails.serverId);
    free(details->serverDetails.persistedGameId);

    for (size_t i = 0; i < details->serverDetails.num_maps; i++) {
        free(details->serverDetails.maps[i].mapPrettyName);
        free(details->serverDetails.maps[i].modePrettyName);
    }
    free(details->serverDetails.maps);
}

//uuid生成
void generate_uuid_v4(char* uuid) {
#ifdef __linux__
    uuid_t binuuid;
    uuid_generate_random(binuuid);
    uuid_unparse(binuuid, uuid);
#else
    // 生成一个包含128位随机数的数组
    unsigned char uuid_bytes[16];
    for (int i = 0; i < 16; i++) {
        uuid_bytes[i] = rand() % 256;
    }

    // 设置版本号到第13位(版本4)
    uuid_bytes[6] = (uuid_bytes[6] & 0x0F) | 0x40; // 版本4

    // 设置变体位到第17位
    uuid_bytes[8] = (uuid_bytes[8] & 0x3F) | 0x80; // 变体1

    // 转换成UUID的字符串形式
    sprintf_s(uuid, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
        uuid_bytes[4], uuid_bytes[5], uuid_bytes[6], uuid_bytes[7],
        uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
        uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]);
#endif
}



// 初始化动态字符串结构体
void init_string(struct string* s) {
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

// CURL写入回调函数
size_t writefunc(void* ptr, size_t size, size_t nmemb, struct string* s) {
    size_t new_len = s->len + size * nmemb;
    s->ptr = realloc(s->ptr, new_len + 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}

// 发送请求并获取响应
RespContent GetFullServerDetails(const char* sessionId, long long gameId) {

    clock_t start_time = clock();
    RespContent respContent = { 0 };
    struct string s;
    init_string(&s);

    CURL* curl = curl_easy_init();
    if (curl) {
        // 创建JSON对象
        json_t* root = json_object();
        json_object_set_new(root, "jsonrpc", json_string("2.0"));
        json_object_set_new(root, "method", json_string("GameServer.getFullServerDetails"));


        json_t* params = json_object();
        json_object_set_new(params, "game", json_string("tunguska"));
        json_object_set_new(params, "gameId", json_integer(gameId));
        json_object_set_new(root, "params", params);

        //UUID
        char uuid[37];
        generate_uuid_v4(uuid); // 生成uuid
        json_object_set_new(root, "id", json_string(uuid));


        char* requestData = json_dumps(root, JSON_ENCODE_ANY);

        // 设置HTTP头部，包括Session ID
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        char session_header[256];
        snprintf(session_header, sizeof(session_header), "X-GatewaySession: %s", sessionId);
        headers = curl_slist_append(headers, session_header);

        // 打印HTTP头部信息以便调试
        struct curl_slist* temp_headers = headers;
        printf("HTTP Headers:\n");
        while (temp_headers) {
            printf("%s\n", temp_headers->data);
            temp_headers = temp_headers->next;
        }
        // 打印生成的JSON请求体以便调试
        printf("Request JSON Body:\n%s\n", requestData);

        // 设置CURL选项
        curl_easy_setopt(curl, CURLOPT_URL, "https://sparta-gw.battlelog.com/jsonrpc/pc/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestData);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers); // Set the headers for the request


        // 执行请求
        CURLcode res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            respContent.content = _strdup(s.ptr);
            respContent.is_success = 1;
        }
        else {
            respContent.content = _strdup(curl_easy_strerror(res));
            respContent.is_success = 0;
        }

        // 清理
        free(requestData);
        json_decref(root);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(s.ptr);


    }
    else {
        free(s.ptr);
        respContent.is_success = 0;
        respContent.content = _strdup("CURL failed");
    }

    // 计时结束并返回结果
    clock_t end_time = clock();
    respContent.exec_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;


    return respContent;
}



// 用于接收响应的回调函数
size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t real_size = size * nmemb;
    RespContent* resp = (RespContent*)userp;

    // 检查resp->content是否为NULL
    size_t old_len = resp->content ? strlen(resp->content) : 0;

    char* new_content = realloc(resp->content, old_len + real_size + 1);
    if (!new_content) {
        printf("Memory allocation failed\n");
        return 0; // 返回0，CURL会停止传输
    }
    resp->content = new_content;
    memcpy(&(resp->content[old_len]), contents, real_size);
    resp->content[old_len + real_size] = '\0';
    return real_size;
}


// 换图
RespContent RSPChooseLevel(const char* sessionId, const char* persistedGameId, int levelIndex) {
    clock_t start_time = clock();
    RespContent respContent;
    respContent.content = NULL;  // 初始化为空指针
    respContent.is_success = 0;

    CURL* curl = curl_easy_init();
    if (curl) {
        // 使用jansson创建JSON对象
        json_t* root = json_object();
        json_object_set_new(root, "jsonrpc", json_string("2.0"));
        json_object_set_new(root, "method", json_string("RSP.chooseLevel"));
        json_t* params = json_object();
        json_object_set_new(params, "game", json_string("tunguska"));
        json_object_set_new(params, "persistedGameId", json_string(persistedGameId));
        json_object_set_new(params, "levelIndex", json_integer(levelIndex));
        json_object_set_new(root, "params", params);

        uuid_t binuuid;         // UUID类型
        char uuid[37];          // 用来存储UUID字符串的数组

        // 初始化binuuid数组为0
        memset(&binuuid, 0, sizeof(binuuid));

        generate_uuid_v4(uuid);
        srand((unsigned int)time(NULL)); // 初始化随机数生成器


        json_object_set_new(root, "id", json_string(uuid));

        // 将JSON对象转换为字符串
        char* json_data = json_dumps(root, 0);

        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        char session_header[256];
        sprintf_s(session_header, sizeof(session_header), "X-GatewaySession: %s", sessionId);
        headers = curl_slist_append(headers, session_header);

        curl_easy_setopt(curl, CURLOPT_URL, "https://sparta-gw.battlelog.com/jsonrpc/pc/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&respContent);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            // 检查错误代码
            switch (res) {
            case CURLE_COULDNT_CONNECT:
            case CURLE_HTTP_RETURNED_ERROR:
                fprintf(stderr, "Network or remote server error.\n");
                break;
            case CURLE_OUT_OF_MEMORY:
                fprintf(stderr, "Out of memory error.\n");
                break;
            default:
                fprintf(stderr, "Other error: %d\n", res);
                break;
            }
        }
        else {
            long response_code;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            if (response_code == 200) {
                respContent.is_success = 1;
            }
        }

        // 清理

        free(json_data);  // 释放动态分配的内存,不知道为什么必须第一个清理
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        json_decref(root);

    }

    clock_t end_time = clock();
    respContent.exec_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;

    return respContent;
}
//系统代理
void set_system_proxy(CURL* curl) {
#ifdef _WIN32
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;

    if (WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig)) {
        if (proxyConfig.lpszProxy) {
            // Convert wide-char string to multibyte string
            int len = WideCharToMultiByte(CP_ACP, 0, proxyConfig.lpszProxy, -1, NULL, 0, NULL, NULL);
            char* proxy = (char*)malloc(len);
            WideCharToMultiByte(CP_ACP, 0, proxyConfig.lpszProxy, -1, proxy, len, NULL, NULL);

            curl_easy_setopt(curl, CURLOPT_PROXY, proxy);
            curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            printf("Using system proxy: %s\n", proxy);

            free(proxy);
            GlobalFree(proxyConfig.lpszProxy);
        }
        if (proxyConfig.lpszProxyBypass) {
            GlobalFree(proxyConfig.lpszProxyBypass);
        }
        if (proxyConfig.lpszAutoConfigUrl) {
            GlobalFree(proxyConfig.lpszAutoConfigUrl);
        }
    }
    else {
        printf("No system proxy found.\n");
    }
#else
    const char* http_proxy = getenv("http_proxy");
    const char* https_proxy = getenv("https_proxy");
    if (https_proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, https_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        printf("Using system HTTPS proxy: %s\n", https_proxy);
    }
    else if (http_proxy) {
        curl_easy_setopt(curl, CURLOPT_PROXY, http_proxy);
        curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
        printf("Using system HTTP proxy: %s\n", http_proxy);
}
    else {
        printf("No system proxy found.\n");
    }
#endif
}



size_t WriteMemoryCallback(void* contents, size_t size, size_t nmemb, struct MemoryStruct* userp) {
    size_t realsize = size * nmemb;
    char* ptr = realloc(userp->memory, userp->size + realsize + 1);
    if (ptr == NULL) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0;  // 返回0
    }
    userp->memory = ptr;  // 更新内存指针
    memcpy(&(userp->memory[userp->size]), contents, realsize);
    userp->size += realsize;
    userp->memory[userp->size] = '\0';

    return realsize;
}

void httpGetRequest(const char* url, struct MemoryStruct* chunk) {
    CURL* curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)chunk);

        // Enable SSL/TLS verification
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        // Set system proxy
        set_system_proxy(curl);

        // Enable verbose output for debugging
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        // Set timeout options (optional)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);  // Timeout after 10 seconds

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
    }
}
// 释放 ServerInfoRoot 结构体的内存
void free_server_info_error(ServerInfoRoot* serverInfo) {
    if (!serverInfo) return;

    if (serverInfo->name) free(serverInfo->name);
    if (serverInfo->description) free(serverInfo->description);
    if (serverInfo->region) free(serverInfo->region);

    for (size_t i = 0; i < serverInfo->team_count; i++) {
        if (serverInfo->teams[i].teamid) free(serverInfo->teams[i].teamid);
        for (size_t j = 0; j < serverInfo->teams[i].player_count; j++) {
            if (serverInfo->teams[i].players[j].name) free(serverInfo->teams[i].players[j].name);
            if (serverInfo->teams[i].players[j].platoon) free(serverInfo->teams[i].players[j].platoon);
        }
        if (serverInfo->teams[i].players) free(serverInfo->teams[i].players);
    }

    if (serverInfo->teams) free(serverInfo->teams);
    free(serverInfo);
}
// JSON 解析函数
ServerInfoRoot* parse_server_info(const char* json_text) {
    printf("0 ok\n");
    json_error_t error;
    json_t* root = json_loads(json_text, 0, &error);
    if (!root) {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return NULL;
    }

    ServerInfoRoot* serverInfo = malloc(sizeof(ServerInfoRoot));
    if (!serverInfo) {
        json_decref(root);
        return NULL;
    }

    serverInfo->name = NULL;
    serverInfo->description = NULL;
    serverInfo->region = NULL;
    serverInfo->teams = NULL;

    const char* name = json_string_value(json_object_get(root, "name"));
    serverInfo->name = name ? _strdup(name) : NULL;
    if (name && !serverInfo->name) {
        fprintf(stderr, "error: strdup failed for name\n");
        free_server_info_error(serverInfo);
        json_decref(root);
        return NULL;
    }
    printf("1 ok\n");

    const char* description = json_string_value(json_object_get(root, "description"));
    serverInfo->description = description ? _strdup(description) : NULL;
    if (description && !serverInfo->description) {
        fprintf(stderr, "error: strdup failed for description\n");
        free_server_info_error(serverInfo);
        json_decref(root);
        return NULL;
    }
    printf("2 ok\n");

    const char* region = json_string_value(json_object_get(root, "region"));
    serverInfo->region = region ? _strdup(region) : NULL;
    if (region && !serverInfo->region) {
        fprintf(stderr, "error: strdup failed for region\n");
        free_server_info_error(serverInfo);
        json_decref(root);
        return NULL;
    }
    printf("3 ok\n");

    json_t* teams = json_object_get(root, "teams");
    if (!teams || !json_is_array(teams)) {
        fprintf(stderr, "error: teams is not an array\n");
        free_server_info_error(serverInfo);
        json_decref(root);
        return NULL;
    }
    serverInfo->team_count = json_array_size(teams);
    serverInfo->teams = malloc(sizeof(TeamInfo) * serverInfo->team_count);
    if (!serverInfo->teams) {
        fprintf(stderr, "error: malloc failed for teams\n");
        free_server_info_error(serverInfo);
        json_decref(root);
        return NULL;
    }

    for (size_t i = 0; i < serverInfo->team_count; i++) {
        json_t* team = json_array_get(teams, i);
        if (!team || !json_is_object(team)) {
            fprintf(stderr, "error: team is not an object\n");
            continue;  // Skip this invalid team
        }
        const char* teamid = json_string_value(json_object_get(team, "teamid"));
        serverInfo->teams[i].teamid = teamid ? _strdup(teamid) : NULL;
        if (teamid && !serverInfo->teams[i].teamid) {
            fprintf(stderr, "error: strdup failed for teamid\n");
            continue;  // Skip this invalid teamid allocation
        }
        printf("4 ok\n");

        json_t* players = json_object_get(team, "players");
        if (!players || !json_is_array(players)) {
            fprintf(stderr, "error: players is not an array\n");
            serverInfo->teams[i].player_count = 0;
            serverInfo->teams[i].players = NULL;
            continue;  // Skip this invalid players array
        }
        serverInfo->teams[i].player_count = json_array_size(players);
        serverInfo->teams[i].players = malloc(sizeof(PlayerInfo) * serverInfo->teams[i].player_count);
        if (!serverInfo->teams[i].players) {
            fprintf(stderr, "error: malloc failed for players\n");
            serverInfo->teams[i].player_count = 0;
            continue;  // Skip this invalid players allocation
        }

        for (size_t j = 0; j < serverInfo->teams[i].player_count; j++) {
            json_t* player = json_array_get(players, j);
            if (!player || !json_is_object(player)) {
                fprintf(stderr, "error: player is not an object\n");
                continue;  // Skip this invalid player
            }
            const char* player_name = json_string_value(json_object_get(player, "name"));
            serverInfo->teams[i].players[j].name = player_name ? _strdup(player_name) : NULL;
            if (player_name && !serverInfo->teams[i].players[j].name) {
                fprintf(stderr, "error: strdup failed for player_name\n");
                continue;  // Skip this invalid player_name allocation
            }
            printf("5 ok\n");

            serverInfo->teams[i].players[j].rank = json_integer_value(json_object_get(player, "rank"));

            json_t* player_id_json = json_object_get(player, "player_id");
            json_int_t temp_id = json_integer_value(player_id_json);
            unsigned long long player_id = 0;

            if (temp_id < 0) {
                player_id = (unsigned long long)((json_int_t)(-1) - temp_id + 1);
            }
            else {
                player_id = (unsigned long long)temp_id;
            }

            serverInfo->teams[i].players[j].playerid = player_id;

            const char* platoon = json_string_value(json_object_get(player, "platoon"));
            serverInfo->teams[i].players[j].platoon = platoon ? _strdup(platoon) : NULL;
            if (platoon && !serverInfo->teams[i].players[j].platoon) {
                fprintf(stderr, "error: strdup failed for platoon\n");
                continue;  // Skip this invalid platoon allocation
            }
            printf("6 ok\n");
        }
    }

    json_decref(root);
    return serverInfo;
}
void* threadFunction(void* arg) {
    // 线程代码
    return NULL;
}

// 控制台输出玩家列表
void printPlayerList(ServerInfoRoot* serverInfo) {
    if (!serverInfo) return;

    printf("Server: %s\nDescription: %s\nRegion: %s\n", serverInfo->name, serverInfo->description, serverInfo->region);

    for (size_t i = 0; i < serverInfo->team_count; i++) {
        printf("\nTeam: %s\n", serverInfo->teams[i].teamid);
        for (size_t j = 0; j < serverInfo->teams[i].player_count; j++) {
            PlayerInfo player = serverInfo->teams[i].players[j];
            printf("Player Name: %s, Rank: %d, Platoon: %s , playerid:%lld\n", player.name, player.rank, player.platoon, player.playerid);
        }
    }
}

// 清理内存
void free_server_info(ServerInfoRoot* serverInfo) {
    if (!serverInfo) return;

    free(serverInfo->name);
    free(serverInfo->description);
    free(serverInfo->region);
    for (size_t i = 0; i < serverInfo->team_count; i++) {
        free(serverInfo->teams[i].teamid);
        for (size_t j = 0; j < serverInfo->teams[i].player_count; j++) {
            free(serverInfo->teams[i].players[j].name);
            free(serverInfo->teams[i].players[j].platoon);
        }
        free(serverInfo->teams[i].players);
    }
    free(serverInfo->teams);
    free(serverInfo);
}




void init_memory_struct(struct MemoryStruct* mem) {
    mem->memory = malloc(1);  // 初始分配1字节，realloc将调整大小
    mem->size = 0;           // 初始大小为0
}
struct GameStats {
    int roundsPlayed;
    int wins;
    int losses;
    int kills;
    int deaths;
};
// 进行HTTP请求，并解析响应以获取游戏战绩
struct GameStats get_game_stats(const char* sessionId, long long personaId) {
    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;
    init_memory_struct(&chunk);

    struct GameStats stats = { 0, 0, 0 }; // 初始化为0

    curl = curl_easy_init();
    if (curl) {
        char postFields[1024];
        snprintf(postFields, sizeof(postFields),
            "{\"jsonrpc\": \"2.0\", \"method\": \"Stats.detailedStatsByPersonaId\", "
            "\"params\": {\"game\": \"tunguska\", \"personaId\": %lld}, \"id\": \"1\"}",
            personaId);

        curl_easy_setopt(curl, CURLOPT_URL, "https://sparta-gw.battlelog.com/jsonrpc/pc/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L); // 设置超时为3秒

        char sessionHeader[256];
        snprintf(sessionHeader, sizeof(sessionHeader), "X-GatewaySession: %s", sessionId);
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, sessionHeader);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            // 当发生超时时，清理cURL并返回默认的 stats
            if (res == CURLE_OPERATION_TIMEDOUT) {
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                free(chunk.memory);
                return stats;
            }
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    // 没有超时，继续解析JSON
    json_error_t error;
    json_t* root = json_loads(chunk.memory, 0, &error);
    if (root) {
        json_t* result = json_object_get(root, "result");
        if (result) {
            json_t* roundsPlayedJson = json_object_get(result, "roundsPlayed");
            if (roundsPlayedJson) {
                stats.roundsPlayed = json_integer_value(roundsPlayedJson);
            }

            json_t* basicStats = json_object_get(result, "basicStats");
            if (basicStats) {
                json_t* winsJson = json_object_get(basicStats, "wins");
                if (winsJson) {
                    stats.wins = json_integer_value(winsJson);
                }
                json_t* lossesJson = json_object_get(basicStats, "losses");
                if (lossesJson) {
                    stats.losses = json_integer_value(lossesJson);
                }
                json_t* killJson = json_object_get(basicStats, "kills");
                if (killJson) {
                    stats.kills = json_integer_value(killJson);
                }
                json_t* deathJson = json_object_get(basicStats, "deaths");
                if (deathJson) {
                    stats.deaths = json_integer_value(deathJson);
                }
            }
        }
        json_decref(root);
    }
    else {
        fprintf(stderr, "JSON parsing failed on line %d: %s\n", error.line, error.text);
    }

    free(chunk.memory);
    return stats;
}
//查询玩家正在游玩的服务器
int get_playerplaying(const char* sessionId, long long personaId) {
    CURL* curl;
    CURLcode res;
    struct MemoryStruct chunk;
    init_memory_struct(&chunk);

    unsigned long long nowgameid = 0;
    curl = curl_easy_init();
    if (curl) {
        char postFields[1024];
        snprintf(postFields, sizeof(postFields),
            "{\"jsonrpc\": \"2.0\", \"method\": \"GameServer.getServersByPersonaIds\", "
            "\"params\": {\"game\": \"tunguska\", \"personaIds\": [%lld]}, \"id\": \"1\"}",
            personaId);

        curl_easy_setopt(curl, CURLOPT_URL, "https://sparta-gw.battlelog.com/jsonrpc/pc/api");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L); // 设置超时为3秒

        char sessionHeader[256];
        snprintf(sessionHeader, sizeof(sessionHeader), "X-GatewaySession: %s", sessionId);
        struct curl_slist* headers = NULL;
        headers = curl_slist_append(headers, sessionHeader);
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            // 当发生超时时，清理cURL并返回默认的0
            if (res == CURLE_OPERATION_TIMEDOUT) {
                curl_easy_cleanup(curl);
                curl_slist_free_all(headers);
                free(chunk.memory);
                return 0;
            }
        }

        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
    }

    // 没有超时，继续解析JSON
    json_error_t error;
    json_t* root = json_loads(chunk.memory, 0, &error);
    if (root) {
        // 从root对象中获取result对象
        json_t* result = json_object_get(root, "result");
        if (result) {
            // 将personaId转换为字符串以查找对应的键
            char persona_id_str[21];  // long long最大值为20位数字，外加一个终止符
            snprintf(persona_id_str, sizeof(persona_id_str), "%lld", personaId);

            json_t* player_info = json_object_get(result, persona_id_str);
            if (player_info) {
                json_t* game_id_json = json_object_get(player_info, "gameId");
                if (game_id_json) {
                    const char* game_id_str = json_string_value(game_id_json);
                    if (game_id_str) {
                        nowgameid = atoll(game_id_str);
                    }
                }
            }
        }
        // 释放root对象
        json_decref(root);
    }
    else {
        fprintf(stderr, "JSON parsing failed on line %d: %s\n", error.line, error.text);
    }

    free(chunk.memory);
    if (nowgameid == gameID) {
        return 1;
    }
    else {
        return 0;
    }
}


//深拷贝

ServerInfoRoot* deep_copy_server_info(const ServerInfoRoot* source) {
    if (!source) return NULL;

    ServerInfoRoot* copy = malloc(sizeof(ServerInfoRoot));
    if (!copy) {
        return NULL; // 内存分配失败
    }

    // 复制name
    if (source->name) {
        copy->name = malloc(strlen(source->name) + 1);
        if (!copy->name) {
            free(copy);
            return NULL; // 内存分配失败
        }
        strcpy_s(copy->name, strlen(source->name) + 1, source->name);
    }
    else {
        copy->name = NULL;
    }

    // 复制description
    if (source->description) {
        copy->description = malloc(strlen(source->description) + 1);
        if (!copy->description) {
            free(copy->name);
            free(copy);
            return NULL; // 内存分配失败
        }
        strcpy_s(copy->description, strlen(source->description) + 1, source->description);
    }
    else {
        copy->description = NULL;
    }

    // 复制region
    if (source->region) {
        copy->region = malloc(strlen(source->region) + 1);
        if (!copy->region) {
            free(copy->description);
            free(copy->name);
            free(copy);
            return NULL; // 内存分配失败
        }
        strcpy_s(copy->region, strlen(source->region) + 1, source->region);
    }
    else {
        copy->region = NULL;
    }

    // 复制team_count
    copy->team_count = source->team_count;
    copy->teams = malloc(copy->team_count * sizeof(TeamInfo));
    if (!copy->teams) {
        free(copy->region);
        free(copy->description);
        free(copy->name);
        free(copy);
        return NULL; // 内存分配失败
    }

    for (size_t i = 0; i < copy->team_count; i++) {
        // 复制teamid
        if (source->teams[i].teamid) {
            copy->teams[i].teamid = malloc(strlen(source->teams[i].teamid) + 1);
            if (!copy->teams[i].teamid) {
                for (size_t k = 0; k < i; k++) {
                    free(copy->teams[k].teamid);
                    free(copy->teams[k].players);
                }
                free(copy->teams);
                free(copy->region);
                free(copy->description);
                free(copy->name);
                free(copy);
                return NULL; // 内存分配失败
            }
            strcpy_s(copy->teams[i].teamid, strlen(source->teams[i].teamid) + 1, source->teams[i].teamid);
        }
        else {
            copy->teams[i].teamid = NULL;
        }

        // 复制player_count
        copy->teams[i].player_count = source->teams[i].player_count;
        copy->teams[i].players = malloc(copy->teams[i].player_count * sizeof(PlayerInfo));
        if (!copy->teams[i].players) {
            for (size_t k = 0; k <= i; k++) {
                free(copy->teams[k].teamid);
                free(copy->teams[k].players);
            }
            free(copy->teams);
            free(copy->region);
            free(copy->description);
            free(copy->name);
            free(copy);
            return NULL; // 内存分配失败
        }

        for (size_t j = 0; j < copy->teams[i].player_count; j++) {
            copy->teams[i].players[j].rank = source->teams[i].players[j].rank;
            copy->teams[i].players[j].playerid = source->teams[i].players[j].playerid;

            // 复制name
            if (source->teams[i].players[j].name) {
                copy->teams[i].players[j].name = malloc(strlen(source->teams[i].players[j].name) + 1);
                if (!copy->teams[i].players[j].name) {
                    for (size_t k = 0; k <= i; k++) {
                        for (size_t m = 0; m < copy->teams[k].player_count; m++) {
                            free(copy->teams[k].players[m].name);
                            free(copy->teams[k].players[m].platoon);
                        }
                        free(copy->teams[k].teamid);
                        free(copy->teams[k].players);
                    }
                    free(copy->teams);
                    free(copy->region);
                    free(copy->description);
                    free(copy->name);
                    free(copy);
                    return NULL; // 内存分配失败
                }
                strcpy_s(copy->teams[i].players[j].name, strlen(source->teams[i].players[j].name) + 1, source->teams[i].players[j].name);
            }
            else {
                copy->teams[i].players[j].name = NULL;
            }

            // 复制platoon
            if (source->teams[i].players[j].platoon) {
                copy->teams[i].players[j].platoon = malloc(strlen(source->teams[i].players[j].platoon) + 1);
                if (!copy->teams[i].players[j].platoon) {
                    for (size_t k = 0; k <= i; k++) {
                        for (size_t m = 0; m < copy->teams[k].player_count; m++) {
                            free(copy->teams[k].players[m].name);
                            free(copy->teams[k].players[m].platoon);
                        }
                        free(copy->teams[k].teamid);
                        free(copy->teams[k].players);
                    }
                    free(copy->teams);
                    free(copy->region);
                    free(copy->description);
                    free(copy->name);
                    free(copy);
                    return NULL; // 内存分配失败
                }
                strcpy_s(copy->teams[i].players[j].platoon, strlen(source->teams[i].players[j].platoon) + 1, source->teams[i].players[j].platoon);
            }
            else {
                copy->teams[i].players[j].platoon = NULL;
            }
        }
    }

    return copy;
}
// 函数：将单个字符转换为其十六进制字符串表示
void char_to_hex(char c, char hex[3]) {
    const char* hex_digits = "0123456789ABCDEF";
    hex[0] = hex_digits[(c >> 4) & 0xF]; // 取字符的高四位并转换为十六进制
    hex[1] = hex_digits[c & 0xF];        // 取字符的低四位并转换为十六进制
    hex[2] = '\0';                       // 字符串结束符
}

// 函数：将字符串进行URL编码
void urlencode(const char* input, char* output) {
    int output_index = 0;  // 输出字符串的索引
    for (int i = 0; input[i] != '\0'; i++) {
        // 判断字符是否为字母或数字，或者是其他不需要编码的字符
        if (isalnum(input[i]) || input[i] == '-' || input[i] == '_' || input[i] == '.' || input[i] == '~') {
            output[output_index++] = input[i];  // 直接添加到输出字符串
        }
        else {
            // 对于需要编码的字符
            output[output_index++] = '%';       // 添加百分号
            char hex[3];
            char_to_hex(input[i], hex);         // 转换为十六进制
            output[output_index++] = hex[0];    // 添加十六进制数字
            output[output_index++] = hex[1];
        }
    }
    output[output_index] = '\0';  // 确保输出字符串以空字符结尾
}


// 排名比较函数
int comparePlayersByRank(const void* a, const void* b) {
    const PlayerInfo* playerA = (const PlayerInfo*)a;
    const PlayerInfo* playerB = (const PlayerInfo*)b;
    return playerB->rank - playerA->rank;  // 降序排序
}

// 重置缓存
void invalidateCache() {
    printf("正在重置缓存\n");
    pthread_mutex_lock(&lock);
    printf("重置锁获取成功\n");
    cacheValid = 0;
    if (cachedServerInfo) {
        free_server_info(cachedServerInfo);
        cachedServerInfo = NULL;
    }
    pthread_mutex_unlock(&lock);
    printf("重置锁释放成功\n");
}
// 封装的数据获取和处理函数
void fetchAndDisplayTopPlayers(MonitorArgs* args) {
    pthread_mutex_lock(&cacheMutex);
    if (!cacheValid) {
        struct MemoryStruct chunk = { 0 };
        chunk.memory = malloc(1);
        chunk.size = 0;

        httpGetRequest(url, &chunk);
        if (chunk.memory) {
            if (cachedServerInfo) {
                free_server_info(cachedServerInfo);
            }
            cachedServerInfo = parse_server_info(chunk.memory);
            cacheValid = 1;
            free(chunk.memory);
        }
    }

    if (cachedServerInfo) {
        ServerInfoRoot* serverInfo = deep_copy_server_info(cachedServerInfo);
        pthread_mutex_unlock(&cacheMutex);

        if (serverInfo) {
            int playerIndex = 0;
            int errorcount = 0;
            for (size_t i = 0; i < serverInfo->team_count && playerIndex < MAX_PLAYERS; i++) {
                if (strcmp(serverInfo->teams[i].teamid, "teamOne") == 0 || strcmp(serverInfo->teams[i].teamid, "teamTwo") == 0) {
                    printf("%s", serverInfo->teams[i].teamid);
                    qsort(serverInfo->teams[i].players, serverInfo->teams[i].player_count, sizeof(PlayerInfo), comparePlayersByRank);

                    size_t selectedPlayers = 0;
                    for (size_t j = 0; j < serverInfo->teams[i].player_count && selectedPlayers < 3 && playerIndex < MAX_PLAYERS; j++) {
                        PlayerInfo player = serverInfo->teams[i].players[j];
                        if (player.playerid == 1) {
                            errorcount++;
                            continue;
                        }
                        args->playerid[playerIndex++] = player.playerid;
                        selectedPlayers++;
                        if (strcmp(serverInfo->teams[i].teamid, "teamOne") == 0) {
                            args->teamid[playerIndex - 1] = 1;
                            printf("teamid 1 ok \n");
                        }
                        else if (strcmp(serverInfo->teams[i].teamid, "teamTwo") == 0) {
                            args->teamid[playerIndex - 1] = 2;
                            printf("teamid 2 ok \n");
                        }
                    }
                }
            }
            args->count = playerIndex;
            if (errorcount + playerIndex >= 6 && playerIndex < 6) {
                printf("玩家过少，重新获取列表\n");
                invalidateCache();
            }
            else if (playerIndex == 0) {
                printf("玩家过少，重新获取列表\n");
                invalidateCache();
            }
            free_server_info(serverInfo);
        }
    }
    else {
        pthread_mutex_unlock(&cacheMutex);
    }
}


//更改缓存
void updatePlayerIdToZeroInCache(unsigned long long playerid) {
    printf("正在清除无效玩家\n");
    pthread_mutex_lock(&cacheMutex);
    printf("清除访问锁获取成功\n");
    if (cachedServerInfo) {
        for (size_t i = 0; i < cachedServerInfo->team_count; i++) {
            TeamInfo* team = &cachedServerInfo->teams[i];
            for (size_t j = 0; j < team->player_count; j++) {
                if (team->players[j].playerid == playerid) {
                    team->players[j].playerid = 1;
                    printf("Player ID %llu set to 1 in cache\n", playerid);
                    pthread_mutex_unlock(&cacheMutex);
                    return;
                }
            }
        }
    }
    pthread_mutex_unlock(&cacheMutex);
    printf("清除访问锁释放成功\n");
}



// 监控玩家函数
void* monitor_players(void* arg) {
    int index = *((int*)arg);
    free(arg);

    MonitorArgs* args = &monitorArgsArray[index];
    fetchAndDisplayTopPlayers(args);
    if (args->count == 0) {
        printf("no player\n");
        return NULL;
    }

    int initialCounts[MAX_PLAYERS] = { 0 };
    struct GameStats playerStatsArray[MAX_PLAYERS];
    for (int i = 0; i < args->count; i++) {
        do {
            playerStatsArray[i] = get_game_stats(sessionId, args->playerid[i]);
        } while (!playerStatsArray[i].roundsPlayed && args->playerid[i] != 0);
    }

    time_t start_time = time(NULL);
    while (difftime(time(NULL), start_time) < 30 && liveflag) {
        int increasedCount = 0;
        int team1winincount = 0;
        for (int i = 0; i < args->count; i++) {
            int retry = 2;
            int retrytime = 0;
            do {
                if (get_playerplaying(sessionId, args->playerid[i])) {
                    break;
                }
                retrytime++;
            } while (retrytime <= retry);
            if (retrytime > retry) {
                updatePlayerIdToZeroInCache(args->playerid[i]);
                
                continue;
            }
            retry = 2;
            retrytime = 0;
            do {
                struct GameStats stats = get_game_stats(sessionId, args->playerid[i]);
                if (stats.roundsPlayed != 0) {
                    printf("总数%d", stats.roundsPlayed);
                    printf("胜利%d", stats.wins);
                    printf("失败%d", stats.losses);
                    printf("击杀%d", stats.kills);
                    printf("死亡%d\n", stats.deaths);
                    if (playerStatsArray[i].roundsPlayed < stats.roundsPlayed &&
                        (playerStatsArray[i].kills + playerStatsArray[i].deaths) < (stats.kills + stats.deaths)) {
                        increasedCount++;
                        if (args->teamid[i] == 1 && playerStatsArray[i].wins < stats.wins) {
                            team1winincount++;
                        }
                        else if (args->teamid[i] == 2 && playerStatsArray[i].wins < stats.wins) {
                            team1winincount--;
                        }
                    }
                    break;
                }
                retrytime++;
            } while (retrytime <= retry);
        }
        if (!liveflag) {
            break;
        }
        int playerCountThreshold = args->count <= 3 ? 1 : args->count - 3;
        if (increasedCount >= playerCountThreshold) {
            printf("获取监控锁\n");
            pthread_mutex_lock(&lock);
            if (team1winincount > 0) {
                attackwinflag = 1;
            }
            jiankongflag = 1;
            pthread_mutex_unlock(&lock);
            printf("释放监控锁\n");
            break;
        }
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
    }
    printf("获取监控锁\n");
    pthread_mutex_lock(&lock);
    activeThreads--;
    monitorArgsArray[index].threadId = THREAD_ID_UNUSED;
    pthread_mutex_unlock(&lock);
    printf("释放监控锁\n");

    return NULL;
}

// 控制线程函数
void* thread_controller(void* arg) {
    while (jiankongflag != 2)
    {
        pthread_mutex_lock(&lock);
        if (createflag) {
            if (activeThreads < MAX_THREADS) {
                for (int i = 0; i < MAX_THREADS; i++) {
                    if (pthread_equal(monitorArgsArray[i].threadId, THREAD_ID_UNUSED)) {
                        int* threadIndex = malloc(sizeof(int));
                        if (threadIndex == NULL) {
                            fprintf(stderr, "Error allocating memory.\n");
                            exit(1);
                        }
                        *threadIndex = i;
                        if (pthread_create(&monitorArgsArray[i].threadId, NULL, monitor_players, threadIndex) != 0) {
                            fprintf(stderr, "Error creating thread.\n");
                            free(threadIndex);
                            continue;
                        }
                        activeThreads++;
                        break;
                    }
                }
            }
        }
        pthread_mutex_unlock(&lock);
#ifdef _WIN32
        Sleep(15000);  // Windows中使用Sleep，参数单位为毫秒
#else
        sleep(15);         // UNIX/Linux中使用sleep，参数单位为秒
#endif
    }
    return NULL;
}



int main(void) {
    int numbers[100];
    int count = 0;
    int operationflag = 0;
    gameID = 0;  // 用于存储游戏ID
#ifdef _WIN32
    system("chcp 65001");
#endif
    // 使用JSON
    if (read_config_json("config.json", &gameID, &operationflag,sessionId,numbers, &count) != 0) {
        printf("读取配置文件失败\n");
    }
    else
    {
        printf("读取配置文件成功，如果您想更改设置，请删除配置文件并重启\n");
        goto NEXT;
    }
    


    printf("项目地址:https://github.com/LINGSHI666/changemap\n");
    printf("请输入你的sessionId，可以在服管工具中获取：");
#ifdef _WIN32
    scanf_s("%99s", sessionId, (unsigned)_countof(sessionId));
#else
    scanf("%99s", sessionId);
#endif
   

    long long personaId = 1779148883;
    struct GameStats stats = get_game_stats(sessionId, personaId);
   
    if (stats.roundsPlayed > 1000)
    {
        printf("sessionId有效\n");
    }
    else
    {
        printf("sessionId无效\n");
    }

    // 提示输入gameID
    printf("请输入gameID: ");
#ifdef _WIN32
    if (scanf_s("%lld", &gameID) != 1) {
        printf("输入错误，请输入一个有效的数字。\n");
        return 1;  // 非法输入，提前结束程序
    }
#else
    if(scanf("%lld", &gameID) !=1){
        printf("输入错误，请输入一个有效的数字。\n");
        return 1;  // 非法输入，提前结束程序
    }
#endif
    
    NEXT:;
    // 格式化URL
    sprintf_s(url, sizeof(url), "https://api.gametools.network/bf1/players/?gameid=%lld", gameID);
   // printf("请输入gameID: ");


    //在windows上设置编码格式

   // int test = get_playerplaying();

    RespContent resp = GetFullServerDetails(sessionId, gameID);



    FullServerDetails fullDetails;
    char* serverId = NULL;
    if (resp.is_success) {
        if (parse_full_server_details(resp.content, &fullDetails) == 0) {
            printf("JSON解析成功！\n");
            printf("Server ID: %s\n", fullDetails.serverDetails.serverId);

            if (fullDetails.serverDetails.serverId != NULL) {
                serverId = _strdup(fullDetails.serverDetails.serverId); // 复制字符串
            }
            printf("Persisted Game ID: %s\n", fullDetails.serverDetails.persistedGameId);

            for (size_t i = 0; i < fullDetails.serverDetails.num_maps; i++) {
                printf("Map ID: %d, Map Pretty Name: %s, Mode Pretty Name: %s\n",
                    fullDetails.serverDetails.maps[i].mapId,
                    fullDetails.serverDetails.maps[i].mapPrettyName,
                    fullDetails.serverDetails.maps[i].modePrettyName);//不要有，
            }
           
            // 当不再需要时，释放fullDetails中分配的内存
            //free_full_server_details(&fullDetails);
        }
        else {
            printf("JSON解析失败。\n");
        }
    }
    else {
        printf("Failed to receive a valid response: %s\n", resp.content);
    }

    printf("Request execution time: %.2f seconds\n", resp.exec_time);
    
    // 释放响应内容内存
    free(resp.content);

    const char* team1 = "TeamA";
    const char* team2 = "TeamB";

    printf("1111111111111111111111111111111111111111\n");
    // 调用封装好的函数来获取数据
//fetchAndDisplayTopPlayers(url, team1, team2);
   

    char input[100];
   
    int num;
    if (count)
    {
        goto NEXT2;
    }
    if (strcmp(fullDetails.serverDetails.maps[0].modePrettyName, "行動模式") == 0) {
        
        printf("是否需要按战役切图，输入1为启动，0为关闭: ");
#ifdef _WIN32
        if (scanf_s("%d", &operationflag) != 1) {
            printf("输入错误，请输入一个有效的数字。\n");
            return 1;  // 非法输入，提前结束程序
        }
#else
        if (scanf("%d", &operationflag) != 1) {
            printf("输入错误，请输入一个有效的数字。\n");
            return 1;  // 非法输入，提前结束程序
        }
#endif
        if (operationflag)
        {
            printf("以战役模式运行\n");
        }
        else
        {
            printf("以非战役模式运行\n");
        }
        //operationflag = 1;
    }
    else {

        printf("非行动模式运行\n");

    }
    printf("请在换图机启动前确保当前地图为列表首图\n");
    printf("请输入以逗号分隔的地图数字编号序列，例如3,1,2,45,23;");
    // 清空输入缓冲区
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

#ifdef _WIN32
    scanf_s("%99[^\n]", input, (unsigned)_countof(input));  // 读取用户输入
#else
    scanf("%99[^\n]", input);  // 读取用户输入
#endif


    char* token;
    char* nextToken;
    token = strtok_s(input, ",", &nextToken);
    while (token != NULL) {
        sscanf_s(token, "%d", &num);  // 将字符串转换为整数
        numbers[count] = num;
        count++;
        token = strtok_s(NULL, ",", &nextToken);
    }
    NEXT2:
    printf("您输入的数字是：");
    for (int i = 0; i < count; i++) {
        printf("%d ", numbers[i]);
    }
    printf("\n");
    if (save_config_json("config.json", gameID, operationflag, sessionId, numbers, count) != 0) {
        printf("保存配置失败\n");  // 处理保存失败的情况
    }
    else
    {
        printf("保存配置成功\n");
    }
    int mapcount = 1;
    int mapid = 0;
    pthread_t controllerThread;
    pthread_mutex_init(&lock, NULL);
    pthread_cond_init(&cond, NULL);
    printf("线程锁初始化成功\n");
    // 初始化线程ID数组
    for (int i = 0; i < MAX_THREADS; i++) {
        monitorArgsArray[i].threadId = THREAD_ID_UNUSED;
    }

    pthread_create(&controllerThread, NULL, thread_controller, NULL);
    printf("监控线程启动成功\n");
    printf("换图即已启动，下一张地图id为：%d", numbers[mapcount % count]);
    
    // 换图逻辑
    do {
#ifdef _WIN32
        Sleep(1000);
#else
        sleep(1);
#endif
        
        if (jiankongflag) {
            liveflag = 0;
            createflag = 0;
            if (operationflag == 1 && attackwinflag) {
                int lastcount = mapcount ? mapcount - 1 : count;
                mapid = numbers[lastcount % count];
                const char* mapname = fullDetails.serverDetails.maps[mapid].mapPrettyName;
                for (int i = 0; i < 10; ++i) {
                    if (strcmp(mapname, MAP_NAME[i]) == 0) {
                        operationflag = 2;
                        printf("OPERATION ATTACKER WIN\n");
                        goto END;
                    }
                }
            }
            else if (operationflag == 2) {
                operationflag = 1;
            }
           
            // 循环取地图ID
            mapid = numbers[mapcount % count];
            for (int try = 1; try <= 3; try++) {
                RespContent respR = RSPChooseLevel(sessionId, serverId, mapid);
                printf("Map ID: %d\n", mapid);
                printf("Is Success: %d\n", respR.is_success);
                printf("内容: %s\n", respR.content);
                printf("Execution Time: %.2f seconds\n", respR.exec_time);

                if (!respR.is_success) {
                    if (try == 3)
                    {
                        jiankongflag = 2;  // 设置一个状态以结束循环
                        printf("sessionid失效");
                    }
                    free(respR.content);
                }
                else
                {
                    free(respR.content);
                    break;
                }
               
            }
            mapcount++;  // 每次换图后增加地图列表长度
        END:;
            printf("Map ID: %d\n", mapid);

#ifdef _WIN32
            Sleep(18000);  // Windows中使用Sleep，参数单位为毫秒
#else
            sleep(18);     // UNIX/Linux中使用sleep，参数单位为秒
#endif
            pthread_mutex_lock(&lock);
            liveflag = 1;
            attackwinflag = 0;
            jiankongflag = 0;
            createflag = 1;
            pthread_mutex_unlock(&lock);
            printf("启动下一次换图检测\n");
            invalidateCache(); //刷新缓存
            continue;
        }
        

    } while (jiankongflag != 2);
#ifdef _WIN32
    Sleep(160000);  // Windows中使用Sleep，参数单位为毫秒
#else
    sleep(16);     // UNIX/Linux中使用sleep，参数单位为秒
#endif
    pthread_join(controllerThread, NULL);
    pthread_mutex_destroy(&lock);
    pthread_mutex_destroy(&cacheMutex);
    pthread_cond_destroy(&cond);
    return 0;




    struct MemoryStruct chunk = { 0 };


    httpGetRequest(url, &chunk);
    if (chunk.memory) {
        ServerInfoRoot* serverInfo = parse_server_info(chunk.memory);
        if (serverInfo) {
            printPlayerList(serverInfo);
            free_server_info(serverInfo);
        }
        free(chunk.memory);
    }


    RespContent respR = RSPChooseLevel(sessionId, serverId, mapid);
    printf("Is Success: %d\n", respR.is_success);
    printf("内容: %s\n", respR.content);
    printf("Execution Time: %.2f seconds\n", respR.exec_time);

    free(respR.content);
#ifdef _WIN32
    system("chcp 936");
#endif
    return 0;
}

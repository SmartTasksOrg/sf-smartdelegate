/* SmartDelegate C ABI check.
 *
 * 1. Runs every shared conformance case through smartdelegate_call(). C has no
 *    JSON library here, so the step logic runs inside the core
 *    ("conformance_case"); what this proves is the ABI itself: linking,
 *    handles, string ownership, error reporting.
 * 2. Makes a few direct calls the way an embedding application would.
 *
 *   conformance <repo root> <scratch dir>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "smartdelegate.h"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (buf && fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); buf = NULL; }
    if (buf) buf[n] = 0;
    fclose(f);
    return buf;
}

/* Returns the end of the JSON value starting at p (object or array). */
static const char *skip_value(const char *p) {
    int depth = 0, in_string = 0;
    for (; *p; p++) {
        if (in_string) {
            if (*p == '\\' && p[1]) p++;
            else if (*p == '"') in_string = 0;
        } else if (*p == '"') in_string = 1;
        else if (*p == '{' || *p == '[') depth++;
        else if (*p == '}' || *p == ']') { if (--depth == 0) return p + 1; }
    }
    return p;
}

/* Value of a top-level key of the JSON object `doc`, or NULL. Only top-level
 * keys are considered, so a "config" inside a case is never mistaken for the
 * suite's own. */
static const char *top_level(const char *doc, const char *key) {
    const char *p = strchr(doc, '{');
    size_t klen = strlen(key);
    if (!p) return NULL;
    p++;
    while (*p) {
        while (*p && *p != '"' && *p != '}') p++;
        if (*p != '"') return NULL;
        const char *k = p + 1;
        const char *q = k;
        while (*q && *q != '"') { if (*q == '\\' && q[1]) q++; q++; }
        if (!*q) return NULL;
        int match = (size_t)(q - k) == klen && strncmp(k, key, klen) == 0;
        p = q + 1;
        while (*p && *p != ':') p++;
        if (!*p) return NULL;
        p++;
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
        if (match) return p;
        if (*p == '{' || *p == '[') p = skip_value(p);
        else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; } if (*p) p++; }
        else while (*p && *p != ',' && *p != '}') p++;
    }
    return NULL;
}

/* JSON string escaping for paths (backslashes on Windows). */
static void escape(const char *in, char *out, size_t cap) {
    size_t j = 0;
    for (; *in && j + 2 < cap; in++) {
        if (*in == '\\' || *in == '"') out[j++] = '\\';
        out[j++] = *in;
    }
    out[j] = 0;
}

static int failures = 0;

static void check(int ok, const char *what) {
    if (!ok) { failures++; printf("FAIL %s\n", what); }
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: conformance <repo root> <scratch dir>\n"); return 2; }
    char root[1024], scratch[1024], path[2048], config[4096];
    char *case_config = NULL;
    escape(argv[1], root, sizeof root);
    escape(argv[2], scratch, sizeof scratch);
    check(smartdelegate_abi_version() == 1, "abi version is 1");

    const char *suites[] = {"01_tokens", "02_delegation", "03_fields", "04_spend_limits_approval", "05_guards",
                            "06_roles", "07_require_role", "08_oidc", "09_oidc_groups", "10_offboarding",
                            "11_operations", "12_oidc_nested_claim"};
    int total = 0;
    for (size_t s = 0; s < sizeof suites / sizeof *suites; s++) {
        snprintf(path, sizeof path, "%s/spec/conformance/vectors/%s.json", argv[1], suites[s]);
        char *doc = read_file(path);
        if (!doc) { printf("FAIL cannot read %s\n", path); return 1; }
        const char *p = top_level(doc, "cases");
        if (!p || *p != '[') { printf("FAIL no cases in %s\n", path); return 1; }
        p++;
        /* A suite may add engine settings (an identity provider, require_role):
         * its top-level "config" object is merged over the standard one. The
         * members are appended; for a repeated key the later one wins. */
        const char *extra = top_level(doc, "config");
        size_t extra_len = 0;
        if (extra && *extra == '{') {
            const char *extra_end = skip_value(extra);
            extra++;
            extra_len = (size_t)(extra_end - 1 - extra);
            size_t i;
            for (i = 0; i < extra_len && strchr(" \n\r\t", extra[i]); i++) {}
            if (i == extra_len) extra_len = 0; /* an empty object */
        } else extra = NULL;
        while (1) {
            while (*p && *p != '{' && *p != ']') p++;
            if (*p != '{') break;
            const char *end = skip_value(p);
            size_t len = (size_t)(end - p);
            char *one = malloc(len + 1);
            memcpy(one, p, len);
            one[len] = 0;
            p = end;

            snprintf(config, sizeof config,
                     "{\"bundle_dir\":\"%s/spec/conformance/bundle\",\"state_dir\":\"%s/c-%d\",\"allow_test_clock\":true,\"max_depth\":3",
                     root, scratch, total);
            size_t base_len = strlen(config);
            case_config = malloc(base_len + extra_len + 3);
            memcpy(case_config, config, base_len);
            size_t at = base_len;
            if (extra_len) {
                case_config[at++] = ',';
                memcpy(case_config + at, extra, extra_len);
                at += extra_len;
            }
            case_config[at++] = '}';
            case_config[at] = 0;
            smartdelegate_engine *e = smartdelegate_engine_new(case_config);
            free(case_config);
            if (!e) { printf("FAIL engine: %s\n", smartdelegate_last_error()); free(one); return 1; }
            char *result = smartdelegate_call(e, "conformance_case", one);
            total++;
            if (!result || !strstr(result, "\"passed\":true")) { failures++; printf("FAIL %s case %d: %s\n", suites[s], total, result ? result : "(null)"); }
            smartdelegate_string_free(result);
            smartdelegate_engine_free(e);
            free(one);
        }
        free(doc);
    }
    printf("c conformance: %d cases, %d failed\n", total, failures);

    /* direct use */
    check(smartdelegate_engine_new("{not json") == NULL, "bad config returns NULL");
    check(smartdelegate_last_error() && strstr(smartdelegate_last_error(), "invalid_input"), "last_error explains a bad config");
    check(smartdelegate_engine_new("{\"bundle_dir\":\"/no/such/dir\"}") == NULL, "missing bundle returns NULL");
    check(smartdelegate_last_error() && strstr(smartdelegate_last_error(), "bundle_io"), "last_error explains a missing bundle");

    snprintf(config, sizeof config, "{\"bundle_dir\":\"%s/spec/conformance/bundle\"}", root);
    smartdelegate_engine *e = smartdelegate_engine_new(config);
    check(e != NULL, "engine without a state directory");
    if (e) {
        char *t = smartdelegate_call(e, "issue_token",
            "{\"user\":\"alice\",\"agent\":\"support-bot\",\"cap\":{\"actions\":[\"read\"],\"resources\":[\"crm.customer/*\"]}}");
        const char *tok = t ? strstr(t, "\"token\":\"") : NULL;
        check(tok != NULL, "issue_token returns a token");
        if (tok) {
            tok += 9;
            size_t n = strcspn(tok, "\"");
            char *req = malloc(n + 512);
            snprintf(req, n + 512,
                     "{\"token\":\"%.*s\",\"action\":\"read\",\"resource\":{\"path\":\"crm.customer\",\"id\":\"c-1\"},"
                     "\"data\":{\"id\":\"c-1\",\"email\":\"ada@example.com\",\"ssn\":\"123-45-6789\",\"region\":\"EU\"}}",
                     (int)n, tok);
            char *d = smartdelegate_call(e, "filter", req);
            check(d && strstr(d, "\"effect\":\"allow\""), "filter allows the read");
            check(d && strstr(d, "ada@example.com"), "permitted field is kept");
            check(d && !strstr(d, "123-45-6789"), "ssn value is gone from the result");
            smartdelegate_string_free(d);
            free(req);
        }
        smartdelegate_string_free(t);
        char *bad = smartdelegate_call(e, "authorize", "this is not json");
        check(bad && strstr(bad, "\"ok\":false"), "malformed input is an error result, not a crash");
        smartdelegate_string_free(bad);
        char *null_in = smartdelegate_call(e, NULL, NULL);
        check(null_in && strstr(null_in, "\"ok\":false"), "NULL arguments are an error result");
        smartdelegate_string_free(null_in);
        smartdelegate_engine_free(e);
    }
    char *no_handle = smartdelegate_call(NULL, "info", "{}");
    check(no_handle && strstr(no_handle, "invalid_handle"), "NULL handle is an error result");
    smartdelegate_string_free(no_handle);
    smartdelegate_string_free(NULL);
    smartdelegate_engine_free(NULL);

    printf("c abi checks: %s\n", failures ? "FAILED" : "passed");
    return failures ? 1 : 0;
}

/* SmartDelegate C ABI, version 1. Apache-2.0.
 *
 * Every payload is a NUL-terminated UTF-8 JSON string. Operations and their
 * JSON shapes are specified in spec/API.md; they are the same in every
 * binding and in the REST daemon.
 */
#ifndef SMARTDELEGATE_H
#define SMARTDELEGATE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct smartdelegate_engine smartdelegate_engine;

/* Returns 1 for this ABI. */
uint32_t smartdelegate_abi_version(void);

/* Create an engine from a JSON config. Returns NULL on failure; the reason is
 * available from smartdelegate_last_error() on the same thread. */
smartdelegate_engine *smartdelegate_engine_new(const char *config_json);

/* JSON error for the last failed smartdelegate_engine_new on this thread, or NULL.
 * Owned by the library: do not free. */
const char *smartdelegate_last_error(void);

/* Run one operation ("authorize", "filter", "issue_token", ...). Returns a
 * JSON string the caller must release with smartdelegate_string_free. Thread-safe:
 * calls on one engine are serialised. */
char *smartdelegate_call(smartdelegate_engine *engine, const char *op, const char *input_json);

void smartdelegate_string_free(char *s);
void smartdelegate_engine_free(smartdelegate_engine *engine);

#ifdef __cplusplus
}
#endif
#endif

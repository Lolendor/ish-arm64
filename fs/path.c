#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include "kernel/calls.h"
#include "fs/path.h"

// === Path Normalize Cache ===
// Thread-local cache for frequently normalized paths
// Reduces redundant path normalization during Python import and file operations

#define PATH_CACHE_SIZE 64
#define PATH_CACHE_TTL_NS 100000000  // 100ms TTL

struct path_cache_entry {
    char input_path[MAX_PATH];     // Original path (with at_path prefix if any)
    char normalized[MAX_PATH];     // Normalized result
    uint64_t timestamp;            // nanosecond timestamp
    int flags;                     // N_SYMLINK_FOLLOW or N_SYMLINK_NOFOLLOW
    bool valid;
};

// Thread-local cache (one per thread for lock-free access)
static __thread struct path_cache_entry path_cache[PATH_CACHE_SIZE];
static __thread bool path_cache_initialized = false;

// Simple hash function for path strings
static inline uint32_t path_hash(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; // hash * 33 + c
    return hash;
}

// Get current time in nanoseconds
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// Initialize thread-local cache
static void path_cache_init(void) {
    if (!path_cache_initialized) {
        memset(path_cache, 0, sizeof(path_cache));
        path_cache_initialized = true;
    }
}

// Try to get cached normalized path
// Returns 0 on cache hit, -1 on cache miss
static int path_cache_get(const char *full_path, int flags, char *out) {
    path_cache_init();

    uint32_t hash = path_hash(full_path);
    uint32_t index = hash % PATH_CACHE_SIZE;
    struct path_cache_entry *entry = &path_cache[index];

    // Check cache validity
    if (!entry->valid)
        return -1;

    // Check path and flags match
    if (strcmp(entry->input_path, full_path) != 0)
        return -1;

    if (entry->flags != flags)
        return -1;

    // Check TTL (time-to-live)
    uint64_t now = get_time_ns();
    if (now - entry->timestamp > PATH_CACHE_TTL_NS) {
        entry->valid = false;  // Expired
        return -1;
    }

    // Cache hit! Copy result
    strcpy(out, entry->normalized);
    return 0;
}

// Store normalized path in cache
static void path_cache_set(const char *full_path, int flags, const char *normalized) {
    path_cache_init();

    uint32_t hash = path_hash(full_path);
    uint32_t index = hash % PATH_CACHE_SIZE;
    struct path_cache_entry *entry = &path_cache[index];

    // Store in cache
    strncpy(entry->input_path, full_path, MAX_PATH - 1);
    entry->input_path[MAX_PATH - 1] = '\0';

    strncpy(entry->normalized, normalized, MAX_PATH - 1);
    entry->normalized[MAX_PATH - 1] = '\0';

    entry->flags = flags;
    entry->timestamp = get_time_ns();
    entry->valid = true;
}

// chroot_prefix: the mount-absolute path of the current chroot root
// (e.g. "/srv/vms/test"), or NULL/"/" when no chroot is in effect.
// path_is_mount_absolute: caller guarantees `path` is already in
// mount-absolute terms (i.e. starts with `/` from the real fs root).
// This is the case during recursive symlink expansion when we already
// built the absolute path in `out` on the previous level. Top-level
// callers from path_normalize() pass false: their `path` is given in
// chroot-relative terms (the user typed `/etc/passwd`, meaning
// "/etc/passwd inside the jail").
//
// Containment rules:
//   1. `..` never backs `o` below strlen(chroot_prefix); mirrors POSIX
//      chroot semantics.
//   2. A user-supplied absolute path (or an absolute symlink target,
//      which is *also* user-namespace) starts with chroot_prefix
//      planted, so it cannot reach above the jail.
//   3. A mount-absolute recursive call (relative symlink that we
//      already resolved) is treated verbatim — its output already
//      contains the prefix.
static int __path_normalize_with_prefix(const char *at_path, const char *path,
                                        char *out, int flags, int levels,
                                        const char *chroot_prefix,
                                        bool path_is_mount_absolute) {
    // you must choose one
    if (flags & N_SYMLINK_FOLLOW)
        assert(!(flags & N_SYMLINK_NOFOLLOW));
    else
        assert(flags & N_SYMLINK_NOFOLLOW);

    int chroot_floor = 0;
    if (chroot_prefix != NULL && chroot_prefix[0] != '\0' &&
        strcmp(chroot_prefix, "/") != 0) {
        chroot_floor = (int)strlen(chroot_prefix);
    }

    const char *p = path;
    char *o = out;
    *o = '\0';
    int n = MAX_PATH - 1;

    if (strcmp(path, "") == 0)
        return _ENOENT;

    if (at_path != NULL && strcmp(at_path, "/") != 0) {
        strcpy(o, at_path);
        n -= strlen(at_path);
        o += strlen(at_path);
    } else if (chroot_floor > 0 && path[0] == '/' && !path_is_mount_absolute) {
        // Caller-supplied absolute path inside a chroot starts at the
        // chroot root. Plant the prefix so subsequent resolution stays
        // inside the jail. (Skipped when path is already a mount-
        // absolute string carried over from a previous resolution
        // step; that string already includes the prefix.)
        strcpy(o, chroot_prefix);
        n -= chroot_floor;
        o += chroot_floor;
    }

    while (*p == '/')
        p++;

    while (*p != '\0') {
        if (p[0] == '.') {
            if (p[1] == '\0' || p[1] == '/') {
                // single dot path component, ignore
                p++;
                while (*p == '/')
                    p++;
                continue;
            } else if (p[1] == '.' && (p[2] == '\0' || p[2] == '/')) {
                // double dot path component, delete the last component,
                // but never back below chroot_floor (chroot containment).
                if ((o - out) > chroot_floor) {
                    do {
                        o--;
                        n++;
                    } while ((o - out) > chroot_floor && *o != '/');
                }
                p += 2;
                while (*p == '/')
                    p++;
                continue;
            }
        }

        // output a slash
        *o++ = '/'; n--;
        char *c = o;
        // copy up to a slash or null
        while (*p != '/' && *p != '\0' && --n > 0)
            *o++ = *p++;
        // eat any slashes
        while (*p == '/')
            p++;

        if (n == 0)
            return _ENAMETOOLONG;

        if ((flags & N_SYMLINK_FOLLOW) || *p != '\0') {
            // this buffer is used to store the path that we're readlinking, then
            // if it turns out to point to a symlink it's reused as the buffer
            // passed to the next path_normalize call
            char possible_symlink[MAX_PATH];
            *o = '\0';
            strcpy(possible_symlink, out);
            struct mount *mount = find_mount_and_trim_path(possible_symlink);
            assert(path_is_normalized(possible_symlink));
            int res = _EINVAL;
            if (mount->fs->readlink)
                res = mount->fs->readlink(mount, possible_symlink, c, MAX_PATH - (c - out));
            if (res >= 0) {
                mount_release(mount);
                if (levels >= 5)
                    return _ELOOP;
                // readlink does not null terminate
                c[res] = '\0';

                // Two cases for the symlink's text payload:
                //   abs ("/foo")  — user-namespace absolute: must be
                //       re-prefixed with chroot_prefix so it stays
                //       inside the jail. We feed it to the recursive
                //       call as a non-mount-absolute path.
                //   rel ("foo")   — relative to the symlink's parent
                //       directory; the in-progress `out` buffer
                //       already names that parent in mount-absolute
                //       terms. Concatenate and recurse with
                //       path_is_mount_absolute=true so we don't
                //       double-plant the prefix.
                bool target_is_user_absolute = (*c == '/');
                char *expanded_path = possible_symlink;
                if (target_is_user_absolute) {
                    // expanded_path = symlink_target (user-absolute) [+ "/" + p]
                    strcpy(expanded_path, c);
                    if (strcmp(p, "") != 0) {
                        strcat(expanded_path, "/");
                        strcat(expanded_path, p);
                    }
                    return __path_normalize_with_prefix(
                        NULL, expanded_path, out, flags, levels + 1,
                        chroot_prefix, /*path_is_mount_absolute=*/false);
                } else {
                    // out currently ends with the symlink itself
                    // (mount-absolute). Strip it back to the parent
                    // dir; the readlink wrote the relative target into
                    // `c` (the byte after the last '/'), so we point
                    // the path concat right at it.
                    strcpy(expanded_path, out);
                    if (strcmp(p, "") != 0) {
                        strcat(expanded_path, "/");
                        strcat(expanded_path, p);
                    }
                    return __path_normalize_with_prefix(
                        NULL, expanded_path, out, flags, levels + 1,
                        chroot_prefix, /*path_is_mount_absolute=*/true);
                }
            }

            // if there's a slash after this component, ensure that if it
            // exists, it's a directory and that we have execute perms on it
            if (*(p - 1) == '/') {
                struct statbuf stat;
                int err = mount->fs->stat(mount, possible_symlink, &stat);
                mount_release(mount);
                if (err >= 0) {
                    if (!S_ISDIR(stat.mode))
                        return _ENOTDIR;
                    err = access_check(&stat, AC_X);
                    if (err < 0)
                        return err;
                }
            } else {
                mount_release(mount);
            }
        }
    }

    *o = '\0';
    assert(path_is_normalized(out));

    return 0;
}

// Back-compat wrapper for any in-tree caller (none currently).
static int __path_normalize(const char *at_path, const char *path, char *out, int flags, int levels) {
    return __path_normalize_with_prefix(at_path, path, out, flags, levels, NULL, false);
}

// Hash a string into 24 bits — used to mix the chroot prefix into the
// path cache key so two VMs with different roots don't share entries.
static uint32_t chroot_prefix_hash(const char *s) {
    if (s == NULL || s[0] == '\0') return 0;
    uint32_t h = 5381;
    while (*s) h = ((h << 5) + h) + (uint8_t)*s++;
    return h & 0xFFFFFFu;
}

int path_normalize(struct fd *at, const char *path, char *out, int flags) {
    assert(at != NULL);
    if (strcmp(path, "") == 0)
        return _ENOENT;

    // Snapshot the chroot prefix and the relevant `at`. Resolution
    // happens in mount-absolute terms; chroot_prefix is used both as a
    // floor for `..` and as the prefix planted at the start of any
    // absolute path encountered (including absolute symlink targets).
    struct fd *chroot_root_fd;
    lock(&current->fs->lock);
    chroot_root_fd = current->fs->root;
    if (path[0] == '/')
        at = current->fs->root;
    else if (at == AT_PWD)
        at = current->fs->pwd;
    unlock(&current->fs->lock);

    char at_path[MAX_PATH];
    if (at != NULL) {
        int err = generic_getpath(at, at_path);
        if (err < 0)
            return err;
        assert(path_is_normalized(at_path));
    }

    char chroot_path[MAX_PATH];
    chroot_path[0] = '\0';
    const char *chroot_prefix = NULL;
    if (chroot_root_fd != NULL) {
        if (generic_getpath(chroot_root_fd, chroot_path) == 0
                && strcmp(chroot_path, "/") != 0) {
            chroot_prefix = chroot_path;
        }
    }

    // Defensive check: if `at` is the per-process pwd and that pwd has
    // somehow drifted outside the chroot (e.g. a stale fd held across
    // chroot()), force resolution to start at the chroot root rather
    // than honour an out-of-jail `at_path`.
    if (chroot_prefix != NULL && at != NULL && path[0] != '/') {
        size_t cl = strlen(chroot_prefix);
        if (strncmp(at_path, chroot_prefix, cl) != 0 ||
            (at_path[cl] != '\0' && at_path[cl] != '/')) {
            // pwd is outside the jail — clamp to the chroot root.
            strcpy(at_path, chroot_prefix);
        }
    }

    // Build full input path for cache lookup. Include the chroot
    // prefix in the key so two VMs with same-length root paths can't
    // share cache entries.
    char full_input[MAX_PATH];
    if (at != NULL && strcmp(at_path, "/") != 0) {
        snprintf(full_input, MAX_PATH, "%s/%s", at_path, path);
    } else {
        strncpy(full_input, path, MAX_PATH - 1);
        full_input[MAX_PATH - 1] = '\0';
    }

    // 8 low bits stay for `flags`; the rest carries a 24-bit hash of
    // the chroot prefix.
    uint32_t prefix_h = chroot_prefix_hash(chroot_prefix);
    int cache_flags = (flags & 0xFF) | (int)(prefix_h << 8);
    if (path_cache_get(full_input, cache_flags, out) == 0) {
        return 0;
    }

    int result = __path_normalize_with_prefix(
        at != NULL ? at_path : NULL, path, out, flags, 0,
        chroot_prefix, /*path_is_mount_absolute=*/false);

    if (result == 0) {
        path_cache_set(full_input, cache_flags, out);
    }

    return result;
}


bool path_is_normalized(const char *path) {
    while (*path != '\0') {
        if (*path != '/')
            return false;
        path++;
        if (*path == '/')
            return false;
        while (*path != '/' && *path != '\0')
            path++;
    }
    return true;
}

bool path_next_component(const char **path, char *component, int *err) {
    const char *p = *path;
    if (*p == '\0')
        return false;

    assert(*p == '/');
    p++;
    char *c = component;
    while (*p != '/' && *p != '\0') {
        *c++ = *p++;
        if (c - component >= MAX_NAME) {
            *err = _ENAMETOOLONG;
            return false;
        }
    }
    *c = '\0';
    *path = p;
    return true;
}

#include <string.h>
#include <sys/stat.h>
#include "kernel/memory.h"
#include "kernel/calls.h"
#include "fs/proc.h"
#include "fs/fd.h"
#include "fs/tty.h"
#include "kernel/fs.h"
#include "kernel/vdso.h"
#include "util/sync.h"

static void proc_pid_getname(struct proc_entry *entry, char *buf) {
    sprintf(buf, "%d", entry->pid);
}

struct proc_pid_mem_stats {
    pages_t size;
    pages_t resident;
    pages_t shared;
    pages_t text;
    pages_t data;
    pages_t stack;
};

static void proc_pid_mem_stats_get(struct task *task, struct proc_pid_mem_stats *stats) {
    memset(stats, 0, sizeof(*stats));
    struct mem *mem = task->mem;
    if (mem == NULL)
        return;

    read_wrlock(&mem->lock);
#ifdef GUEST_ARM64
    for (struct mem_reservation *res = mem->reservations; res; res = res->next) {
        stats->size += res->pages;
        if (res->flags & P_EXEC)
            stats->text += res->pages;
        if ((res->flags & (P_WRITE | P_ANONYMOUS | P_GROWSDOWN)) != 0)
            stats->data += res->pages;
    }
#endif
    page_t page = 0;
    while (page < MEM_PAGES) {
        while (page < MEM_PAGES && mem_pt(mem, page) == NULL)
            mem_next_page(mem, &page);
        if (page >= MEM_PAGES)
            break;
        page_t start = page;
        struct pt_entry *start_pt = mem_pt(mem, start);
        struct data *data = start_pt->data;

        while (page < MEM_PAGES) {
            struct pt_entry *pt = mem_pt(mem, page);
            if (pt == NULL)
                break;
            if ((pt->flags & P_RWX) != (start_pt->flags & P_RWX))
                break;
            if (!(pt->data == data || (pt->flags & P_ANONYMOUS && start_pt->flags & P_ANONYMOUS)))
                break;
            page++;
        }
        pages_t pages = page - start;
        stats->size += pages;
        stats->resident += pages;
        if (start_pt->flags & P_SHARED)
            stats->shared += pages;
        if (start_pt->flags & P_EXEC)
            stats->text += pages;
        if (start_pt->flags & P_GROWSDOWN)
            stats->stack += pages;
        if ((start_pt->flags & (P_WRITE | P_ANONYMOUS | P_GROWSDOWN)) != 0)
            stats->data += pages;
    }
    read_wrunlock(&mem->lock);
}

static void proc_pid_signal_masks(struct task *task, sigset_t_ *ignored, sigset_t_ *caught) {
    *ignored = 0;
    *caught = 0;
    for (int i = 0; i < 32; i++) {
        if (task->sighand->action[i].handler == SIG_IGN_)
            *ignored |= 1ull << i;
        else if (task->sighand->action[i].handler != SIG_DFL_)
            *caught |= 1ull << i;
    }
}

static struct task *proc_get_task(struct proc_entry *entry) {
    lock(&pids_lock);
    struct task *task = pid_get_task(entry->pid);
    // Also reject tasks that are mid-exit: sighand/group may already be freed.
    if (task != NULL && (task->exiting || task->sighand == NULL || task->group == NULL))
        task = NULL;
    if (task == NULL)
        unlock(&pids_lock);
    return task;
}
static void proc_put_task(struct task *UNUSED(task)) {
    unlock(&pids_lock);
}

static int proc_pid_stat_show(struct proc_entry *entry, struct proc_data *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    lock(&task->general_lock);
    lock(&task->group->lock);
    lock(&task->sighand->lock);

    proc_printf(buf, "%d ", task->pid);
    proc_printf(buf, "(%.16s) ", task->comm);
    proc_printf(buf, "%c ",
            task->zombie ? 'Z' :
            task->group->stopped ? 'T' :
            'R'); // I have no visibility into sleep state at the moment
    proc_printf(buf, "%d ", task->parent ? task->parent->pid : 0);
    proc_printf(buf, "%d ", task->group->pgid);
    proc_printf(buf, "%d ", task->group->sid);
    struct tty *tty = task->group->tty;
    proc_printf(buf, "%d ", tty ? dev_make(tty->driver->major, tty->num) : 0);
    proc_printf(buf, "%d ", tty ? tty->fg_group : 0);
    proc_printf(buf, "%u ", 0); // flags

    // page faults (no data available)
    proc_printf(buf, "%lu ", 0l); // minor faults
    proc_printf(buf, "%lu ", 0l); // children minor faults
    proc_printf(buf, "%lu ", 0l); // major faults
    proc_printf(buf, "%lu ", 0l); // children major faults

    // values that would be returned from getrusage
    // finding these for a given process isn't too easy
    proc_printf(buf, "%lu ", 0l); // user time
    proc_printf(buf, "%lu ", 0l); // system time
    proc_printf(buf, "%ld ", 0l); // children user time
    proc_printf(buf, "%ld ", 0l); // children system time

    proc_printf(buf, "%ld ", 20l); // priority (not adjustable)
    proc_printf(buf, "%ld ", 0l); // nice (also not adjustable)
    proc_printf(buf, "%ld ", list_size(&task->group->threads));
    proc_printf(buf, "%ld ", 0l); // itimer value (deprecated, always 0)
    proc_printf(buf, "%lld ", 0ll); // jiffies on process start

    struct proc_pid_mem_stats mem_stats;
    proc_pid_mem_stats_get(task, &mem_stats);
    proc_printf(buf, "%llu ", (unsigned long long) mem_stats.size * PAGE_SIZE); // vsize
    proc_printf(buf, "%lld ", (long long) mem_stats.resident); // rss
    proc_printf(buf, "%lu ", 0l); // rss limit

    // bunch of shit that can only be accessed by a debugger
    proc_printf(buf, "%lu ", 0l); // startcode
    proc_printf(buf, "%lu ", 0l); // endcode
    proc_printf(buf, "%lu ", task->mm ? task->mm->stack_start : 0);
    proc_printf(buf, "%lu ", 0l); // kstkesp
    proc_printf(buf, "%lu ", 0l); // kstkeip

    proc_printf(buf, "%lu ", (unsigned long) task->pending & 0xffffffff);
    proc_printf(buf, "%lu ", (unsigned long) task->blocked & 0xffffffff);
    sigset_t_ ignored, caught;
    proc_pid_signal_masks(task, &ignored, &caught);
    proc_printf(buf, "%lu ", (unsigned long) ignored);
    proc_printf(buf, "%lu ", (unsigned long) caught);

    proc_printf(buf, "%lu ", 0l); // wchan (wtf)
    proc_printf(buf, "%lu ", 0l); // nswap
    proc_printf(buf, "%lu ", 0l); // cnswap
    proc_printf(buf, "%d ", task->exit_signal);
    proc_printf(buf, "%d", 0); // processor
    // that's enough for now
    proc_printf(buf, "\n");

    unlock(&task->sighand->lock);
    unlock(&task->group->lock);
    unlock(&task->general_lock);
    proc_put_task(task);
    return 0;
}

static int proc_pid_statm_show(struct proc_entry *entry, struct proc_data *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;

    struct proc_pid_mem_stats mem_stats;
    proc_pid_mem_stats_get(task, &mem_stats);
    proc_printf(buf, "%llu ", (unsigned long long) mem_stats.size); // total vm size
    proc_printf(buf, "%llu ", (unsigned long long) mem_stats.resident); // vm resident size
    proc_printf(buf, "%llu ", (unsigned long long) mem_stats.shared); // resident shared
    proc_printf(buf, "%llu ", (unsigned long long) mem_stats.text); // text
    proc_printf(buf, "%lu ", 0ul); // lib (always 0 since linux 2.6)
    proc_printf(buf, "%llu ", (unsigned long long) mem_stats.data); // data + stack
    proc_printf(buf, "%lu ", 0ul); // dirty (always 0 since linux 2.6)
    proc_printf(buf, "\n");

    proc_put_task(task);
    return 0;
}

static int proc_pid_status_show(struct proc_entry *entry, struct proc_data *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;

    lock(&task->general_lock);
    lock(&task->group->lock);
    lock(&task->sighand->lock);

    struct proc_pid_mem_stats mem_stats;
    proc_pid_mem_stats_get(task, &mem_stats);
    sigset_t_ ignored, caught;
    proc_pid_signal_masks(task, &ignored, &caught);
    char state = task->zombie ? 'Z' : task->group->stopped ? 'T' : 'R';
    const char *state_name = task->zombie ? "zombie" : task->group->stopped ? "stopped" : "running";

    proc_printf(buf, "Name:\t%.16s\n", task->comm);
    proc_printf(buf, "Umask:\t%04o\n", task->fs ? task->fs->umask : 0);
    proc_printf(buf, "State:\t%c (%s)\n", state, state_name);
    proc_printf(buf, "Tgid:\t%d\n", task->tgid);
    proc_printf(buf, "Ngid:\t0\n");
    proc_printf(buf, "Pid:\t%d\n", task->pid);
    proc_printf(buf, "PPid:\t%d\n", task->parent ? task->parent->pid : 0);
    proc_printf(buf, "TracerPid:\t0\n");
    proc_printf(buf, "Uid:\t%d\t%d\t%d\t%d\n", task->uid, task->euid, task->suid, task->euid);
    proc_printf(buf, "Gid:\t%d\t%d\t%d\t%d\n", task->gid, task->egid, task->sgid, task->egid);
    proc_printf(buf, "FDSize:\t%d\n", task->files ? task->files->size : 0);
    proc_printf(buf, "Groups:");
    for (unsigned i = 0; i < task->ngroups; i++)
        proc_printf(buf, "\t%d", task->groups[i]);
    proc_printf(buf, "\n");
    proc_printf(buf, "VmPeak:\t%8llu kB\n", (unsigned long long) mem_stats.size * (PAGE_SIZE / 1024));
    proc_printf(buf, "VmSize:\t%8llu kB\n", (unsigned long long) mem_stats.size * (PAGE_SIZE / 1024));
    proc_printf(buf, "VmRSS:\t%8llu kB\n", (unsigned long long) mem_stats.resident * (PAGE_SIZE / 1024));
    proc_printf(buf, "VmData:\t%8llu kB\n", (unsigned long long) mem_stats.data * (PAGE_SIZE / 1024));
    proc_printf(buf, "VmStk:\t%8llu kB\n", (unsigned long long) mem_stats.stack * (PAGE_SIZE / 1024));
    proc_printf(buf, "VmExe:\t%8llu kB\n", (unsigned long long) mem_stats.text * (PAGE_SIZE / 1024));
    proc_printf(buf, "VmLib:\t%8d kB\n", 0);
    proc_printf(buf, "Threads:\t%ld\n", list_size(&task->group->threads));
    proc_printf(buf, "SigQ:\t0/0\n");
    proc_printf(buf, "SigPnd:\t%016llx\n", (unsigned long long) task->pending);
    proc_printf(buf, "ShdPnd:\t%016llx\n", 0ull);
    proc_printf(buf, "SigBlk:\t%016llx\n", (unsigned long long) task->blocked);
    proc_printf(buf, "SigIgn:\t%016llx\n", (unsigned long long) ignored);
    proc_printf(buf, "SigCgt:\t%016llx\n", (unsigned long long) caught);
    proc_printf(buf, "CapInh:\t%016llx\n", 0ull);
    proc_printf(buf, "CapPrm:\t%016llx\n", 0ull);
    proc_printf(buf, "CapEff:\t%016llx\n", 0ull);
    proc_printf(buf, "CapBnd:\t%016llx\n", 0ull);
    proc_printf(buf, "CapAmb:\t%016llx\n", 0ull);
    proc_printf(buf, "NoNewPrivs:\t0\n");
    proc_printf(buf, "Seccomp:\t0\n");
    proc_printf(buf, "Cpus_allowed:\t1\n");
    proc_printf(buf, "Cpus_allowed_list:\t0\n");
    proc_printf(buf, "Mems_allowed:\t1\n");
    proc_printf(buf, "Mems_allowed_list:\t0\n");

    unlock(&task->sighand->lock);
    unlock(&task->group->lock);
    unlock(&task->general_lock);
    proc_put_task(task);
    return 0;
}

static int proc_pid_auxv_show(struct proc_entry *entry, struct proc_data *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    int err = 0;
    lock(&task->general_lock);
    if (task->mm == NULL)
        goto out_free_task;

    size_t size = task->mm->auxv_end - task->mm->auxv_start;
    char *data = malloc(size);
    if (data == NULL) {
        err = _ENOMEM;
        goto out_free_task;
    }
    if (user_read_task(task, task->mm->auxv_start, data, size) == 0)
        proc_buf_append(buf, data, size);
    free(data);

out_free_task:
    unlock(&task->general_lock);
    proc_put_task(task);
    return err;
}

static int proc_pid_cmdline_show(struct proc_entry *entry, struct proc_data *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    int err = 0;
    lock(&task->general_lock);
    if (task->mm == NULL)
        goto out_free_task;

    size_t size = task->mm->argv_end - task->mm->argv_start;
    char *data = malloc(size);
    if (data == NULL) {
        err = _ENOMEM;
        goto out_free_task;
    }
    if (user_read_task(task, task->mm->argv_start, data, size) == 0)
        proc_buf_append(buf, data, size);
    free(data);

out_free_task:
    unlock(&task->general_lock);
    proc_put_task(task);
    return err;
}

void proc_maps_dump(struct task *task, struct proc_data *buf) {
    struct mem *mem = task->mem;
    if (mem == NULL)
        return;

    read_wrlock(&mem->lock);
    page_t page = 0;
    while (page < MEM_PAGES) {
        // find a region
        while (page < MEM_PAGES && mem_pt(mem, page) == NULL) {
            mem_next_page(mem, &page);
        }
        if (page >= MEM_PAGES)
            break;
        page_t start = page;
        struct pt_entry *start_pt = mem_pt(mem, start);
        struct data *data = start_pt->data;

        // find the end of said region
        while (page < MEM_PAGES) {
            struct pt_entry *pt = mem_pt(mem, page);
            if (pt == NULL)
                break;
            if ((pt->flags & P_RWX) != (start_pt->flags & P_RWX))
                break;
            // region continues if data is the same or both are anonymous
            if (!(pt->data == data || (pt->flags & P_ANONYMOUS && start_pt->flags & P_ANONYMOUS)))
                break;
            mem_next_page(mem, &page);
        }
        page_t end = page;

        // output info
        char path[MAX_PATH] = "";
        if (start_pt->flags & P_GROWSDOWN) {
            strcpy(path, "[stack]");
        } else if (data->name != NULL) {
            strcpy(path, data->name);
        } else if (data->fd != NULL) {
            generic_getpath(start_pt->data->fd, path);
        }
#ifdef GUEST_ARM64
        proc_printf(buf, "%012llx-%012llx %c%c%c%c %08lx 00:00 %-10d %s\n",
                (unsigned long long)(start << PAGE_BITS),
                (unsigned long long)(end << PAGE_BITS),
#else
        proc_printf(buf, "%08x-%08x %c%c%c%c %08lx 00:00 %-10d %s\n",
                start << PAGE_BITS, end << PAGE_BITS,
#endif
                start_pt->flags & P_READ ? 'r' : '-',
                start_pt->flags & P_WRITE ? 'w' : '-',
                start_pt->flags & P_EXEC ? 'x' : '-',
                start_pt->flags & P_SHARED ? '-' : 'p',
                (unsigned long) data->file_offset, // offset
                0, // inode
                path);
    }
    read_wrunlock(&mem->lock);
}

static int proc_pid_maps_show(struct proc_entry *entry, struct proc_data *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    proc_maps_dump(task, buf);
    proc_put_task(task);
    return 0;
}

static ssize_t proc_pid_mem_pread(struct proc_entry *entry, struct proc_data *buf, off_t offset) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    int result = user_read_task(task, (addr_t)offset, buf->data, buf->size);
    proc_put_task(task);
    return result ? -1 : buf->size;
}

static ssize_t proc_pid_mem_pwrite(struct proc_entry *entry, struct proc_data *buf, off_t offset) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    int result = user_write_task_ptrace(task, (addr_t)offset, buf->data, buf->size);
    proc_put_task(task);
    return result ? -1 : buf->size;
}


static struct proc_dir_entry proc_pid_fd;

static bool proc_pid_fd_readdir(struct proc_entry *entry, unsigned long *index, struct proc_entry *next_entry) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    lock(&task->files->lock);
    while (*index < task->files->size && task->files->files[*index] == NULL)
        (*index)++;
    fd_t f = (*index)++;
    bool any_left = (unsigned) f < task->files->size;
    unlock(&task->files->lock);
    proc_put_task(task);
    *next_entry = (struct proc_entry) {&proc_pid_fd, .pid = entry->pid, .fd = f};
    return any_left;
}

static void proc_pid_fd_getname(struct proc_entry *entry, char *buf) {
    sprintf(buf, "%d", entry->fd);
}

static int proc_pid_fd_readlink(struct proc_entry *entry, char *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    lock(&task->files->lock);
    struct fd *fd = fdtable_get(task->files, entry->fd);
    int err = generic_getpath(fd, buf);
    unlock(&task->files->lock);
    proc_put_task(task);
    return err;
}

// Strip the calling task's chroot prefix (if any) from a mount-absolute
// path so the guest never sees paths above its jail root via /proc.
// `buf` is rewritten in place.
static void strip_caller_chroot_prefix(char *buf) {
    if (buf == NULL || buf[0] == '\0') return;
    char chroot_path[MAX_PATH];
    lock(&current->fs->lock);
    int err = current->fs->root != NULL
        ? generic_getpath(current->fs->root, chroot_path) : -1;
    unlock(&current->fs->lock);
    if (err < 0 || strcmp(chroot_path, "/") == 0) return;
    size_t cl = strlen(chroot_path);
    if (strncmp(buf, chroot_path, cl) == 0 &&
        (buf[cl] == '\0' || buf[cl] == '/')) {
        memmove(buf, buf + cl, strlen(buf) - cl + 1);
        if (buf[0] == '\0') strcpy(buf, "/");
    } else {
        // The path is outside the caller's jail. Don't leak it.
        strcpy(buf, "/");
    }
}

static int proc_pid_exe_readlink(struct proc_entry *entry, char *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    lock(&task->general_lock);
    int err;
    if (task->mm == NULL || task->mm->exefile == NULL)
        err = _ENOENT;
    else
        err = generic_getpath(task->mm->exefile, buf);
    unlock(&task->general_lock);
    proc_put_task(task);
    if (err == 0)
        strip_caller_chroot_prefix(buf);
    return err;
}

static void proc_pid_task_getname(struct proc_entry *entry, char *buf) {
    sprintf(buf, "%d", entry->pid);
}

static int proc_pid_task_readlink(struct proc_entry *entry, char *buf) {
    sprintf(buf, "/proc/%d", entry->pid);
    return 0;
}

static struct proc_dir_entry proc_pid_task;

static bool proc_pid_task_readdir(struct proc_entry *entry, unsigned long *index, struct proc_entry *next_entry) {
    // TODO: Expose all threads
    *next_entry = (struct proc_entry) {&proc_pid_task, .pid = entry->pid};
    return !(*index)++;
}

static int proc_pid_cwd_readlink(struct proc_entry *entry, char *buf) {
    struct task *task = proc_get_task(entry);
    if (task == NULL)
        return _ESRCH;
    lock(&task->fs->lock);
    int err = generic_getpath(task->fs->pwd, buf);
    unlock(&task->fs->lock);
    proc_put_task(task);
    if (err == 0)
        strip_caller_chroot_prefix(buf);
    return err;
}


struct proc_children proc_pid_children = PROC_CHILDREN({
    {"auxv", .show = proc_pid_auxv_show},
    {"cmdline", .show = proc_pid_cmdline_show},
    {"cwd", S_IFLNK, .readlink = proc_pid_cwd_readlink},
    {"exe", S_IFLNK, .readlink = proc_pid_exe_readlink},
    {"fd", S_IFDIR, .readdir = proc_pid_fd_readdir},
    {"maps", .show = proc_pid_maps_show},
    {"mem", .pread = proc_pid_mem_pread, .pwrite = proc_pid_mem_pwrite},
    {"stat", .show = proc_pid_stat_show},
    {"statm", .show = proc_pid_statm_show},
    {"status", .show = proc_pid_status_show},
    {"task", S_IFDIR, .readdir = proc_pid_task_readdir},
});

struct proc_dir_entry proc_pid = {NULL, S_IFDIR,
    .children = &proc_pid_children, .getname = proc_pid_getname};

static struct proc_dir_entry proc_pid_fd = {NULL, S_IFLNK,
    .getname = proc_pid_fd_getname, .readlink = proc_pid_fd_readlink};

static struct proc_dir_entry proc_pid_task = {NULL, S_IFLNK,
    .getname = proc_pid_task_getname, .readlink = proc_pid_task_readlink};

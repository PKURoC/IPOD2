#include "asm/stat.h"
#include "linux/fs.h"
#include "linux/limits.h"
#include "linux/list.h"
#include "linux/string.h"
#include "linux/syscalls.h"
#include <crypto/hash.h>
#include <linux/cred.h>
#include <linux/crypto.h>
#include <linux/dcache.h>
#include <linux/iversion.h>
#include <linux/stringhash.h>
#include <linux/timekeeping.h>
#include <linux/uidgid.h>
#include <linux/xattr.h>

#include "ima.h"

void ima_file_path_init(struct ima_file_path *fpath, struct path *path)
{
	fpath->pathname = ima_d_path(path, &fpath->pathbuf, fpath->filename);
}

static uid_t ima_file_label_get_uid(void)
{
	return current_uid().val;
}

static pid_t ima_file_label_get_pid(void)
{
	return current->pid;
}

static unsigned int calc_fpcr_id_from_file(struct file *file)
{
	char *filename = file->f_path.dentry->d_iname;
	/* unsigned int len = strnlen(filename, DNAME_INLINE_LEN); */
	/* struct dentry* dir = file->f_path.dentry->d_parent; */
	/* unsigned int fpcr_id = full_name_hash(dir, filename, len); */
	struct inode *inode = d_backing_inode(file->f_path.dentry);
	unsigned int fpcr_id = inode->i_ino;
	// printk("[fpcr test] fpcr_id=%u from file[%s]", fpcr_id, filename);
	return fpcr_id;
}

static unsigned int calc_fpcr_id_from_path(struct path *path)
{
	struct dentry *dentry = path->dentry;
	char *filename = dentry->d_iname;
	// struct inode *inode = d_backing_inode(dentry);
	unsigned int fpcr_id = dentry->d_inode->i_ino;
	// printk("[fpcr test] fpcr_id=%u from dentry[%s]", fpcr_id, filename);
	return fpcr_id;
}

void ima_file_label_init(struct ima_file_label *flabel, struct file *file,
			 struct path *path, enum ima_file_label_action action)
{
	flabel->uid = ima_file_label_get_uid();
	flabel->pid = ima_file_label_get_pid();
	flabel->action = 0;
	flabel->file = file;
	flabel->fpcr_id = FPCR_NULL_ID;
	flabel->action = action;
	flabel->fpath.pathname = NULL;

	if (file) {
		ima_file_path_init(&flabel->fpath, &file->f_path);
		flabel->fpcr_id = calc_fpcr_id_from_file(file);
		flabel->dentry = file->f_path.dentry;
	} else if (path) {
		ima_file_path_init(&flabel->fpath, path);
		flabel->fpcr_id = calc_fpcr_id_from_path(path);
		flabel->dentry = path->dentry;
	}
}

unsigned int hash_ima_file_label(struct ima_file_label *flabel)
{
	if (!flabel) {
		return FPCR_NULL_ID;
	}

	return flabel->fpcr_id;
}

int ima_file_label_to_string(struct ima_file_label *flabel, char *buf,
			     int max_buf)
{
	int len;
	enum ima_file_label_action action = flabel->action;
	const char *action_name = NULL;
	const char *tail = "";

	switch (action) {
	case LABEL_HOOK_OPEN:
		action_name = "OPEN";
		break;
	case LABEL_HOOK_READ:
		action_name = "READ";
		break;
	case LABEL_HOOK_WRITE:
		action_name = "WRITE";
		break;
	case LABEL_HOOK_CLOSE:
		action_name = "CLOSE";
		break;
	case LABEL_HOOK_SYNC:
		action_name = "SYNC";
		break;
	case LABEL_HOOK_FSETXATTR:
		action_name = "FSETXATTR";
		break;
	case LABEL_HOOK_FTRUNCATE:
		action_name = "FTRUNCATE";
		break;
	case LABEL_HOOK_LSEEK:
		action_name = "LSEEK";
		break;
	case LABEL_HOOK_TRUNCATE:
		action_name = "TRUNCATE";
		break;
	case LABEL_HOOK_FCNTL:
		action_name = "FCNTL";
		break;
	case LABEL_HOOK_FSTAT:
		action_name = "FSTAT";
		break;
	case LABEL_HOOK_MMAP:
		action_name = "MMAP";
		break;
	case LABEL_HOOK_RENAME:
		action_name = "RENAME";
		break;
	case LABEL_HOOK_UNLINK:
		action_name = "UNLINK";
		break;
	case LABEL_HOOK_LINK:
		action_name = "LINK";
		break;
	default:
		action_name = "UNKNOWN";
	}

	if (flabel->state) {
		if (flabel->state->write_to_sync) {
			action_name = "OVERWRITE";
			flabel->state->write_to_sync = 0;
		} else if (flabel->state->error) {
			tail = "[UNEXPECTED]:";
			flabel->state->error = 0;
		} else if (flabel->state->ready) {
			action_name = "INITIAL";
			flabel->state->ready = 0;
		} else if (flabel->state->load_content) {
			action_name = "LOAD";
			flabel->state->load_content = 0;
		}
	}

	len = snprintf(buf, max_buf, "%lld-%u-%u-%s%s-%s",
		       ktime_get_real_seconds(), flabel->uid, flabel->pid, tail,
		       action_name, flabel->fpath.pathname);

	return len;
}

static int ima_file_check_xattr(struct dentry *dentry)
{
	struct inode *inode;
	int error = 0;
	char buffer[2];

	inode = d_backing_inode(dentry);

	error = __vfs_getxattr(dentry, inode, XATTR_NAME_SECDEL, buffer, 2);
	if (error < 0) {
		return error;
	}

	if (strncmp(buffer, "1", 1)) {
		// printk("[fpcr test] DEBUG: file[%s] xattr[%s] is not 1, buffer[%s]",
		//        dentry->d_iname, XATTR_NAME_SECDEL, buffer);
		return -ENODATA;
	}

	return 0;
}

int ima_file_filter(struct dentry *dentry, unsigned int action)
{
	int need_record = 0;

	if (action > 0 && ima_file_check_xattr(dentry) == 0) {
		return 1;
	}

	return need_record;
}

#define __set_state(st, next)                                                  \
	do {                                                                   \
		(st)->state = (next);                                          \
	} while (0)

#define __fallback(st)                                                         \
	do {                                                                   \
		if (state->start_seq) {                                        \
			goto err;                                              \
		} else {                                                       \
			goto back;                                             \
		}                                                              \
	} while (0)

int ima_fpcr_get_next(struct ima_file_state *state, int ev)
{
	enum ima_fpcr_file_state {
		STARTUP_STATE = 0,
		STARTUP_XATTR,
		STARTUP_CLOSE,
		LOAD_WRITE,
		LOAD_CLOSE,
		INIT_STATE,
		INIT_OPEN,
		INIT_FSTAT,
		INIT_FCNTL,
		DO_LSEEK,
		DO_WRITE,
		DO_SYNC,
		DO_FCNTL,
		DO_FTRUNCATE,
		DO_CLOSE,
		DO_RENAME,
		DO_UNLINK,
	};
	int cur = state->state;
	int skip = 0;

	switch (ev) {
	case LABEL_HOOK_OPEN:
		if (cur == STARTUP_CLOSE || cur == INIT_STATE ||
		    cur == LOAD_CLOSE) {
			__set_state(state, INIT_OPEN);
			skip = 1;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_READ:
		__fallback(state);
		break;
	case LABEL_HOOK_WRITE:
		if (cur == DO_LSEEK) {
			__set_state(state, DO_WRITE);
			skip = 1;
		} else if (cur == DO_WRITE) {
			__set_state(state, DO_WRITE);
			skip = 1;
		} else if (cur == INIT_FSTAT || cur == LOAD_WRITE) {
			__set_state(state, LOAD_WRITE);
			skip = 1;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_CLOSE:
		if (cur == STARTUP_XATTR) {
			__set_state(state, STARTUP_CLOSE);
		} else if (cur == DO_FTRUNCATE) {
			__set_state(state, DO_CLOSE);
		} else if (cur == LOAD_WRITE) {
			__set_state(state, LOAD_CLOSE);
			state->load_content = 1;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_SYNC:
		if (cur == DO_WRITE) {
			__set_state(state, DO_SYNC);
			state->write_to_sync = 1;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_FSETXATTR:
		if (cur == STARTUP_STATE) {
			__set_state(state, STARTUP_XATTR);
		} else {
			// unexpected reach
			__set_state(state, STARTUP_XATTR);
		}
		break;
	case LABEL_HOOK_FTRUNCATE:
		if (cur == DO_SYNC) {
			__set_state(state, DO_FTRUNCATE);
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_LSEEK:
		if (cur == INIT_FCNTL || cur == INIT_FSTAT) {
			__set_state(state, DO_LSEEK);
			state->start_seq = 1;
			skip = 1;
		} else if (cur == DO_FCNTL) {
			__set_state(state, DO_LSEEK);
			skip = 1;
		} else if (cur == DO_SYNC) {
			__set_state(state, DO_LSEEK);
			skip = 1;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_FCNTL:
		if (cur == INIT_FSTAT) {
			__set_state(state, INIT_FCNTL);
			skip = 1;
		} else if (cur == INIT_FCNTL) {
			__set_state(state, INIT_FCNTL);
			state->ready = 1;
		} else if (cur == DO_SYNC) {
			__set_state(state, DO_FCNTL);
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_MMAP:
		__fallback(state);
		break;
	case LABEL_HOOK_RENAME:
		if (cur == DO_CLOSE) {
			__set_state(state, DO_RENAME);
		} else if (cur == DO_RENAME) {
			__set_state(state, DO_RENAME);
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_FSTAT:
		if (cur == INIT_OPEN) {
			__set_state(state, INIT_FSTAT);
			skip = 1;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_UNLINK:
		if (cur == DO_RENAME) {
			__set_state(state, DO_UNLINK);
			state->finish = 1;
			state->start_seq = 0;
		} else {
			__fallback(state);
		}
		break;
	case LABEL_HOOK_LINK:
		__fallback(state);
		break;
	}

	// printk("[fpcr test] return skip=%d with action=%d", skip, ev);
	return skip;
err:
	state->error = 1;
back:
	__set_state(state, INIT_STATE);
	state->start_seq = 0;
	return 0;
}
#undef __set_state
#undef __fallback

unsigned int ima_fpcr_get_id(struct ima_file_label *flabel)
{
	return hash_ima_file_label(flabel);
}

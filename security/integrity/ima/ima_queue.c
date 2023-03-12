// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 *
 * Authors:
 * Serge Hallyn <serue@us.ibm.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * File: ima_queue.c
 *       Implements queues that store template measurements and
 *       maintains aggregate over the stored measurements
 *       in the pre-configured TPM PCR (if available).
 *       The measurement list is append-only. No entry is
 *       ever removed or changed during the boot-cycle.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/rculist.h>
#include <linux/slab.h>
#include "ima.h"

#define AUDIT_CAUSE_LEN_MAX 32

#ifdef CONFIG_IMA_FPCR
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>

struct ima_fpcr_h_table ima_fpcr_htable = {
	.len = ATOMIC_LONG_INIT(0),
	.queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] = HLIST_HEAD_INIT
};

struct fpcr_list *ima_fpcr_lookup_entry(unsigned int id)
{
	struct ima_fpcr_h_entry *qe = NULL;
	struct fpcr_list *ret = NULL;
	unsigned int key;
	int rc;

	key = ima_fpcr_hash_key(id);
	rcu_read_lock();
	hlist_for_each_entry_rcu (qe, &ima_fpcr_htable.queue[key], hnext) {
		if (qe->id_list->id == id) {
			ret = qe->id_list;
			break;
		}
	}

	rcu_read_unlock();
	return ret;
}

#endif /* CONFIG_IMA_FPCR */

/* pre-allocated array of tpm_digest structures to extend a PCR */
static struct tpm_digest *digests;

LIST_HEAD(ima_measurements); /* list of all measurements */
#ifdef CONFIG_IMA_KEXEC
static unsigned long binary_runtime_size;
#else
static unsigned long binary_runtime_size = ULONG_MAX;
#endif

/* key: inode (before secure-hashing a file) */
struct ima_h_table ima_htable = { .len = ATOMIC_LONG_INIT(0),
				  .violations = ATOMIC_LONG_INIT(0),
				  .queue[0 ... IMA_MEASURE_HTABLE_SIZE - 1] =
					  HLIST_HEAD_INIT };

/* mutex protects atomicity of extending measurement list
 * and extending the TPM PCR aggregate. Since tpm_extend can take
 * long (and the tpm driver uses a mutex), we can't use the spinlock.
 */
static DEFINE_MUTEX(ima_extend_list_mutex);

/* lookup up the digest value in the hash table, and return the entry */
static struct ima_queue_entry *ima_lookup_digest_entry(u8 *digest_value,
						       int pcr)
{
	struct ima_queue_entry *qe, *ret = NULL;
	unsigned int key;
	int rc;

	key = ima_hash_key(digest_value);
	rcu_read_lock();
	hlist_for_each_entry_rcu (qe, &ima_htable.queue[key], hnext) {
		rc = memcmp(qe->entry->digest, digest_value, TPM_DIGEST_SIZE);
		if ((rc == 0) && (qe->entry->pcr == pcr)) {
			ret = qe;
			break;
		}
	}
	rcu_read_unlock();
	return ret;
}

/*
 * Calculate the memory required for serializing a single
 * binary_runtime_measurement list entry, which contains a
 * couple of variable length fields (e.g template name and data).
 */
static int get_binary_runtime_size(struct ima_template_entry *entry)
{
	int size = 0;

	size += sizeof(u32); /* pcr */
	size += sizeof(entry->digest);
	size += sizeof(int); /* template name size field */
	size += strlen(entry->template_desc->name);
	size += sizeof(entry->template_data_len);
	size += entry->template_data_len;
	return size;
}

/* ima_add_template_entry helper function:
 * - Add template entry to the measurement list and hash table, for
 *   all entries except those carried across kexec.
 *
 * (Called with ima_extend_list_mutex held.)
 */
static int ima_add_digest_entry(struct ima_template_entry *entry,
				bool update_htable)
{
	struct ima_queue_entry *qe;
	unsigned int key;

	qe = kmalloc(sizeof(*qe), GFP_KERNEL);
	if (qe == NULL) {
		pr_err("OUT OF MEMORY ERROR creating queue entry\n");
		return -ENOMEM;
	}
	qe->entry = entry;

	INIT_LIST_HEAD(&qe->later);
	list_add_tail_rcu(&qe->later, &ima_measurements);

	atomic_long_inc(&ima_htable.len);
	if (update_htable) {
		key = ima_hash_key(entry->digest);
		hlist_add_head_rcu(&qe->hnext, &ima_htable.queue[key]);
	}

	if (binary_runtime_size != ULONG_MAX) {
		int size;

		size = get_binary_runtime_size(entry);
		binary_runtime_size = (binary_runtime_size < ULONG_MAX - size) ?
					      binary_runtime_size + size :
						    ULONG_MAX;
	}
	return 0;
}

#ifdef CONFIG_IMA_FPCR
/* ima_add_template_entry helper function:
 * - Add template entry to the measurement list and hash table, for
 *   all entries except those carried across kexec.
 *
 * (Called with ima_extend_list_mutex held.)
 */
static int ima_fpcr_add_digest_entry(struct ima_template_entry *entry,
				     bool update_htable, struct fpcr_list *list)
{
	struct ima_queue_entry *qe;
	unsigned int key;

	qe = kmalloc(sizeof(*qe), GFP_KERNEL);
	if (qe == NULL) {
		pr_err("OUT OF MEMORY ERROR creating queue entry\n");
		return -ENOMEM;
	}
	qe->entry = entry;

	INIT_LIST_HEAD(&qe->later);

	if (list && list->mt && list->tree_node_id) {
		// printk("[fpcr test] a ME added into fpcr[%u]", list->id);
		list_add_tail_rcu(&qe->later, &list->measurements);
	} else {
		list_add_tail_rcu(&qe->later, &ima_measurements);

		atomic_long_inc(&ima_htable.len);
		if (update_htable) {
			key = ima_hash_key(entry->digest);
			hlist_add_head_rcu(&qe->hnext, &ima_htable.queue[key]);
		}
	}

	if (binary_runtime_size != ULONG_MAX) {
		int size;

		size = get_binary_runtime_size(entry);
		binary_runtime_size = (binary_runtime_size < ULONG_MAX - size) ?
					      binary_runtime_size + size :
						    ULONG_MAX;
	}
	return 0;
}

#endif /* CONFIG_IMA_FPCR */

/*
 * Return the amount of memory required for serializing the
 * entire binary_runtime_measurement list, including the ima_kexec_hdr
 * structure.
 */
unsigned long ima_get_binary_runtime_size(void)
{
	if (binary_runtime_size >= (ULONG_MAX - sizeof(struct ima_kexec_hdr)))
		return ULONG_MAX;
	else
		return binary_runtime_size + sizeof(struct ima_kexec_hdr);
};

static int ima_pcr_extend(const u8 *hash, int pcr)
{
	int result = 0;
	int i;

	if (!ima_tpm_chip)
		return result;

	for (i = 0; i < ima_tpm_chip->nr_allocated_banks; i++)
		memcpy(digests[i].digest, hash, TPM_DIGEST_SIZE);

	result = tpm_pcr_extend(ima_tpm_chip, pcr, digests);
	if (result != 0)
		pr_err("Error Communicating to TPM chip, result: %d\n", result);
	return result;
}

/*
 * Add template entry to the measurement list and hash table, and
 * extend the pcr.
 *
 * On systems which support carrying the IMA measurement list across
 * kexec, maintain the total memory size required for serializing the
 * binary_runtime_measurements.
 */
int ima_add_template_entry(struct ima_template_entry *entry, int violation,
			   const char *op, struct inode *inode,
			   const unsigned char *filename)
{
	u8 digest[TPM_DIGEST_SIZE];
	const char *audit_cause = "hash_added";
	char tpm_audit_cause[AUDIT_CAUSE_LEN_MAX];
	int audit_info = 1;
	int result = 0, tpmresult = 0;

	mutex_lock(&ima_extend_list_mutex);
	if (!violation) {
		memcpy(digest, entry->digest, sizeof(digest));
		if (ima_lookup_digest_entry(digest, entry->pcr)) {
			audit_cause = "hash_exists";
			result = -EEXIST;
			goto out;
		}
	}

	result = ima_add_digest_entry(entry, 1);
	if (result < 0) {
		audit_cause = "ENOMEM";
		audit_info = 0;
		goto out;
	}

	if (violation) /* invalidate pcr */
		memset(digest, 0xff, sizeof(digest));

	tpmresult = ima_pcr_extend(digest, entry->pcr);
	if (tpmresult != 0) {
		snprintf(tpm_audit_cause, AUDIT_CAUSE_LEN_MAX, "TPM_error(%d)",
			 tpmresult);
		audit_cause = tpm_audit_cause;
		audit_info = 0;
	}
out:
	mutex_unlock(&ima_extend_list_mutex);
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename, op,
			    audit_cause, result, audit_info);
	return result;
}

#ifdef CONFIG_IMA_FPCR
static int ima_pcrread(u32 idx, struct tpm_digest *d)
{
	int result = 0;
	if (!ima_tpm_chip)
		return result;
	result = tpm_pcr_read(ima_tpm_chip, idx, d);
	if (result != 0)
		pr_err("[fpcr test]: Error communicating to TPM chip, result=%d\n",
		       result);

	return result;
}

static int ima_fpcr_bind(void)
{
	// 暂时先硬编码，这个不好处理
	struct tpm_digest d = { .alg_id = TPM_ALG_SHA1, .digest = { 0 } };
	struct fpcr_list *qe;
	struct merkle_tree *qmt;
	u8 digest[TPM_DIGEST_SIZE];
	int i;
	int rc = 0;

	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(fpcr_for_history.tfm)];
	} desc;

	desc.shash.tfm = fpcr_for_history.tfm;

	rc = crypto_shash_init(&desc.shash);
	if (rc != 0) {
		return rc;
	}

	// printk("[fpcr test] prepared to bind fpcr to pcr");
	rc = ima_pcrread(CONFIG_FPCR_BIND_PCR_INDEX, &d);

	memcpy(fpcr_for_history.data, d.digest, FPCR_DATA_SIZE);

	/* printk("[fpcr test] >>> currnet pcr[%d] value is ", CONFIG_FPCR_BIND_PCR_INDEX); */
	/* for (i = 0; i < 20; i++) { */
	/*     printk(KERN_CONT "%02x ", fpcr_for_history.data[i]); */
	/* } */

	rcu_read_lock();
	list_for_each_entry_rcu (qmt, &merkle_tree_list, list) {
		// for (i = 0; i < FPCR_DATA_SIZE; ++i) {
		//     digest[i] = qe->fpcr->secret[i] ^ qe->fpcr->data[i];
		// }
		rc = crypto_shash_update(&desc.shash,
					 merkle_tree_root_data(qmt),
					 MERKLE_TREE_DATA_SIZE);
	}
	rcu_read_unlock();

	crypto_shash_final(&desc.shash, digest);

	// printk("[fpcr test] Successfully calculate the digest of ima_fpcrs");
	rc = ima_pcr_extend(digest, CONFIG_FPCR_BIND_PCR_INDEX);

	/* printk("[fpcr test] >>> randor xor all fpcrs value is: "); */
	/* for (i = 0; i < FPCR_DATA_SIZE; ++i) { */
	/*     printk(KERN_CONT "%02x ", digest[i]); */
	/* } */

	// printk("[fpcr test] Successfully bind all ima_fpcrs into pcr[%d]",
	// CONFIG_FPCR_BIND_PCR_INDEX);

	return rc;
}

/* extend to the related ima_fpcr and set the iterative value into PCR */
static int ima_fpcr_extend(const u8 *hash, struct fpcr_list *list)
{
	int i;
	int rc = 0;

	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(list->mt->tfm)];
	} desc;

	desc.shash.tfm = list->mt->tfm;

	rc = crypto_shash_init(&desc.shash);
	if (rc != 0) {
		return rc;
	}

	merkle_tree_extend(list->mt, list->tree_node_id, hash);

	// printk("[fpcr test] extend fpcr[%u]: ", list->id);
	// for (i = 0; i < 20; i++) {
	// 	printk(KERN_CONT "%02x",
	// 	       merkle_tree_node_data(list->mt, list->tree_node_id)[i]);
	// }
	// printk("[fpcr test] HASH: ");
	// for (i = 0; i < 20; i++) {
	// 	printk(KERN_CONT "%02x", hash[i]);
	// }

	return rc;
}

/*
 * Add template entry to the measurement list and hash table, and
 * extend the pcr.
 *
 * On systems which support carrying the IMA measurement list across
 * kexec, maintain the total memory size required for serializing the
 * binary_runtime_measurements.
 */
int ima_fpcr_add_template_entry(struct ima_template_entry *entry, int violation,
				const char *op, struct inode *inode,
				const unsigned char *filename,
				unsigned int fpcr_id)
{
	u8 digest[TPM_DIGEST_SIZE];
	const char *audit_cause = "hash_added";
	char tpm_audit_cause[AUDIT_CAUSE_LEN_MAX];
	int audit_info = 1;
	int result = 0, tpmresult = 0;
	struct fpcr_list *list = NULL;

	mutex_lock(&ima_extend_list_mutex);

	/* printk("[fpcr test] ima_fpcr_add_template_entry with fpcr_id[%u]", fpcr_id); */
	if (fpcr_id != FPCR_NULL_ID) {
		// printk("[fpcr test] fpcr_id[%u] in ima_fpcr_add_template_entry",
		// fpcr_id);
		list = ima_fpcr_lookup_entry(fpcr_id);
	}

	if (!violation) {
		memcpy(digest, entry->digest, sizeof(digest));
		// if exist, it will not add measurement list
		if (ima_lookup_digest_entry(digest, entry->pcr)) {
			audit_cause = "hash_exists";
			result = -EEXIST;
			goto out;
		}
	}

	result = ima_fpcr_add_digest_entry(entry, 1, list);
	if (result < 0) {
		audit_cause = "ENOMEM";
		audit_info = 0;
		goto out;
	}

	if (violation) /* invalidate pcr */
		memset(digest, 0xff, sizeof(digest));

	// extend fpcr
	if (list && list->mt && list->tree_node_id) {
		// printk("[fpcr test] prepared to extend fpcr with %s", filename);

		tpmresult = ima_fpcr_extend(digest, list);
		if (tpmresult != 0) {
			printk("[fpcr test] ERROR: failed to extend fpcr");
		}
		tpmresult = ima_fpcr_bind();
		if (tpmresult != 0) {
			printk("[fpcr test] ERROR: failed to bind fpcr");
		}
	} else {
		/* if (!list) { */
		/*     printk("[fpcr test] list not exist"); */
		/* } */
		/* else if (list && !list->fpcr) { */
		/*     printk("[fpcr test] list->fpcr not exist"); */
		/* } */
		/* else if (!list->fpcr->tfm) { */
		/*     printk("[fpcr test] list->fpcr->tfm not exist"); */
		/* } */
		tpmresult = ima_pcr_extend(digest, CONFIG_IMA_MEASURE_PCR_IDX);
	}

	if (tpmresult != 0) {
		snprintf(tpm_audit_cause, AUDIT_CAUSE_LEN_MAX, "TPM_error(%d)",
			 tpmresult);
		audit_cause = tpm_audit_cause;
		audit_info = 0;
	}

out:
	mutex_unlock(&ima_extend_list_mutex);
	integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename, op,
			    audit_cause, result, audit_info);

	return result;
}
#endif /* CONFIG_IMA_FPCR */

int ima_restore_measurement_entry(struct ima_template_entry *entry)
{
	int result = 0;

	mutex_lock(&ima_extend_list_mutex);
	result = ima_add_digest_entry(entry, 0);
	mutex_unlock(&ima_extend_list_mutex);
	return result;
}

int __init ima_init_digests(void)
{
	int i;

	if (!ima_tpm_chip)
		return 0;

	digests = kcalloc(ima_tpm_chip->nr_allocated_banks, sizeof(*digests),
			  GFP_NOFS);
	if (!digests)
		return -ENOMEM;

	for (i = 0; i < ima_tpm_chip->nr_allocated_banks; i++)
		digests[i].alg_id = ima_tpm_chip->allocated_banks[i].alg_id;

	return 0;
}

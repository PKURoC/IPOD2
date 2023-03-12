//
// Created by sspku on 2021/7/19.
//

#include <linux/ima.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/hash.h>

#include "ima.h"

int ima_record_task_for_fpcr(unsigned int fpcr_id);

struct fpcr_list user_id_fpcr_list;
struct ima_fpcr_history fpcr_for_history;

/*
 * ima_store_measurement - store file measurement
 *
 * Create an "ima" template and then store the template by calling
 * ima_store_template.
 *
 * We only get here if the inode has not already been measured,
 * but the measurement could already exist:
 *	- multiple copies of the same file on either the same or
 *	  different filesystems.
 *	- the inode was previously flushed as well as the iint info,
 *	  containing the hashing info.
 *
 * Must be called with iint->mutex held.
 */
void ima_fpcr_store_measurement(
	struct integrity_iint_cache *iint, struct file *file,
	const unsigned char *filename, struct evm_ima_xattr_data *xattr_value,
	int xattr_len, const struct modsig *modsig, int pcr,
	struct ima_template_desc *template_desc, unsigned int fpcr_id)
{
	static const char op[] = "add_template_measure";
	static const char audit_cause[] = "ENOMEM";
	int result = -ENOMEM;
	struct inode *inode = file_inode(file);
	struct ima_template_entry *entry;
	struct ima_event_data event_data = { .iint = iint,
					     .file = file,
					     .filename = filename,
					     .xattr_value = xattr_value,
					     .xattr_len = xattr_len,
					     .modsig = modsig };
	int violation = 0;

	/*
	 * We still need to store the measurement in the case of MODSIG because
	 * we only have its contents to put in the list at the time of
	 * appraisal, but a file measurement from earlier might already exist in
	 * the measurement list.
	 */
	if (iint->measured_pcrs & (0x1 << pcr) && !modsig)
		return;

	result = ima_alloc_init_template(&event_data, &entry, template_desc);
	if (result < 0) {
		integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode, filename, op,
				    audit_cause, result, 0);
		return;
	}

	result = ima_fpcr_store_template(entry, violation, inode, filename, pcr,
					 fpcr_id);
	/* printk("[fpcr test] exit ima_fpcr_store_template in %s with %d", __FUNCTION__, result); */
	if ((!result || result == -EEXIST) && !(file->f_flags & O_DIRECT)) {
		iint->flags |= IMA_MEASURED;
		iint->measured_pcrs |= (0x1 << pcr);
	}
	if (result < 0)
		ima_free_template_entry(entry);
}

/*
 * ima_store_template - store ima template measurements
 *
 * Calculate the hash of a template entry, add the template entry
 * to an ordered list of measurement entries maintained inside the kernel,
 * and also update the aggregate integrity value (maintained inside the
 * configured TPM PCR) over the hashes of the current list of measurement
 * entries.
 *
 * Applications retrieve the current kernel-held measurement list through
 * the securityfs entries in /sys/kernel/security/ima. The signed aggregate
 * TPM PCR (called quote) can be retrieved using a TPM user space library
 * and is used to validate the measurement list.
 *
 * Returns 0 on success, error code otherwise
 */
int ima_fpcr_store_template(struct ima_template_entry *entry, int violation,
			    struct inode *inode, const unsigned char *filename,
			    int pcr, unsigned int fpcr_id)
{
	static const char op[] = "add_template_measure";
	static const char audit_cause[] = "hashing_error";
	char *template_name = entry->template_desc->name;
	int result;
	struct {
		struct ima_digest_data hdr;
		char digest[TPM_DIGEST_SIZE];
	} hash;

	if (!violation) {
		int num_fields = entry->template_desc->num_fields;

		/* this function uses default algo */
		hash.hdr.algo = HASH_ALGO_SHA1;
		result = ima_calc_field_array_hash(&entry->template_data[0],
						   entry->template_desc,
						   num_fields, &hash.hdr);
		if (result < 0) {
			integrity_audit_msg(AUDIT_INTEGRITY_PCR, inode,
					    template_name, op, audit_cause,
					    result, 0);
			return result;
		}
		memcpy(entry->digest, hash.hdr.digest, hash.hdr.length);
	}
	entry->pcr = pcr;
	result = ima_fpcr_add_template_entry(entry, violation, op, inode,
					     filename, fpcr_id);
	/* printk("[fpcr test] exit ima_fpcr_add_template_entry in %s with %d", __FUNCTION__, result); */
	return result;
}

static int ima_fpcr_do_record(char *filename, unsigned int fpcr_id)
{
	struct ima_template_entry *entry;
	struct integrity_iint_cache tmp_iint, *iint = &tmp_iint;
	struct ima_event_data event_data = { .iint = iint,
					     .filename = filename };

	/* printk("[fpcr test] ima_add_fpcr_task filename: %s", filename); */

	int result = -ENOMEM;
	int violation = 0;
	struct {
		struct ima_digest_data hdr;
		char digest[FPCR_DATA_SIZE];
	} hash;

	memset(iint, 0, sizeof(*iint));
	memset(&hash, 0, sizeof(hash));
	iint->ima_hash = &hash.hdr;
	iint->ima_hash->algo = ima_hash_algo;
	iint->ima_hash->length = hash_digest_size[ima_hash_algo];

	// printk("[fpcr test] fill zero in no file event\n");
	/* result = ima_calc_file_hash(file, &hash.hdr); */
	/* if (result < 0) { */
	/*     return result; */
	/* } */

	// printk("[fpcr test] prepare to succeed\n");
	result = ima_alloc_init_template(&event_data, &entry, NULL);
	if (result < 0) {
		return result;
	}

	// printk("[fpcr test] prepare to record\n");
	result = ima_fpcr_store_template(entry, violation, NULL, filename,
					 CONFIG_IMA_MEASURE_PCR_IDX, fpcr_id);
	if (result < 0) {
		ima_free_template_entry(entry);
	}

	// printk("[fpcr test] ima_fpcr_add_task succeed\n");
	return result;
}

int ima_fpcr_invoke_measure(struct ima_file_label *flabel)
{
	unsigned int fpcr_id = hash_ima_file_label(flabel);
	char *fpcr_pathname = kmalloc(PATH_MAX + 22, GFP_KERNEL);
	ima_file_label_to_string(flabel, fpcr_pathname, PATH_MAX + 22);
	// printk("[fpcr test] get fpcr_pathname[%s] in ima_fpcr_invoke_measure",
	//        fpcr_pathname);

	return ima_fpcr_do_record(fpcr_pathname, fpcr_id);
}

int __init ima_init_fpcr_structures(void)
{
	int rc = 0;
	fpcr_for_history.tfm = crypto_alloc_shash("sha1", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(fpcr_for_history.tfm)) {
		rc = PTR_ERR(fpcr_for_history.tfm);
		printk("[fpcr test] ERROR: Can not allocate tfm (rc: %d)", rc);
		return -1;
	}

	memset(fpcr_for_history.data, 0x00, FPCR_DATA_SIZE);

	return 0;
}

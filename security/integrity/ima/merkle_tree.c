#include "asm/string_64.h"
#include "linux/list.h"
#include "linux/slab.h"
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>

#include "ima.h"

struct list_head merkle_tree_list;

#define merkle_tree_node_get(mt, node, attr) ((mt)->node_list[node].attr)
#define merkle_tree_node_set(mt, node, flag)                                   \
	do {                                                                   \
		(mt)->node_list[node].flag = 1;                                \
	} while (0)

static int merkle_tree_node_set_random(struct merkle_tree *mt, int node)
{
	int rc;

	if (merkle_tree_node_get(mt, node, used) ||
	    merkle_tree_node_get(mt, node, random)) {
		return 0;
	}

	rc = ima_get_random(merkle_tree_node_data(mt, node),
			    MERKLE_TREE_DATA_SIZE);
	if (rc <= 0) {
		printk("[fpcr test] Error get random failed\n");
		return rc;
	}
	merkle_tree_node_set(mt, node, random);
	return 0;
}

static int calc_two_data_hash(struct merkle_tree *mt, u8 *dst, u8 *left,
			      const u8 *right, int len)
{
	struct {
		struct shash_desc shash;
		char ctx[crypto_shash_descsize(mt->tfm)];
	} desc;
	int rc = 0;

	desc.shash.tfm = mt->tfm;
	rc = crypto_shash_init(&desc.shash);
	if (rc != 0) {
		return rc;
	}

	rc = crypto_shash_update(&desc.shash, left, len);
	rc = crypto_shash_update(&desc.shash, right, len);
	crypto_shash_final(&desc.shash, dst);
	return 0;
}

static int calc_two_node_hash(struct merkle_tree *mt, int node_1, int node_2,
			      int parent)
{
	merkle_tree_node_set_random(mt, node_1);
	merkle_tree_node_set_random(mt, node_2);

	return calc_two_data_hash(mt, merkle_tree_node_get(mt, parent, data),
				  merkle_tree_node_get(mt, node_1, data),
				  merkle_tree_node_get(mt, node_2, data),
				  MERKLE_TREE_DATA_SIZE);
}

int merkle_tree_init(struct merkle_tree **mt)
{
	int rc = 0;
	static int id = 1;

	*mt = (struct merkle_tree *)kmalloc(
		MERKLE_TREE_SIZE * sizeof(struct merkle_tree_node), GFP_KERNEL);
	if (!(*mt)) {
		printk("[fpcr test] ERROR: alloc merkle_tree failed");
		return 1;
	}
	memset((*mt)->node_list, 0,
	       MERKLE_TREE_SIZE * sizeof(struct merkle_tree_node));
	(*mt)->id = id++;
	(*mt)->last_empty = MERKLE_TREE_SIZE / 2;
	(*mt)->tfm = crypto_alloc_shash("sha1", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR((*mt)->tfm)) {
		rc = PTR_ERR((*mt)->tfm);
		printk("[fpcr test] ERROR: Can not allocate tfm (reason: %d)\n",
		       rc);
		kfree((*mt));

		return rc;
	}
	return 0;
}

// Set used flag at first extend, not get
int merkle_tree_get_empty(struct merkle_tree *mt)
{
	int start = mt->last_empty;
	// for (start = mt->last_empty; start < MERKLE_TREE_SIZE; ++start) {
	//     if (merkle_tree_node_used(mt, start) == 0) {
	//         mt->last_empty = start + 1;
	//         return start;
	//     }
	// }
	if (!merkle_tree_isfull(mt)) {
		(mt->last_empty)++;

		return start;
	}
	return 0;
}

int merkle_tree_update(struct merkle_tree *mt, int node, const u8 *data)
{
	int parent;

	if (node == 0) {
		return 0;
	}

	merkle_tree_node_set(mt, node, used);
	memcpy(merkle_tree_node_data(mt, node), data, MERKLE_TREE_DATA_SIZE);

	while (node > 1) {
		parent = node / 2;
		merkle_tree_node_set(mt, parent, used);
		if (node % 2) {
			calc_two_node_hash(mt, node - 1, node, parent);
		} else {
			calc_two_node_hash(mt, node, node + 1, parent);
		}
		node = parent;
	}
	return 0;
}

int merkle_tree_extend(struct merkle_tree *mt, int node, const u8 *data)
{
	int parent;
	int rc;
	int i;

	if (!merkle_tree_node_get(mt, node, used)) {
		merkle_tree_node_set(mt, node, used);
		memset(merkle_tree_node_get(mt, node, data), 0,
		       MERKLE_TREE_DATA_SIZE);
	}

	// 	printk("[fpcr test] [node %d] merkle tree extend [", node);
	// 	for (i = 0; i < MERKLE_TREE_DATA_SIZE; ++i) {
	// 		printk(KERN_CONT "%02x",
	// 		       merkle_tree_node_data(mt, node)[i]);
	// 	}
	// 	printk(KERN_CONT "] and [");
	// 	for (i = 0; i < MERKLE_TREE_DATA_SIZE; ++i) {
	// 		printk(KERN_CONT "%02x", data[i]);
	// 	}
	// 	printk(KERN_CONT "]");

	rc = calc_two_data_hash(mt, merkle_tree_node_get(mt, node, data),
				merkle_tree_node_get(mt, node, data), data,
				MERKLE_TREE_DATA_SIZE);
	if (rc) {
		printk("[fpcr test] extend merkle tree leaf failed");
		return rc;
	}
	// 	printk("[fpcr test] [node %d] merkle tree extend result: ",
	// 	       node);
	// 	for (i = 0; i < MERKLE_TREE_DATA_SIZE; ++i) {
	// 		printk(KERN_CONT "%02x",
	// 		       merkle_tree_node_data(mt, node)[i]);
	// 	}

	while (node > 1) {
		parent = node / 2;
		merkle_tree_node_set(mt, parent, used);
		if (node % 2) {
			rc = calc_two_node_hash(mt, node - 1, node, parent);
		} else {
			rc = calc_two_node_hash(mt, node, node + 1, parent);
		}
		node = parent;

		if (rc) {
			printk("[fpcr test] calc two node hash failed");
			return rc;
		}
	}
	return 0;
}

struct merkle_tree *merkle_tree_list_get_empty(void)
{
	struct merkle_tree *mt =
		list_last_entry(&merkle_tree_list, struct merkle_tree, list);
	if (list_empty(&merkle_tree_list) || merkle_tree_isfull(mt)) {
		if (merkle_tree_init(&mt)) {
			return NULL;
		}
		list_add_tail(&mt->list, &merkle_tree_list);
	}
	return mt;
}
// void merkle_tree_print(struct merkle_tree *mt) {
//     int i;
//     int j;
//     int count = 1;
//     for (i = 1; i < MERKLE_TREE_SIZE; ++i) {
//         printk("[fpcr test] {%d %d ", i, merkle_tree_node_used(mt, i));
//         for (j = 0; j < MERKLE_TREE_DATA_SIZE; ++j) {
//             printk(KERN_CONT "%02x", merkle_tree_node_data(mt, i)[j]);
//         }
//         if (i == (1 << count) - 1) {
//             count++;
//             printk(KERN_CONT "}\n");
//         } else {
//             printk(KERN_CONT "} ");
//         }
//     }
// }

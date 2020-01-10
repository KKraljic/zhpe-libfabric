/*
 * Copyright (c) 2017-2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <zhpe_offloaded.h>

#define ZHPE_OFFLOADED_LOG_DBG(...) _ZHPE_OFFLOADED_LOG_DBG(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_OFFLOADED_LOG_INFO(...) _ZHPE_OFFLOADED_LOG_INFO(FI_LOG_EP_CTRL, __VA_ARGS__)
#define ZHPE_OFFLOADED_LOG_ERROR(...) _ZHPE_OFFLOADED_LOG_ERROR(FI_LOG_EP_CTRL, __VA_ARGS__)

struct mem_wire_msg1 {
	uint32_t		rx_ring_size;
};

struct mem_wire_msg2 {
	uint64_t		key;
};

void zhpe_offloaded_tx_free(struct zhpe_offloaded_tx *ztx)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_pe_retry	*pe_retry;
	struct zhpeu_atm_snatch_head atm_list;
	struct zhpeu_atm_list_next *atm_cur;
	struct zhpeu_atm_list_next *atm_next;

	if (!ztx)
		return;

	zhpeu_atm_snatch_list(&ztx->pe_retry_list, &atm_list);
	for (atm_cur = atm_list.head; atm_cur; atm_cur = atm_next) {
		pe_retry = container_of(atm_cur, struct zhpe_offloaded_pe_retry, next);
		atm_next = atm_load_rlx(&atm_cur->next);
		if (atm_next == ZHPEU_ATM_LIST_END) {
			atm_next = NULL;
			break;
		}
		zhpe_offloaded_pe_retry_free(ztx, pe_retry);
	}
	while ((atm_cur = zhpeu_atm_fifo_pop(&ztx->pe_retry_free_list))) {
		pe_retry = container_of(atm_cur, struct zhpe_offloaded_pe_retry, next);
		free(pe_retry);
	}

	zhpe_offloaded_mr_put(ztx->zmr);
	zhpeq_free(ztx->zq);
	free(ztx->pentries);
	free(ztx->zentries);
	ztx->zentries = NULL;
	mutex_destroy(&ztx->mutex);
	free(ztx);
}

static int do_tx_setup(struct zhpe_offloaded_ep_attr *ep_attr, struct zhpe_offloaded_tx **ztx_out)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = -FI_ENOMEM;
	struct zhpe_offloaded_tx		*ztx = NULL;
	uint32_t		qlen;
	uint32_t		i;
	size_t			req;
	struct fid_mr		*mr;
	struct zhpe_offloaded_free_index	ufree;
	struct zhpe_offloaded_free_index	pfree;

	ztx = calloc_cachealigned(1, sizeof(*ztx));
	if (!ztx)
		goto done;
	dlist_init(&ztx->pe_lentry);
	ztx->ep_attr = ep_attr;
	qlen = roundup_power_of_two(ep_attr->ep->tx_attr.size) * 2;
	ztx->mask = qlen - 1;
	ztx->use_count = 1;
	zhpeu_atm_fifo_init(&ztx->pe_retry_free_list);
	mutex_init(&ztx->mutex, NULL);

	/* Allocate memory */
	req = sizeof(*ztx->pentries) * qlen;
	ret = -posix_memalign((void **)&ztx->pentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		ztx->pentries = NULL;
		goto done;
	}
	memset(ztx->pentries, 0, req);
	/* user free list */
	ufree.seq = 0;
	ufree.index = 0;
	ufree.count = qlen / 2;
	/* status/index in last entry doesn't matter, since it will
	 * never be checked because xfree.count will be zero.
	 */
	for (i = 0; i < qlen / 2  - 1; i++)
		ztx->pentries[i].pe_root.compstat.status = i + 1;
	atm_store_rlx(&ztx->ufree, ufree);
	/* provider free list */
	pfree.seq = 0;
	pfree.index = ++i;
	pfree.count = qlen / 2;
	for (; i < qlen - 1; i++)
		ztx->pentries[i].pe_root.compstat.status = i + 1;
	atm_store_rlx(&ztx->pfree, pfree);

	req = ZHPE_OFFLOADED_RING_ENTRY_LEN * qlen;
	ret = -posix_memalign((void **)&ztx->zentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		ztx->zentries = NULL;
		goto done;
	}

	/* Allocate queue from bridge. */
	ret = zhpeq_alloc(ep_attr->domain->zdom, qlen, qlen,
			  0, 0, 0, &ztx->zq);
	if (ret < 0)  {
		ZHPE_OFFLOADED_LOG_ERROR("zhpeq_alloc() error %d\n", ret);
		goto done;
	}
	memset(ztx->zentries, 0, req);

	/* Register zentries memory. */
	ret = zhpe_offloaded_mr_reg_int_uncached(ep_attr->domain, ztx->zentries, req,
				       FI_WRITE, 0, &mr);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpe_offloaded_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	ztx->zmr = container_of(mr, struct zhpe_offloaded_mr, mr_fid);
	ret = zhpeq_lcl_key_access(ztx->zmr->kdata, ztx->zentries,
				   0, 0, &ztx->lz_zentries);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpeq_lcl_key_access() error %d\n", ret);
		goto done;
	}

 done:
	if (ret < 0) {
		zhpe_offloaded_tx_put(ztx);
		ztx = NULL;
	}
	atm_store_rlx(ztx_out, ztx);

	return ret;
}

static inline void *scoreboard_alloc(struct zhpe_offloaded_rx_common *rx_cmn)
{
    PRINT_DEBUG_LIBFAB;
	const size_t		size = sizeof(*rx_cmn->scoreboard);
	const uint32_t		bits = size * CHAR_BIT;

	rx_cmn->scoreboard = calloc((rx_cmn->mask + bits) / bits, size);

	return rx_cmn->scoreboard;
}

static void zhpe_offloaded_tx_handle_conn_pull(struct zhpe_offloaded_pe_root *pe_root,
				     struct zhpeq_cq_entry *zq_cqe)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_conn	*conn = pe_root->conn;
	struct zhpe_offloaded_rx_peer_visible *peer = (void *)&zq_cqe->z.result;

	if (zq_cqe->z.status == ZHPEQ_CQ_STATUS_SUCCESS)
		atm_store_rlx(&conn->rx_remote.tail.shadow_head,
			      ntohl(atm_load_rlx(&peer->completed)));
	else
		ZHPE_OFFLOADED_LOG_ERROR("status : %d\n", zq_cqe->z.status);
	atm_dec(&conn->rx_remote.pull_busy);
}

static void do_rx_free(struct zhpe_offloaded_conn *conn)
{
    PRINT_DEBUG_LIBFAB;
	zhpe_offloaded_rkey_put(conn->rx_remote.cmn.rkey);
	conn->rx_remote.cmn.rkey = NULL;
	zhpe_offloaded_mr_put(conn->rx_local.cmn.zmr);
	conn->rx_local.cmn.zmr = NULL;
	free(conn->rx_local.zentries);
	conn->rx_local.zentries = NULL;
	free(conn->rx_local.cmn.scoreboard);
	conn->rx_local.cmn.scoreboard = NULL;
	free(conn->rx_remote.cmn.scoreboard);
	conn->rx_remote.cmn.scoreboard = NULL;
}

static int do_rx_setup(struct zhpe_offloaded_conn *conn, int conn_fd)
{
    PRINT_DEBUG_LIBFAB;
	int			ret;
	struct zhpe_offloaded_ep_attr	*ep_attr = conn->ep_attr;
	struct zhpe_offloaded_ep		*ep = conn->ep_attr->ep;
	struct zhpe_offloaded_rx_local	*rx_ringl = &conn->rx_local;
	struct zhpe_offloaded_rx_remote	*rx_ringr = &conn->rx_remote;
	char			blob[ZHPEQ_KEY_BLOB_MAX];
	struct zhpe_offloaded_msg_hdr	ohdr = { .op_type = 0 };
	struct mem_wire_msg1	mem_msg1;
	struct mem_wire_msg2	mem_msg2;
	size_t			blob_len;
	uint32_t		qlenl;
	uint32_t		qlenr;
	struct fid_mr		*mr;
	size_t			off;
	size_t			req;

	memset(rx_ringl, 0, sizeof(*rx_ringl));
	memset(rx_ringr, 0, sizeof(*rx_ringr));
	rx_ringr->pull_pe_root.handler = zhpe_offloaded_tx_handle_conn_pull;
	rx_ringr->pull_pe_root.conn = conn;

	/* rx ring will be the same as the tx size. */
	qlenr = roundup_power_of_two(ep->tx_attr.size) * 2;
	mem_msg1.rx_ring_size = htonl(qlenr);
	if (conn_fd != -1) {
		ret = zhpe_offloaded_send_blob(conn_fd, &mem_msg1, sizeof(mem_msg1));
		if (ret < 0)
			goto done;
		ret = zhpe_offloaded_recv_fixed_blob(conn_fd, &mem_msg1,
					   sizeof(mem_msg1));
		if (ret < 0)
			goto done;
	}
	qlenl = ntohl(mem_msg1.rx_ring_size);

	rx_ringl->cmn.mask = qlenl - 1;
	rx_ringr->cmn.mask = qlenr - 1;

	ret = -FI_ENOMEM;

	/* Allocate local rx ring memory. */
	if (!scoreboard_alloc(&rx_ringl->cmn))
		goto done;

	/* +1 for peer visible cache line. */
	req = ZHPE_OFFLOADED_RING_ENTRY_LEN * (qlenl + 1);
	ret = -posix_memalign((void **)&rx_ringl->zentries,
			      ofi_sysconf(_SC_PAGESIZE), req);
	if (ret < 0) {
		rx_ringl->zentries = NULL;
		goto done;
	}
	memset(rx_ringl->zentries, 0, req);

	/* Register zentries memory. */
	ret = zhpe_offloaded_mr_reg_int_uncached(ep_attr->domain, rx_ringl->zentries, req,
				       FI_REMOTE_READ | FI_REMOTE_WRITE,
				       ZHPEQ_MR_KEY_ZERO_OFF, &mr);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpe_offloaded_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	rx_ringl->cmn.zmr = container_of(mr, struct zhpe_offloaded_mr, mr_fid);

	/* Exchange key information. */
	blob_len = sizeof(blob);
	ret = zhpeq_zmmu_export(zhpeq_dom(conn->ztx->zq),
				rx_ringl->cmn.zmr->kdata, blob, &blob_len);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpeq_zmmu_export() error %d\n", ret);
		goto done;
	}

	mem_msg2.key = htobe64(fi_mr_key(mr));
	if (conn_fd != -1) {
		ret = zhpe_offloaded_send_blob(conn_fd, &mem_msg2, sizeof(mem_msg2));
		if (ret < 0)
			goto done;
		ret = zhpe_offloaded_send_blob(conn_fd, blob, blob_len);
		if (ret < 0)
			goto done;
		ret = zhpe_offloaded_recv_fixed_blob(conn_fd, &mem_msg2,
					   sizeof(mem_msg2));
		if (ret < 0)
			goto done;
		ret = zhpe_offloaded_recv_fixed_blob(conn_fd, blob, blob_len);
		if (ret < 0)
			goto done;
	}

	ret = zhpe_offloaded_conn_rkey_import(conn, ohdr, be64toh(mem_msg2.key),
				    blob, blob_len, &rx_ringr->cmn.rkey);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpeq_conn_key_import() error %d\n", ret);
		goto done;
	}
	ret = zhpeq_rem_key_access(rx_ringr->cmn.rkey->kdata, 0, 0, 0,
				   &rx_ringr->rz_zentries);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpeq_rem_key_access() error %d\n", ret);
		goto done;
	}
	/* Set up pushed locations. */
	off = ZHPE_OFFLOADED_RING_ENTRY_LEN * qlenl;
	rx_ringl->peer_visible = (void *)(rx_ringl->zentries + off);
	off = ZHPE_OFFLOADED_RING_ENTRY_LEN * qlenr;
	rx_ringr->rz_peer_visible = rx_ringr->rz_zentries + off;
 done:
	if (ret < 0)
		do_rx_free(conn);

	return ret;
}

int zhpe_offloaded_compare_zkeys(void *vk1, void *vk2)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_key		*k1 = (void *)vk1;
	struct zhpe_offloaded_key		*k2 = (void *)vk2;

	if (k1->key < k2->key)
		return -1;
	else if (k1->key > k2->key)
		return 1;

	return memcmp(&k1->internal, &k2->internal, sizeof(k1->internal));
}

int zhpe_offloaded_conn_z_setup(struct zhpe_offloaded_conn *conn, int conn_fd)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_ep_attr	*ep_attr = conn->ep_attr;
	union sockaddr_in46	sa;
	size_t			sa_len = sizeof(sa);

	mutex_lock(&ep_attr->conn_mutex);
	if (!ep_attr->ztx)
		ret = do_tx_setup(ep_attr, &ep_attr->ztx);
	if (ret >= 0) {
		conn->ztx = ep_attr->ztx;
		atm_inc(&ep_attr->ztx->use_count);
	}
	mutex_unlock(&ep_attr->conn_mutex);
	if (ret < 0)
		goto done;
	zhpe_offloaded_pe_add_queue(ep_attr->ztx);
	/* Init remote mr tree. */
	dlist_init(&conn->rkey_deferred_list);
	ret = -FI_ENOMEM;
	conn->rkey_tree = rbtNew(zhpe_offloaded_compare_zkeys);
	if (!conn->rkey_tree)
		goto done;
	conn->kexp_tree = rbtNew(zhpe_offloaded_compare_zkeys);
	if (!conn->kexp_tree)
		goto done;
	/* Get address index. */
	ret = zhpeq_backend_exchange(conn->ztx->zq, conn_fd, &sa, &sa_len);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("%s,%u:zhpeq_backend_exchange() error %d\n",
			       __FUNCTION__, __LINE__, ret);
		goto done;
	}
	ret = zhpeq_backend_open(conn->ztx->zq, &sa);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("%s,%u:zhpeq_backend_open() error %d\n",
			       __FUNCTION__, __LINE__, ret);
		goto done;
	}
	conn->zq_index = ret;

	/* Exchange information and setup rx rings */
	ret = do_rx_setup(conn, conn_fd);
	if (ret < 0)
		goto done;
	/* FIXME: Rethink for multiple contexts. */
	conn->tx_ctx = ep_attr->tx_ctx;
	conn->rx_ctx = ep_attr->rx_ctx;
	mutex_lock(&ep_attr->conn_mutex);
	conn->state = ZHPE_OFFLOADED_CONN_STATE_READY;
	zhpeu_atm_snatch_insert(&conn->ztx->rx_poll_list,
				&conn->rx_poll_next);
	mutex_unlock(&ep_attr->conn_mutex);
	cond_broadcast(&ep_attr->conn_cond);
	ret = 0;

 done:
	return ret;
}
int zhpe_offloaded_conn_fam_setup(struct zhpe_offloaded_conn *conn)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_ep_attr	*ep_attr = conn->ep_attr;
	struct zhpe_offloaded_rkey_data	*new;

	mutex_lock(&ep_attr->conn_mutex);
	if (!ep_attr->ztx)
		ret = do_tx_setup(ep_attr, &ep_attr->ztx);
	if (ret >= 0) {
		conn->ztx = ep_attr->ztx;
		atm_inc(&ep_attr->ztx->use_count);
	}
	mutex_unlock(&ep_attr->conn_mutex);
	if (ret < 0)
		goto done;
	zhpe_offloaded_pe_add_queue(ep_attr->ztx);
	/* Init remote mr tree. */
	dlist_init(&conn->rkey_deferred_list);
	ret = -FI_ENOMEM;
	conn->rkey_tree = rbtNew(zhpe_offloaded_compare_zkeys);
	if (!conn->rkey_tree)
		goto done;
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	atm_inc(&conn->ztx->use_count);
	new->ztx = conn->ztx;
	new->zkey.key = 0;
	new->zkey.internal = false;
	new->kdata = NULL;
	new->ohdr = (struct zhpe_offloaded_msg_hdr){ 0 };
	new->use_count = 1;
	zhpe_offloaded_rkey_rbtInsert(conn->rkey_tree, new);
	/* Get address index. */
	ret = zhpeq_backend_open(conn->ztx->zq, &conn->addr);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("%s,%u:zhpeq_backend_open() error %d\n",
			       __FUNCTION__, __LINE__, ret);
		goto done;
	}
	conn->zq_index = ret;
	/* Set up rkey entry for FAM.*/
	ret = zhpeq_zmmu_fam_import(ep_attr->domain->zdom, conn->zq_index,
				    false,  &new->kdata);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("%s,%u:zhpeq_zmmu_fam_import() error %d\n",
			       __FUNCTION__, __LINE__, ret);
		goto done;
	}
	/* FIXME: Rethink for multiple contexts. */
	conn->tx_ctx = ep_attr->tx_ctx;
	conn->rx_ctx = ep_attr->rx_ctx;
	mutex_lock(&ep_attr->conn_mutex);
	conn->state = ZHPE_OFFLOADED_CONN_STATE_READY;
	mutex_unlock(&ep_attr->conn_mutex);
	cond_broadcast(&ep_attr->conn_cond);
	ret = 0;

 done:
	return ret;
}

void zhpe_offloaded_rkey_free(struct zhpe_offloaded_rkey_data *rkey)
{
    PRINT_DEBUG_LIBFAB;
	zhpeq_zmmu_free(zhpeq_dom(rkey->ztx->zq), rkey->kdata);
	zhpe_offloaded_tx_put(rkey->ztx);
	free(rkey);
}

void zhpe_offloaded_conn_z_free(struct zhpe_offloaded_conn *conn)
{
    PRINT_DEBUG_LIBFAB;
	RbtIterator		*rbt;
	struct zhpe_offloaded_rkey_data	*rkey;
	struct zhpe_offloaded_kexp_data	*kexp;

	if (conn->rkey_tree) {
		/* Is lock initialized? */
		if (conn->kexp_tree) {
			/* FIXME: Think about driver disconnect. */
			fastlock_acquire(&conn->ep_attr->domain->lock);
			while ((rbt = rbtBegin(conn->kexp_tree)))  {
				kexp = zhpe_offloaded_rbtKeyValue(conn->kexp_tree, rbt);
				rbtErase(conn->kexp_tree, rbt);
				dlist_remove(&kexp->lentry);
				free(kexp);
			}
			rbtDelete(conn->kexp_tree);
			fastlock_release(&conn->ep_attr->domain->lock);
		}
		while (!dlist_empty(&conn->rkey_deferred_list)) {
			dlist_pop_front(&conn->rkey_deferred_list,
					struct zhpe_offloaded_rkey_data, rkey, lentry);
			zhpe_offloaded_rkey_free(rkey);
		}
		while ((rbt = rbtBegin(conn->rkey_tree)))  {
			rkey = zhpe_offloaded_rbtKeyValue(conn->rkey_tree, rbt);
			rbtErase(conn->rkey_tree, rbt);
			zhpe_offloaded_rkey_free(rkey);
		}
		rbtDelete(conn->rkey_tree);
		conn->rkey_tree = NULL;
	}
	do_rx_free(conn);
	if (conn->zq_index != FI_ADDR_NOTAVAIL)
		zhpeq_backend_close(conn->ztx->zq, conn->zq_index);
	zhpe_offloaded_tx_put(conn->ztx);
}

int __zhpe_offloaded_conn_pull(struct zhpe_offloaded_conn *conn)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_rx_remote	*rx_ringr = &conn->rx_remote;
	uint32_t		zindex;

	ret = zhpeq_reserve(conn->ztx->zq, 1);
	if (ret < 0)
		goto done;
	zindex = ret;
	ret = zhpeq_geti(conn->ztx->zq, zindex, false,
			 sizeof(struct zhpe_offloaded_rx_peer_visible),
			 rx_ringr->rz_peer_visible,
			 &rx_ringr->pull_pe_root);
	if (ret < 0)
		goto done;
	ret = zhpe_offloaded_zq_commit_spin(conn->ztx->zq, zindex, 1);

 done:
	if (ret < 0)
		ZHPE_OFFLOADED_LOG_ERROR("pull failed:error %d\n", ret);

	return ret;
}

int zhpe_offloaded_tx_free_res(struct zhpe_offloaded_conn *conn, int64_t tindex,
		     int64_t zindex, int64_t rindex, uint8_t pe_flags)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_tx		*ztx = conn->ztx;

	if (!conn)
		goto done;

	/* We assume ordered allocation: zq then rx ring; tx_buf can
	 * be freed without problems. index < 0 indicates item was
	 * not allocated.
	 */
	if (tindex >= 0)
		zhpe_offloaded_tx_release(&ztx->pentries[tindex]);

	if (zindex < 0)
		goto done;

	/* If no rx_ring space, send NOP to bridge. */
	if (rindex < 0) {
		ret = zhpeq_nop(ztx->zq, zindex, false,
				ZHPE_OFFLOADED_CONTEXT_IGNORE_PTR);
		if (ret < 0)
			goto done;
		goto commit;
	}

	/* Send NOP to receive ring... this shouldn't happen since
	 * we shouldn't reserve the ring slot until we have all the
	 * resources; so just abort.
	 */
	abort();

commit:
	ret = zhpe_offloaded_zq_commit_spin(ztx->zq, zindex, 1);
	if (ret < 0)
		goto done;
 done:

	return ret;
}

#define	CHUNK_SIZE_OFF		offsetof(struct zhpe_offloaded_slab_free_entry, size)
#define	CHUNK_DATA_OFF		offsetof(struct zhpe_offloaded_slab_free_entry, lentry)
#define CHUNK_SIZE_SIZE		(CHUNK_DATA_OFF - CHUNK_SIZE_OFF)
#define CHUNK_SIZE_MIN \
	(sizeof(struct zhpe_offloaded_slab_free_entry) - CHUNK_DATA_OFF)
#define CHUNK_SIZE_PINUSE	((uintptr_t)1)
#define CHUNK_SIZE_MASK		(~(sizeof(uintptr_t) - 1))

static inline void *ptr_to_chunk(void *ptr)
{
    PRINT_DEBUG_LIBFAB;
	return ((char *)ptr - CHUNK_DATA_OFF);
}

static inline size_t chunk_size(size_t csize)
{
    PRINT_DEBUG_LIBFAB;
	return (csize & CHUNK_SIZE_MASK) + CHUNK_SIZE_SIZE;
}

static inline void *_next_chunk(struct zhpe_offloaded_slab_free_entry *chunk)
{
    PRINT_DEBUG_LIBFAB;
	return ((char *)chunk + chunk_size(chunk->size));
}

static inline void *_prev_chunk(struct zhpe_offloaded_slab_free_entry *chunk)
{
    PRINT_DEBUG_LIBFAB;
	return ((char *)chunk - chunk_size(chunk->prev_size));
}

static inline void *prev_chunk(struct zhpe_offloaded_slab_free_entry *chunk)
{
    PRINT_DEBUG_LIBFAB;
	if (chunk->size & CHUNK_SIZE_PINUSE)
		return NULL;
	return _prev_chunk(chunk);
}

#if 0

#define CHUNK_SIZE_SEEN		((uintptr_t)4)

static uint64_t			slab_check_path;
static void			*slab_check_ptr[4];
struct zhpe_offloaded_slab_free_entry	slab_check_chunk[4];

static void slab_check_save_path(uint shift)
{
	if (!shift)
		slab_check_path = 0;
	else
		slab_check_path |= (1 << shift);
}

static void slab_check_save(struct zhpe_offloaded_slab_free_entry *chunk, uint idx)
{
	if (idx >= ARRAY_SIZE(slab_check_ptr) ||
	    idx >= ARRAY_SIZE(slab_check_chunk))
		abort();
	if (!idx) {
		memset(slab_check_ptr, 0, sizeof(slab_check_ptr));
		memset(slab_check_chunk, 0, sizeof(slab_check_chunk));
	} else if (idx == 3) {
		/* nextnext */
		if (!(slab_check_chunk[2].size & CHUNK_SIZE_MASK))
			return;
	}
	slab_check_ptr[idx] = chunk;
	if (chunk)
		slab_check_chunk[idx] = *chunk;
}

static void slab_check(struct zhpe_offloaded_slab *slab)
{
	struct zhpe_offloaded_slab_free_entry *prev;
	struct zhpe_offloaded_slab_free_entry *chunk;
	struct zhpe_offloaded_slab_free_entry *next;
	struct zhpe_offloaded_slab_free_entry *free;
	size_t			free_count;

	/* Clear seen bits in free list. */
	dlist_foreach_container(&slab->free_list, struct zhpe_offloaded_slab_free_entry,
				free, lentry)
		free->size &= ~CHUNK_SIZE_SEEN;

	free_count = 0;
	prev = NULL;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	for (;;) {
		/* All free chunks should have had their SEEN bit cleared. */
		next = _next_chunk(chunk);
		if (!(next->size & CHUNK_SIZE_PINUSE)) {
			if (chunk->size & CHUNK_SIZE_SEEN)
				abort();
			chunk->size |= CHUNK_SIZE_SEEN;
			free_count++;
			if (_prev_chunk(next) != chunk)
				abort();
		}
		/* Current chunk and previous agree? */
		if (prev) {
			if (!(chunk->size & CHUNK_SIZE_PINUSE) &&
			    _prev_chunk(chunk) != prev)
				abort();
		}
		/* End marker? */
		if (!(next->size & CHUNK_SIZE_MASK)) {
			/* End marker in write place? */
			if (next != (void *)((char *)slab->mem + slab->size -
					     CHUNK_DATA_OFF))
				abort();
			break;
		}
		/* Shuffle. */
		prev = chunk;
		chunk = next;
	}

	/* Check seen bits in free list. */
	dlist_foreach_container(&slab->free_list, struct zhpe_offloaded_slab_free_entry,
				free, lentry) {
		if (!free_count)
			abort();
		if (!(free->size & CHUNK_SIZE_SEEN))
			abort();
		free->size &= ~CHUNK_SIZE_SEEN;
	}
}

static void slab_check_freed(struct zhpe_offloaded_slab *slab,
			     struct zhpe_offloaded_slab_free_entry *freed)
{
	struct zhpe_offloaded_slab_free_entry *chunk;
	struct zhpe_offloaded_slab_free_entry *next;

	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	for (;;) {
		if (chunk == freed)
			break;
		next = _next_chunk(chunk);
		/* End marker? */
		if (!(next->size & CHUNK_SIZE_MASK))
			abort();
		chunk = next;
	}
}

#else

static inline void slab_check_save_path(uint shift)
{
}

static inline void slab_check_save(struct zhpe_offloaded_slab_free_entry *chunk,
				   uint idx)
{
}

static inline void slab_check(struct zhpe_offloaded_slab *slab)
{
}

static void slab_check_freed(struct zhpe_offloaded_slab *slab,
			     struct zhpe_offloaded_slab_free_entry *freed)
{
}

#endif

int zhpe_offloaded_slab_init(struct zhpe_offloaded_slab *slab, size_t size,
		   struct zhpe_offloaded_domain *domain)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = -FI_ENOMEM;
	struct zhpe_offloaded_slab_free_entry *chunk;
	struct fid_mr		*mr;

	/* Align to pointer size boundary; assumed to be power of 2
	 * and greater than 2; so bit 0 will always be zero.
	 */
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	slab->size = size;
	dlist_init(&slab->free_list);
	slab->mem = malloc(size);
	if (!slab->mem)
		goto done;
	ret = 0;
	if (size < CHUNK_SIZE_MIN + 2 * CHUNK_SIZE_SIZE)
		goto done;
	size -= 2 * CHUNK_SIZE_SIZE;
	chunk = (void *)((char *)slab->mem - CHUNK_SIZE_OFF);
	chunk->size = (size | CHUNK_SIZE_PINUSE);
	dlist_insert_tail(&chunk->lentry, &slab->free_list);
	chunk = _next_chunk(chunk);
	chunk->size = 0;

	ret = zhpe_offloaded_mr_reg_int_uncached(domain, slab->mem, slab->size,
				       FI_READ | FI_WRITE, 0, &mr);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpe_offloaded_mr_reg_int_uncached() error %d\n", ret);
		goto done;
	}
	slab->zmr = container_of(mr, struct zhpe_offloaded_mr, mr_fid);
 done:
	return ret;
}

void zhpe_offloaded_slab_destroy(struct zhpe_offloaded_slab *slab)
{
    PRINT_DEBUG_LIBFAB;
	if (slab->mem) {
		slab_check(slab);
		zhpe_offloaded_mr_put(slab->zmr);
		slab->zmr = NULL;
		free(slab->mem);
		slab->mem = NULL;
	}
}

int zhpe_offloaded_slab_alloc(struct zhpe_offloaded_slab *slab, size_t size,  struct zhpe_offloaded_iov *iov)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = -ENOMEM;
	struct zhpe_offloaded_slab_free_entry *chunk;
	struct zhpe_offloaded_slab_free_entry *next;

	if (!slab->mem)
		goto done;

	iov->iov_len = size | ZHPE_OFFLOADED_ZIOV_LEN_KEY_INT;
	size = (size + ~CHUNK_SIZE_MASK) & CHUNK_SIZE_MASK;
	if (size < CHUNK_SIZE_MIN)
		size = CHUNK_SIZE_MIN;
	/* Just first fit because it is fast and entries are transient.
	 * Every free entry should have the PINUSE bit set because,
	 * otherwise, it would be merged with another block.
	 */
	dlist_foreach_container(&slab->free_list, struct zhpe_offloaded_slab_free_entry,
				chunk, lentry) {
		if (chunk->size >= size)
			goto found;
	}
	goto done;
 found:
	/* Do we have space to divide the chunk?
	 * We need space for the pointers (CHUNK_SIZE_MIN) +
	 * space for prev_size (CHUNK_SIZE_OFF).
	 */
	if (chunk->size - size <= CHUNK_SIZE_MIN + CHUNK_SIZE_SIZE + 1) {
		/* No. */
		dlist_remove(&chunk->lentry);
		iov->iov_base = ((char *)chunk + CHUNK_DATA_OFF);
	} else {
		chunk->size -= size + CHUNK_SIZE_SIZE;
		next = _next_chunk(chunk);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size = size;
		iov->iov_base = ((char *)next + CHUNK_DATA_OFF);
		chunk = next;
	}
	next = _next_chunk(chunk);
	next->size |= CHUNK_SIZE_PINUSE;
	slab_check(slab);
	iov->iov_desc = slab->zmr;
	(void)zhpeq_lcl_key_access(slab->zmr->kdata, iov->iov_base, size,
				   0, &iov->iov_zaddr);
	ret = 0;
 done:
	return ret;
}

void zhpe_offloaded_slab_free(struct zhpe_offloaded_slab *slab, void *ptr)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_slab_free_entry *chunk;
	struct zhpe_offloaded_slab_free_entry *next;
	struct zhpe_offloaded_slab_free_entry *nextnext;
	struct zhpe_offloaded_slab_free_entry *prev;

	if (!ptr)
		return;
	chunk = ptr_to_chunk(ptr);
	slab_check(slab);
	slab_check_freed(slab, chunk);
	slab_check_save_path(0);
	slab_check_save(chunk, 0);
	prev = prev_chunk(chunk);
	slab_check_save(prev, 1);
	/* Combine with prev or create new free entry? */
	if (prev) {
		slab_check_save_path(1);
		prev->size += chunk_size(chunk->size);
		chunk = prev;
	} else {
		slab_check_save_path(2);
		dlist_insert_head(&chunk->lentry, &slab->free_list);
	}
	next = _next_chunk(chunk);
	slab_check_save(next, 2);
	nextnext = _next_chunk(next);
	slab_check_save(nextnext, 3);
	/* next is end of slab or in use? */
	if (!(next->size & CHUNK_SIZE_MASK) ||
	    (nextnext->size & CHUNK_SIZE_PINUSE)) {
		/* Yes: Update prev flag and size. */
		slab_check_save_path(3);
		next->prev_size = (chunk->size & CHUNK_SIZE_MASK);
		next->size &= ~CHUNK_SIZE_PINUSE;
		goto done;
	}
	/* No: combine chunk with next. */
	slab_check_save_path(3);
	chunk->size += chunk_size(next->size);
	nextnext->prev_size = (chunk->size & CHUNK_SIZE_MASK);
	dlist_remove(&next->lentry);
 done:
	return;
}

int zhpe_offloaded_iov_op_get(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context)
{
    PRINT_DEBUG_LIBFAB;
	return zhpeq_get(zq, zindex, fence, lza, len, rza, context);
}

int zhpe_offloaded_iov_op_get_imm(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len, uint64_t rza,
			  void *context)
{
    PRINT_DEBUG_LIBFAB;
	if (len > ZHPEQ_IMM_MAX)
		abort();

	return zhpeq_geti(zq, zindex, fence, len, rza, context);
}

int zhpe_offloaded_iov_op_put(struct zhpeq *zq, uint32_t zindex, bool fence,
		    void *lptr, uint64_t lza, size_t len, uint64_t rza,
		    void *context)
{
    PRINT_DEBUG_LIBFAB;
	int			ret;

	if (len <= ZHPEQ_IMM_MAX)
		ret = zhpeq_puti(zq, zindex, fence, lptr, len, rza, context);
	else
		ret = zhpeq_put(zq, zindex, fence, lza, len, rza, context);

	return ret;
}

int zhpe_offloaded_iov_op(struct zhpe_offloaded_pe_root *pe_root,
		struct zhpe_offloaded_iov_state *lstate,
		struct zhpe_offloaded_iov_state *rstate,
		size_t max_bytes, uint8_t max_ops,
		int (*op)(struct zhpeq *zq, uint32_t zindex, bool fence,
			  void *lptr, uint64_t lza, size_t len,
			  uint64_t rza, void *context),
		size_t *rem)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpeq		*zq = pe_root->conn->ztx->zq;
	struct zhpe_offloaded_iov_state	save_lstate = *lstate;
	struct zhpe_offloaded_iov_state	save_rstate = *rstate;
	int64_t			rc;
	uint32_t		zindex;
	size_t			ops;
	size_t			bytes;
	size_t			len;
	size_t			llen;
	size_t			rlen;
	uint64_t		lza;
	uint64_t		rza;
	void			*lptr;

	/* Note: caller should initialize pe_root->completions zero or some
	 * other appropirate value and set the ZHPE_OFFLOADED_PE_PROV flag, if
	 * required.
	 *
	 * We need to determine the number of ops before reserve them.
	 */
	ops = 0;
	bytes = 0;
	while (!zhpe_offloaded_iov_state_empty(lstate) &&
	       !zhpe_offloaded_iov_state_empty(rstate) &&
	       ops < max_ops && bytes < max_bytes) {

		llen = zhpe_offloaded_ziov_state_len(lstate);
		rlen = zhpe_offloaded_ziov_state_len(rstate);
		len = llen;
		if (len > rlen)
			len = rlen;
		ops++;
		bytes += len;
		zhpe_offloaded_ziov_state_adv(lstate, len);
		zhpe_offloaded_ziov_state_adv(rstate, len);
	}
	*lstate = save_lstate;
	*rstate = save_rstate;

	max_ops = ops;
	if (!ops)
		goto done;
	if (bytes < max_bytes)
		max_bytes = bytes;
	for (;;) {
		rc = zhpeq_reserve(zq, max_ops);
		if (rc >= 0)
			break;
		if (max_ops == 1 || rc != -FI_EAGAIN) {
			ret = rc;
			goto done;
		}
		max_ops = 1;
	}
	zindex = rc;

	atm_add(&pe_root->compstat.completions, max_ops);

	for (ops = 0; ops < max_ops; ops++) {
		llen = zhpe_offloaded_ziov_state_len(lstate);
		lptr = zhpe_offloaded_iov_state_ptr(lstate, ZHPE_OFFLOADED_IOV_ZIOV);
		lza = zhpe_offloaded_ziov_state_zaddr(lstate);
		rlen = zhpe_offloaded_ziov_state_len(rstate);
		rza = zhpe_offloaded_ziov_state_zaddr(rstate);

		len = llen;
		if (len > rlen)
			len = rlen;
		if (len > max_bytes)
			len = max_bytes;
		max_bytes -= len;
		*rem -= len;
		ret = op(zq, zindex + ops, false, lptr, lza, len, rza, pe_root);
		if (ret < 0)
			break;
		zhpe_offloaded_ziov_state_adv(lstate, len);
		zhpe_offloaded_ziov_state_adv(rstate, len);
	}
	if (ret < 0) {
		for (; ops < max_ops; ops++)
			zhpeq_nop(zq, zindex + ops, false,
				  ZHPE_OFFLOADED_CONTEXT_IGNORE_PTR);
	}
	ret = zhpe_offloaded_zq_commit_spin(zq, zindex, max_ops);

 done:
	return (ret < 0 ? ret : ops);
}

int zhpe_offloaded_put_imm_to_iov(struct zhpe_offloaded_pe_root *pe_root, void *lbuf,
			size_t llen, struct zhpe_offloaded_iov_state *rstate,
			size_t *rem)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_iov		liov = {
		.iov_base = lbuf,
		.iov_len = llen,
	};
	struct zhpe_offloaded_iov_state	lstate = { .viov = &liov, .cnt = 1 };

	if (llen > ZHPEQ_IMM_MAX)
		return -FI_EINVAL;

	return zhpe_offloaded_iov_op(pe_root, &lstate, rstate, llen, 1,
			   zhpe_offloaded_iov_op_put, rem);
}


int zhpe_offloaded_iov_to_get_imm(struct zhpe_offloaded_pe_root *pe_root,
			size_t llen, struct zhpe_offloaded_iov_state *rstate,
			size_t *rem)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_iov		liov = {
		.iov_len = llen,
	};
	struct zhpe_offloaded_iov_state	lstate = { .viov = &liov, .cnt = 1 };

	if (llen > ZHPEQ_IMM_MAX)
		return -FI_EINVAL;

	return zhpe_offloaded_iov_op(pe_root, &lstate, rstate, llen, 1,
			   zhpe_offloaded_iov_op_get_imm, rem);
}

void zhpe_offloaded_send_status_rem(struct zhpe_offloaded_conn *conn, struct zhpe_offloaded_msg_hdr ohdr,
			  int32_t status, uint64_t rem)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_msg_status	msg_status;

	msg_status.rem = htobe64(rem);
	msg_status.status = htonl(status);
	msg_status.rem_valid = true;
	ohdr.op_type = ZHPE_OFFLOADED_OP_STATUS;

	zhpe_offloaded_prov_op(conn, ohdr, ZHPE_OFFLOADED_PE_RETRY,
		     &msg_status, sizeof(msg_status));
}

void zhpe_offloaded_send_status(struct zhpe_offloaded_conn *conn, struct zhpe_offloaded_msg_hdr ohdr,
		      int32_t status)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_msg_status	msg_status;

	msg_status.status = htonl(status);
	msg_status.rem_valid = false;
	ohdr.op_type = ZHPE_OFFLOADED_OP_STATUS;

	zhpe_offloaded_prov_op(conn, ohdr, ZHPE_OFFLOADED_PE_RETRY,
		     &msg_status, sizeof(msg_status));
}

void zhpe_offloaded_send_key_revoke(struct zhpe_offloaded_conn *conn,
			  const struct zhpe_offloaded_key *zkey)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_msg_hdr	ohdr = {
		.op_type	= ZHPE_OFFLOADED_OP_KEY_REVOKE,
	};
	struct zhpe_offloaded_msg_key_request key_req;

	ohdr.seq = htons(atm_inc(&conn->kexp_seq));
	key_req.zkeys[0].key = htobe64(zkey->key);
	key_req.zkeys[0].internal = zkey->internal;

	zhpe_offloaded_prov_op(conn, ohdr, ZHPE_OFFLOADED_PE_RETRY,
		     &key_req, sizeof(key_req.zkeys[0]));
}

static inline struct zhpe_offloaded_rkey_data *conn_rkey_get(struct zhpe_offloaded_conn *conn,
						   const struct zhpe_offloaded_key *zkey)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_rkey_data	*ret;
	RbtIterator		*rbt;

	rbt = zhpe_offloaded_zkey_rbtFind(conn->rkey_tree, zkey);
	if (!rbt)
		return NULL;
	ret = zhpe_offloaded_rbtKeyValue(conn->rkey_tree, rbt);
	atm_inc(&ret->use_count);

	return ret;
}

struct zhpe_offloaded_rkey_data *zhpe_offloaded_conn_rkey_get(struct zhpe_offloaded_conn *conn,
					  const struct zhpe_offloaded_key *zkey)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_rkey_data	*ret;

	ret = conn_rkey_get(conn, zkey);

	return ret;
}

int zhpe_offloaded_conn_key_export(struct zhpe_offloaded_conn *conn, struct zhpe_offloaded_msg_hdr ohdr,
			 struct zhpe_offloaded_mr *zmr)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_domain	*domain = conn->ep_attr->domain;
	struct zhpe_offloaded_kexp_data	*new = NULL;
	struct zhpe_offloaded_msg_key_data msg_data = { .key = htobe64(zmr->mr_fid.key) };
	uint8_t			pe_flags = 0;
	size_t			blob_len;
	RbtIterator		*rbt;
	int			rc;
	uint16_t		seq;
	size_t			pay_len;

	rbt = zhpe_offloaded_zkey_rbtFind(conn->kexp_tree, &zmr->zkey);

	if (ohdr.op_type == ZHPE_OFFLOADED_OP_KEY_REQUEST) {
		/* A response is always expected. */
		ohdr.op_type = ZHPE_OFFLOADED_OP_KEY_RESPONSE;
	} else if (!rbt)
		/* Only send if we have not already done so. */
		ohdr.op_type = ZHPE_OFFLOADED_OP_KEY_EXPORT;
	else
		goto done;

	blob_len = sizeof(msg_data.blob);
	ret = zhpeq_zmmu_export(zhpeq_dom(conn->ztx->zq),
				zmr->kdata, msg_data.blob, &blob_len);
	if (ret < 0)
		goto done;

	seq = atm_inc(&conn->kexp_seq);
	ohdr.seq = htons(seq);
	pay_len = offsetof(struct zhpe_offloaded_msg_key_data, blob) + blob_len;
	ret = zhpe_offloaded_prov_op(conn, ohdr, pe_flags, &msg_data, pay_len);
	/* If zhpe_offloaded_prov_op() returns -FI_EAGAIN, we don't want to create
	 * the rkey data. If KEY_EXPORT failed, we try to rewind the sequence;
	 * if that can't be done, we must force it out to fill the sequence
	 * remotely. We must also return -FI_EAGAIN to tell the caller to
	 * retry. A KEY_RESPONSE is always forced out and the error is
	 * hidden.
	 */
	if (ret == -FI_EAGAIN) {
		if (ohdr.op_type == ZHPE_OFFLOADED_OP_KEY_REQUEST)
			ret = 0;
		else {
			seq++;
			if (atm_cmpxchg(&conn->kexp_seq, &seq, seq - 1))
				goto done;
		}
		pe_flags |= ZHPE_OFFLOADED_PE_RETRY;
		rc = zhpe_offloaded_prov_op(conn, ohdr, pe_flags, &msg_data, pay_len);
		if (rc < 0)
			ret = rc;
		goto done;
	} else if (ret < 0)
		goto done;

	/* Create rkey data. This is racy, but will become less so when
	 * everything is sequenced.
	 */
	rbt = zhpe_offloaded_zkey_rbtFind(conn->kexp_tree, &zmr->zkey);
	if (!rbt) {
		new = malloc(sizeof(*new));
		if (!new) {
			ret = -FI_ENOMEM;
			goto done;
		}
		new->conn = conn;
		new->zkey = zmr->zkey;
		zhpe_offloaded_kexp_rbtInsert(conn->kexp_tree, new);
		fastlock_acquire(&domain->lock);
		dlist_insert_tail(&new->lentry, &zmr->kexp_list);
		fastlock_release(&domain->lock);
	}

 done:
	return ret;
}

static void process_rkey_revoke(struct zhpe_offloaded_conn *conn,
				const struct zhpe_offloaded_key *zkey)
{
    PRINT_DEBUG_LIBFAB;
	RbtIterator		*rbt;

	rbt = zhpe_offloaded_zkey_rbtFind(conn->rkey_tree, zkey);
	if (rbt) {
		zhpe_offloaded_rkey_put(zhpe_offloaded_rbtKeyValue(conn->rkey_tree, rbt));
		rbtErase(conn->rkey_tree, rbt);
	}
}

static void process_rkey_import(struct zhpe_offloaded_conn *conn,
				struct zhpe_offloaded_rkey_data *new)
{
    PRINT_DEBUG_LIBFAB;
	RbtIterator		*rbt;

	rbt = zhpe_offloaded_zkey_rbtFind(conn->rkey_tree, &new->zkey);
	if (rbt) {
		zhpe_offloaded_rkey_put(zhpe_offloaded_rbtKeyValue(conn->rkey_tree, rbt));
		rbtErase(conn->rkey_tree, rbt);
	}
	zhpe_offloaded_rkey_rbtInsert(conn->rkey_tree, new);
	if (new->ohdr.op_type == ZHPE_OFFLOADED_OP_KEY_RESPONSE)
		zhpe_offloaded_pe_complete_key_response(conn, new->ohdr, 0);
}

static void process_rkey_deferred(struct zhpe_offloaded_conn *conn)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_rkey_data	*new;
	struct dlist_entry      *dlist;

	while (!dlist_empty(&conn->rkey_deferred_list)) {
		dlist = conn->rkey_deferred_list.next;
		new = container_of(dlist, struct zhpe_offloaded_rkey_data, lentry);
		if (new->ohdr.seq != conn->rkey_seq)
			break;
		conn->rkey_seq++;
		dlist_remove(dlist);

		switch (new->ohdr.op_type) {

		case ZHPE_OFFLOADED_OP_KEY_REVOKE:
			process_rkey_revoke(conn, &new->zkey);
			free(new);
			break;

		default:
			process_rkey_import(conn, new);
			break;
		}
	}
}

static void insert_rkey_deferred(struct zhpe_offloaded_conn *conn,
				 struct zhpe_offloaded_rkey_data *new)
{
    PRINT_DEBUG_LIBFAB;
	struct dlist_entry      *dlist;
	struct zhpe_offloaded_rkey_data	*cur;

	dlist_foreach(&conn->rkey_deferred_list, dlist) {
		cur = container_of(dlist, struct zhpe_offloaded_rkey_data,  lentry);
		if (cur->ohdr.seq > new->ohdr.seq) {
			dlist_insert_before(&new->lentry, &cur->lentry);
			return;
		}
	}
	dlist_insert_tail(&new->lentry, &conn->rkey_deferred_list);
}

int zhpe_offloaded_conn_rkey_import(struct zhpe_offloaded_conn *conn, struct zhpe_offloaded_msg_hdr ohdr,
			   uint64_t key, const void *blob, size_t blob_len,
			   struct zhpe_offloaded_rkey_data **rkey_out)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_rkey_data	*new = NULL;
	struct zhpeq_key_data	*kdata = NULL;

	ret = zhpeq_zmmu_import(zhpeq_dom(conn->ztx->zq), conn->zq_index,
				blob, blob_len, false, &kdata);
	if (ret < 0)
		goto done;

	ohdr.seq = ntohs(ohdr.seq);
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	atm_inc(&conn->ztx->use_count);
	new->ztx = conn->ztx;
	new->zkey.key = key;
	new->zkey.internal = !!(kdata->z.access & ZHPE_OFFLOADED_MR_KEY_INT);
	new->kdata = kdata;
	new->ohdr = ohdr;
	new->use_count = 1;
	if (rkey_out) {
		new->use_count++;
		*rkey_out = new;
	}

	if (ohdr.op_type != ZHPE_OFFLOADED_OP_NONE) {
		if (ohdr.seq != conn->rkey_seq) {
			insert_rkey_deferred(conn, new);
			goto done;
		}
		conn->rkey_seq++;
	}
	process_rkey_import(conn, new);
	process_rkey_deferred(conn);

 done:
	return ret;
}

int zhpe_offloaded_conn_rkey_revoke(struct zhpe_offloaded_conn *conn, struct zhpe_offloaded_msg_hdr ohdr,
			  const struct zhpe_offloaded_key *zkey)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_rkey_data	*new = NULL;

	ohdr.seq = ntohs(ohdr.seq);
	if (ohdr.seq == conn->rkey_seq) {
		conn->rkey_seq++;
		process_rkey_revoke(conn, zkey);
		process_rkey_deferred(conn);
		goto done;
	}
	/* Deferred processing. */
	new = malloc(sizeof(*new));
	if (!new) {
		ret = -FI_ENOMEM;
		goto done;
	}
	new->zkey = *zkey;
	new->ohdr = ohdr;
	insert_rkey_deferred(conn, new);
	process_rkey_deferred(conn);

 done:
	return ret;
}

static int check_read(size_t req, ssize_t res)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;

	if (res == -1) {
		ret = -errno;
		ZHPE_OFFLOADED_LOG_ERROR("read(): error %d\n", ret);
		goto done;
	}
	if (res != req) {
		ZHPE_OFFLOADED_LOG_ERROR("read(): read %Ld of %Lu bytes\n",
			       (llong)res, (ullong)req);
		ret = -EIO;
		goto done;
	}
 done:
	return ret;
}

static int check_write(size_t req, ssize_t res)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;

	if (res == -1) {
		ret = -errno;
		ZHPE_OFFLOADED_LOG_ERROR("write(): error %d\n", ret);
		goto done;
	}
	if (res != req) {
		ZHPE_OFFLOADED_LOG_ERROR("write(): wrote %Ld of %Lu bytes\n",
			       (llong)res, (ullong)req);
		ret = -EIO;
		goto done;
	}
 done:
	return ret;
}

int zhpe_offloaded_send_blob(int sock_fd, const void *blob, size_t blob_len)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = -FI_EINVAL;
	uint32_t		wlen = blob_len;
	size_t			req;
	ssize_t			res;

	if (!blob) {
		blob_len = 0;
		wlen = UINT32_MAX;
	} else if (blob_len >= UINT32_MAX)
		goto done;
	wlen = htonl(wlen);
	req = sizeof(wlen);
	res = ofi_write_socket(sock_fd, &wlen, req);
	ret = check_write(req, res);
	if (ret < 0)
		goto done;
	if (!blob_len)
		goto done;
	req = blob_len;
	res = ofi_write_socket(sock_fd, blob, req);
	ret = check_write(req, res);
 done:

	return ret;
}

int zhpe_offloaded_recv_fixed_blob(int sock_fd, void *blob, size_t blob_len)
{
    PRINT_DEBUG_LIBFAB;
	int			ret;
	uint32_t		wlen;
	size_t			req;
	ssize_t			res;

	req = sizeof(wlen);
	res = ofi_read_socket(sock_fd, &wlen, req);
	ret = check_read(req, res);
	if (ret < 0)
		goto done;
	req = ntohl(wlen);
	if (req != blob_len) {
		ZHPE_OFFLOADED_LOG_ERROR("Expected %Lu bytes, saw %Lu\n",
			       (ullong)blob_len, (ullong)res);
		ret = -EINVAL;
		goto done;
	}
	res = ofi_read_socket(sock_fd, blob, req);
	ret = check_read(req, res);
 done:

	return ret;
}

#if ENABLE_DEBUG

static int zmr_print(void *datap)
{
	struct zhpe_offloaded_mr		*zmr = datap;

	fprintf(stderr, "zmr  %p key 0x%Lx/%d use_count %d\n",
		zmr, (ullong)zmr->zkey.key, zmr->zkey.internal, zmr->use_count);

	return 0;
}

static int rkey_print(void *datap)
{
	struct zhpe_offloaded_rkey_data	*rkey = datap;

	fprintf(stderr, "rkey %p key 0x%Lx/%d use_count %d\n",
		rkey, (ullong)rkey->zkey.key, rkey->zkey.internal,
		rkey->use_count);

	return 0;
}

static int kexp_print(void *datap)
{
	struct zhpe_offloaded_kexp_data	*kexp = datap;

	fprintf(stderr, "kexp %p key 0x%Lx/%d conn %p\n",
		kexp, (ullong)kexp->zkey.key, kexp->zkey.internal, kexp->conn);

	return 0;
}

static int tree_work(RbtHandle *tree, int (*work)(void *data))
{
	int			ret = 0;
	RbtIterator		rbt;

	rbt = rbtBegin(tree);
	if (!rbt)
		return 0;
	do {
		ret = work(zhpe_offloaded_rbtKeyValue(tree, rbt));
		if (ret)
			break;
	} while ((rbt = rbtNext(tree, rbt)));

	return ret;
}

void zhpe_offloaded_zmr_dump(struct zhpe_offloaded_domain *domain)
{
	tree_work(domain->mr_tree, zmr_print);
}

void zhpe_offloaded_rkey_dump(struct zhpe_offloaded_conn *conn)
{
	tree_work(conn->rkey_tree, rkey_print);
}

void zhpe_offloaded_kexp_dump(struct zhpe_offloaded_conn *conn)
{
	tree_work(conn->kexp_tree, kexp_print);
}

int gdb_hook_noabort;

void gdb_hook(void)
{
	if (!gdb_hook_noabort)
		abort();
}

#endif
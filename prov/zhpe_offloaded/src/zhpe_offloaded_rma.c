/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
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

#define ZHPE_OFFLOADED_LOG_DBG(...) _ZHPE_OFFLOADED_LOG_DBG(FI_LOG_EP_DATA, __VA_ARGS__)
#define ZHPE_OFFLOADED_LOG_ERROR(...) _ZHPE_OFFLOADED_LOG_ERROR(FI_LOG_EP_DATA, __VA_ARGS__)

static int
zhpe_offloaded_check_user_rma(const struct fi_rma_iov *urma, size_t urma_cnt,
		    uint32_t qaccess,
		    struct zhpe_offloaded_iov_state *rstate, size_t riov_max,
		    size_t *total_len, struct zhpe_offloaded_conn *conn)
{
	int			ret = 0;
	struct zhpe_offloaded_iov		*riov = rstate->viov;
	size_t			i;
	size_t			j;
	struct zhpe_offloaded_rkey_data	*rkey;
	struct zhpe_offloaded_key		zkey;

	*total_len = 0;
	for (i = 0, j = 0; i < urma_cnt; i++) {
		if (OFI_UNLIKELY(!urma[i].len))
			continue;
		if (urma[i].len > ZHPE_OFFLOADED_EP_MAX_IOV_LEN || j >= riov_max) {
			ret = -FI_EMSGSIZE;
			goto done;
		}
		riov[j].iov_addr = urma[i].addr;
		riov[j].iov_len = urma[i].len;
		*total_len += urma[i].len;
		riov[j].iov_key = urma[i].key;
		zhpe_offloaded_ziov_to_zkey(&riov[j], &zkey);
		rkey = zhpe_offloaded_conn_rkey_get(conn, &zkey);
		if (!rkey) {
			if (conn->fam) {
				ret = -FI_ENOKEY;
				goto done;
			}
			rstate->missing |= (1U << j);
			rstate->cnt = ++j;
			continue;
		}
		riov[j].iov_rkey = rkey;
		ret = zhpeq_rem_key_access(rkey->kdata,
					   riov[j].iov_addr, riov[j].iov_len,
					   qaccess, &riov[j].iov_zaddr);
		rstate->cnt = ++j;
		if (ret < 0)
			goto done;
	}
 done:
	return ret;
}

static inline ssize_t do_rma_msg(struct fid_ep *ep,
				 const struct fi_msg_rma *msg,
				 uint64_t flags)
{
	int64_t			ret = -FI_EINVAL;
	int64_t			tindex = -1;
	struct zhpe_offloaded_pe_entry	*pe_entry;
	struct zhpe_offloaded_conn	*conn;
	struct zhpe_offloaded_tx_ctx	*tx_ctx;
	uint64_t		rma_len;
	uint64_t		op_flags;
	struct zhpe_offloaded_ep		*zhpe_offloaded_ep;
	struct zhpe_offloaded_ep_attr	*ep_attr;
	struct zhpe_offloaded_msg_hdr	ohdr;

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 0));

	switch (ep->fid.fclass) {

	case FI_CLASS_EP:
		zhpe_offloaded_ep = container_of(ep, struct zhpe_offloaded_ep, ep);
		tx_ctx = zhpe_offloaded_ep->attr->tx_ctx;
		ep_attr = zhpe_offloaded_ep->attr;
		op_flags = zhpe_offloaded_ep->tx_attr.op_flags;
		break;

	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct zhpe_offloaded_tx_ctx, ctx);
		ep_attr = tx_ctx->ep_attr;
		op_flags = tx_ctx->attr.op_flags;
		break;

	default:
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 0));
		ZHPE_OFFLOADED_LOG_ERROR("Invalid EP type\n");
		goto done;
	}

	if (!tx_ctx->enabled) {
		ret = -FI_EOPBADSTATE;
		goto done;
	}

	if (msg->iov_count > ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT)
		goto done;

	if (msg->rma_iov_count > ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT)
		goto done;

	if (OFI_LIKELY(!(flags & ZHPE_OFFLOADED_TRIGGERED_OP))) {
		switch (flags & (FI_READ | FI_WRITE)) {

		case FI_READ:
			if (flags &
			    ~(ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS |
			      FI_COMPLETION | FI_TRIGGER |
			      FI_FENCE | FI_RMA | FI_READ))
				goto done;
			if (op_flags & FI_RMA_EVENT)
				flags |= FI_REMOTE_READ;
			break;

		case FI_WRITE:
			if (flags &
			    ~(ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS |
			      FI_COMPLETION | FI_TRIGGER |
			      FI_FENCE | FI_RMA | FI_WRITE |
			      FI_INJECT | FI_INJECT_COMPLETE |
			      FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE |
			      FI_REMOTE_CQ_DATA))
				goto done;
			if (op_flags & FI_RMA_EVENT)
				flags |= FI_REMOTE_WRITE;
			break;

		default:
			goto done;
		}

		flags = zhpe_offloaded_tx_fixup_completion(flags, op_flags, tx_ctx);
	}

	if (flags & FI_TRIGGER) {
		ret = zhpe_offloaded_queue_rma_op(ep, msg, flags,
					((flags & FI_READ) ?
					 FI_OP_READ : FI_OP_WRITE));
		if (ret != 1)
			goto done;
	}

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 10));
	ret = zhpe_offloaded_ep_get_conn(ep_attr, msg->addr, &conn);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 10));
	if (ret < 0)
		goto done;

	ret = zhpe_offloaded_tx_reserve(conn->ztx, 0);
	if (ret < 0)
		goto done;
	tindex = ret;
	pe_entry = &conn->ztx->pentries[tindex];
	pe_entry->pe_root.handler = zhpe_offloaded_pe_tx_handle_rma;
	pe_entry->pe_root.conn = conn;
	pe_entry->pe_root.context = msg->context;
	pe_entry->pe_root.compstat.status = 0;
	pe_entry->pe_root.compstat.completions = 0;
	pe_entry->pe_root.compstat.flags |= ZHPE_OFFLOADED_PE_KEY_WAIT;
	pe_entry->cq_data = msg->data;
	pe_entry->rx_id = zhpe_offloaded_get_rx_id(tx_ctx, msg->addr);

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 20));
	ret = zhpe_offloaded_check_user_iov(msg->msg_iov, msg->desc, msg->iov_count,
				  ((flags & FI_READ) ?
				   ZHPEQ_MR_GET : ZHPEQ_MR_PUT),
				  &pe_entry->lstate, ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT,
				  &pe_entry->rem);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 20));
	if (ret < 0)
		goto done;

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 30));
	ret = zhpe_offloaded_check_user_rma(msg->rma_iov, msg->rma_iov_count,
				  ((flags & FI_READ) ?
				   ZHPEQ_MR_GET_REMOTE : ZHPEQ_MR_PUT_REMOTE),
				  &pe_entry->rstate, ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT,
				  &rma_len, conn);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 30));
	if (ret < 0)
		goto done;
	if (pe_entry->rem != rma_len) {
		ret = -FI_EINVAL;
		goto done;
	}

	if (pe_entry->rem <= ZHPEQ_IMM_MAX) {
		zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 40));
		flags |= FI_INJECT;
		if (flags & FI_WRITE) {
			copy_iov_to_mem(pe_entry->inline_data,
					&pe_entry->lstate, ZHPE_OFFLOADED_IOV_ZIOV,
					pe_entry->rem);
			zhpe_offloaded_pe_tx_report_complete(pe_entry,
						   FI_INJECT_COMPLETE);
		}
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 40));
	} else if (pe_entry->lstate.missing) {
		zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 50));
		ret = zhpe_offloaded_mr_reg_int_iov(ep_attr->domain, &pe_entry->lstate);
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 50));
		if (ret < 0)
			goto done;
	}

	pe_entry->flags = flags;
	if (pe_entry->rstate.missing) {
		zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 60));
		ohdr.rx_id = pe_entry->rx_id;
		ohdr.pe_entry_id = htons(tindex);
		zhpe_offloaded_pe_rkey_request(conn, ohdr, &pe_entry->rstate,
				     &pe_entry->pe_root.compstat.completions);
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 60));
	} else {
		zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RMA, 70));
		pe_entry->pe_root.compstat.completions = 1;
		zhpe_offloaded_pe_tx_handle_rma(&pe_entry->pe_root, NULL);
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 70));
	}
 done:
	if (ret < 0 && tindex != -1)
		zhpe_offloaded_tx_release(pe_entry);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RMA, 0));

	return ret;
}

ssize_t zhpe_offloaded_do_rma_msg(struct fid_ep *ep, const struct fi_msg_rma *msg,
			uint64_t flags)
{
	/* Used by trigger: flags are assumed to be correct. */
	return do_rma_msg(ep, msg, flags);
}

static ssize_t zhpe_offloaded_ep_rma_readmsg(struct fid_ep *ep,
				   const struct fi_msg_rma *msg,
				   uint64_t flags)
{
	if (flags & (ZHPE_OFFLOADED_BAD_FLAGS_MASK | FI_WRITE))
		return -EINVAL;

	return do_rma_msg(ep, msg, flags | FI_READ);
}

static ssize_t zhpe_offloaded_ep_rma_read(struct fid_ep *ep, void *buf, size_t len,
				void *desc, fi_addr_t src_addr, uint64_t addr,
				uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;
	msg.rma_iov_count = 1;
	msg.rma_iov = &rma_iov;

	msg.addr = src_addr;
	msg.context = context;

	return do_rma_msg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS | FI_READ);
}

static ssize_t zhpe_offloaded_ep_rma_readv(struct fid_ep *ep, const struct iovec *iov,
				 void **desc, size_t count,
				 fi_addr_t src_addr, uint64_t addr,
				 uint64_t key,void *context)
{
	size_t len, i;
	struct fi_msg_rma msg;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;

	for (i = 0, len = 0; i < count; i++)
		len += iov[i].iov_len;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.addr = src_addr;
	msg.context = context;

	return do_rma_msg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS | FI_READ);
}

static ssize_t zhpe_offloaded_ep_rma_writemsg(struct fid_ep *ep,
				    const struct fi_msg_rma *msg,
				    uint64_t flags)
{
	if (flags & (ZHPE_OFFLOADED_BAD_FLAGS_MASK | FI_READ))
		return -EINVAL;

	return do_rma_msg(ep, msg, flags | FI_WRITE);
}

static ssize_t zhpe_offloaded_ep_rma_write(struct fid_ep *ep, const void *buf,
				 size_t len, void *desc, fi_addr_t dest_addr,
				 uint64_t addr, uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;

	msg.msg_iov = &msg_iov;
	msg.desc = &desc;
	msg.iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov_count = 1;
	msg.rma_iov = &rma_iov;

	msg.addr = dest_addr;
	msg.context = context;

	return do_rma_msg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS | FI_WRITE);
}

static ssize_t zhpe_offloaded_ep_rma_writev(struct fid_ep *ep, const struct iovec *iov,
				  void **desc, size_t count,
				  fi_addr_t dest_addr,
				  uint64_t addr, uint64_t key, void *context)
{
	size_t i;
	size_t len;
	struct fi_msg_rma msg;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = iov;
	msg.desc = desc;
	msg.iov_count = count;
	msg.rma_iov_count = 1;

	for (i = 0, len = 0; i < count; i++)
		len += iov[i].iov_len;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.context = context;
	msg.addr = dest_addr;

	return do_rma_msg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS | FI_WRITE);
}

static ssize_t zhpe_offloaded_ep_rma_writedata(struct fid_ep *ep, const void *buf,
				     size_t len, void *desc, uint64_t data,
				     fi_addr_t dest_addr, uint64_t addr,
				     uint64_t key, void *context)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.desc = &desc;
	msg.iov_count = 1;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.msg_iov = &msg_iov;

	msg.addr = dest_addr;
	msg.context = context;
	msg.data = data;

	return do_rma_msg(ep, &msg,
			  FI_REMOTE_CQ_DATA | ZHPE_OFFLOADED_USE_OP_FLAGS | FI_WRITE);
}

static ssize_t zhpe_offloaded_ep_rma_inject(struct fid_ep *ep, const void *buf,
				  size_t len, fi_addr_t dest_addr,
				  uint64_t addr, uint64_t key)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.msg_iov = &msg_iov;
	msg.addr = dest_addr;

	return do_rma_msg(ep, &msg,
			  (FI_INJECT | ZHPE_OFFLOADED_NO_COMPLETION |
			   ZHPE_OFFLOADED_USE_OP_FLAGS | FI_WRITE));
}

static ssize_t zhpe_offloaded_ep_rma_injectdata(struct fid_ep *ep, const void *buf,
				      size_t len, uint64_t data,
				      fi_addr_t dest_addr, uint64_t addr,
				      uint64_t key)
{
	struct fi_msg_rma msg;
	struct iovec msg_iov;
	struct fi_rma_iov rma_iov;

	memset(&msg, 0, sizeof(msg));
	msg_iov.iov_base = (void *) buf;
	msg_iov.iov_len = len;
	msg.msg_iov = &msg_iov;
	msg.iov_count = 1;
	msg.rma_iov_count = 1;

	rma_iov.addr = addr;
	rma_iov.key = key;
	rma_iov.len = len;

	msg.rma_iov = &rma_iov;
	msg.msg_iov = &msg_iov;
	msg.addr = dest_addr;
	msg.data = data;

	return do_rma_msg(ep, &msg,
			  (FI_INJECT | FI_REMOTE_CQ_DATA |
			   ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS | FI_WRITE));
}


struct fi_ops_rma zhpe_offloaded_ep_rma = {
	.size  = sizeof(struct fi_ops_rma),
	.read = zhpe_offloaded_ep_rma_read,
	.readv = zhpe_offloaded_ep_rma_readv,
	.readmsg = zhpe_offloaded_ep_rma_readmsg,
	.write = zhpe_offloaded_ep_rma_write,
	.writev = zhpe_offloaded_ep_rma_writev,
	.writemsg = zhpe_offloaded_ep_rma_writemsg,
	.inject = zhpe_offloaded_ep_rma_inject,
	.injectdata = zhpe_offloaded_ep_rma_injectdata,
	.writedata = zhpe_offloaded_ep_rma_writedata,
};


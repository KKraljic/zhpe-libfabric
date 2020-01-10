/*
 * Copyright (c) 2014-2015 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2017-2018 Hewlett Packard Enterprise Development LP.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You m"ay choose to be licensed under the terms of the GNU
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

int zhpe_offloaded_check_user_iov(const struct iovec *uiov, void **udesc,
			size_t uiov_cnt, uint32_t qaccess,
			struct zhpe_offloaded_iov_state *lstate, size_t liov_max,
			size_t *total_len)
{
    PRINT_DEBUG_LIBFAB;
	int			ret = 0;
	struct zhpe_offloaded_iov		*liov = lstate->viov;
	struct zhpe_offloaded_mr		*zmr;
	size_t			i;
	size_t			j;

	*total_len = 0;
	for (i = 0, j = 0; i < uiov_cnt; i++) {
		if (OFI_UNLIKELY(!uiov[i].iov_len))
			continue;
		if (uiov[i].iov_len > ZHPE_OFFLOADED_EP_MAX_IOV_LEN || j >= liov_max) {
			ret = -FI_EMSGSIZE;
			goto done;
		}
		liov[j].iov_base = uiov[i].iov_base;
		liov[j].iov_len = uiov[i].iov_len;
		*total_len += uiov[i].iov_len;
		liov[j].iov_desc = zmr = udesc[i];
		if (!zmr) {
			lstate->missing |= (1U << j);
			lstate->cnt = ++j;
			continue;
		}
		ret = zhpeq_lcl_key_access(zmr->kdata,
					   liov[j].iov_base, liov[j].iov_len,
					   qaccess, &liov[j].iov_zaddr);
		lstate->cnt = ++j;
		if (ret < 0)
			goto done;
	}
 done:
	return ret;
}

static inline ssize_t do_recvmsg(struct fid_ep *ep, const void *vmsg,
				 uint64_t flags, bool tagged, bool lock)
{
    PRINT_DEBUG_LIBFAB;
	ssize_t			ret = -FI_EINVAL;
	struct zhpe_offloaded_rx_entry	*rx_entry = NULL;
	struct zhpe_offloaded_ep		*zhpe_offloaded_ep;
	struct zhpe_offloaded_ep_attr	*ep_attr;
	uint64_t		op_flags;
	const struct fi_msg	*msg;
	const struct fi_msg_tagged *tmsg;
	size_t			iov_count;
	const struct iovec	*iov;
	void			**desc;
	fi_addr_t		fiaddr;
	void			*context;
	uint64_t		tag;
	uint64_t		ignore;
	struct zhpe_offloaded_rx_ctx	*rx_ctx;
	struct zhpe_offloaded_rx_entry	*rx_claimed;
	struct zhpe_offloaded_conn	*conn;
	uint64_t		flags2;

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RECV, 0));

	switch (ep->fid.fclass) {
	case FI_CLASS_EP:
		zhpe_offloaded_ep = container_of(ep, struct zhpe_offloaded_ep, ep);
		ep_attr = zhpe_offloaded_ep->attr;
		rx_ctx = ep_attr->rx_ctx;
		op_flags = zhpe_offloaded_ep->rx_attr.op_flags;
		break;
	case FI_CLASS_RX_CTX:
		rx_ctx = container_of(ep, struct zhpe_offloaded_rx_ctx, ctx);
		ep_attr = rx_ctx->ep_attr;
		op_flags = rx_ctx->attr.op_flags;
		break;
	default:
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RECV, 0));
		ZHPE_OFFLOADED_LOG_ERROR("Invalid ep type\n");
		return ret;
	}

	if (lock)
		mutex_lock(&rx_ctx->mutex);

	if (!rx_ctx->enabled) {
		ret = -FI_EOPBADSTATE;
		goto done;
	}

	if (OFI_LIKELY(!(flags & ZHPE_OFFLOADED_TRIGGERED_OP))) {
		if (flags &
		    ~(ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS |
		      FI_COMPLETION | FI_TRIGGER | FI_MULTI_RECV |
		      FI_PEEK | FI_CLAIM | FI_DISCARD | FI_MSG | FI_RECV))
			goto done;
		flags2 = (flags & (FI_PEEK | FI_CLAIM | FI_DISCARD));
		if (flags2 == FI_DISCARD)
			goto done;
		if (flags2 && (flags & FI_MULTI_RECV))
			goto done;
		flags |= (FI_MSG | FI_RECV);

		if (flags & ZHPE_OFFLOADED_USE_OP_FLAGS)
			flags |= op_flags;
		else if (!rx_ctx->comp.recv_cq_event)
			/* recvmsg && no FI_SELECTIVE_COMPLETION */
			flags |= FI_COMPLETION;
	}

	if (flags & FI_TRIGGER) {
		if (tagged)
			ret = zhpe_offloaded_queue_tmsg_op(ep, vmsg, flags, FI_OP_TRECV);
		else
			ret = zhpe_offloaded_queue_msg_op(ep, vmsg, flags, FI_OP_RECV);
		if (ret != 1)
			goto done;
	}

	if (tagged) {
		flags |= FI_TAGGED;
		tmsg = vmsg;
		iov_count = tmsg->iov_count;
		iov = tmsg->msg_iov;
		desc = tmsg->desc;
		fiaddr = tmsg->addr;
		context = tmsg->context;
		tag = tmsg->tag;
		ignore = tmsg->ignore;
	} else {
		msg = vmsg;
		iov_count = msg->iov_count;
		iov = msg->msg_iov;
		desc = msg->desc;
		fiaddr = msg->addr;
		context = msg->context;
		tag = 0;
		ignore = ~tag;
	}

	if (flags & FI_DISCARD)
		iov_count = 0;
	if (iov_count > ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT)
		goto done;

	fiaddr = ((rx_ctx->attr.caps & FI_DIRECTED_RECV) ?
		  fiaddr : FI_ADDR_UNSPEC);
	if (fiaddr != FI_ADDR_UNSPEC) {
		zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RECV, 10));
		ret = zhpe_offloaded_ep_get_conn(ep_attr, fiaddr, &conn);
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RECV, 10));
		if (ret < 0)
			goto done;
	}

	if (flags & FI_PEEK) {
		zhpe_offloaded_pe_rx_peek_recv(rx_ctx, fiaddr, tag, ignore, flags,
				     context);
		ret = 0;
		goto done;
	}

	rx_entry = zhpe_offloaded_rx_new_entry(&rx_ctx->rx_user_free);
	if (!rx_entry) {
		ret = -FI_ENOMEM;
		goto done;
	}
	rx_entry->flags = flags;
	rx_entry->addr = fiaddr;
	rx_entry->tag = tag;
	rx_entry->ignore = ignore;
	rx_entry->context = context;

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RECV, 20));
	ret = zhpe_offloaded_check_user_iov(iov, desc, iov_count, ZHPEQ_MR_RECV,
				  &rx_entry->lstate, ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT,
				  &rx_entry->total_len);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RECV, 20));
	if (ret < 0)
		goto done;

	if (rx_entry->lstate.missing &&
	    (rx_entry->total_len > zhpe_offloaded_ep_max_eager_sz ||
	     OFI_UNLIKELY(flags & FI_MULTI_RECV))) {
		zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RECV, 30));
		ret = zhpe_offloaded_mr_reg_int_iov(rx_ctx->domain, &rx_entry->lstate);
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RECV, 30));
		if (ret < 0)
			goto done;
	}

	if (flags & FI_CLAIM) {
		rx_claimed = ((struct fi_context *)context)->internal[0];
		zhpe_offloaded_pe_rx_claim_recv(rx_claimed, rx_entry);
		goto done;
	}

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(RECV, 40));
	if (OFI_UNLIKELY(flags & FI_MULTI_RECV))
		zhpe_offloaded_pe_rx_post_recv_multi(rx_ctx, rx_entry);
	else
		zhpe_offloaded_pe_rx_post_recv(rx_ctx, rx_entry);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RECV, 40));
	ZHPE_OFFLOADED_LOG_DBG("New rx_entry: %p (ctx: %p)\n", rx_entry, rx_ctx);
 done:
	if (ret < 0 && rx_entry)
		zhpe_offloaded_rx_release_entry(rx_entry);
	if (lock)
		mutex_unlock(&rx_ctx->mutex);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(RECV, 0));

	return ret;
}

ssize_t zhpe_offloaded_do_recvmsg(struct fid_ep *ep, const void *vmsg,
			uint64_t flags, bool tagged)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_ep		*zhpe_offloaded_ep = container_of(ep, struct zhpe_offloaded_ep, ep);

	/* Used by trigger: flags are assumed to be correct. */
	return do_recvmsg(ep, vmsg, flags, tagged,
			  zhpe_offloaded_needs_locking(zhpe_offloaded_ep->attr->domain));
}

static ssize_t do_sendmsg(struct fid_ep *ep, const void *vmsg, uint64_t flags,
			  bool tagged, bool lock)
{
    PRINT_DEBUG_LIBFAB;
	ssize_t			ret = -FI_EINVAL;
	int64_t			tindex = -1;
	struct zhpe_offloaded_msg_hdr	hdr = { .op_type = ZHPE_OFFLOADED_OP_SEND };
	struct zhpe_offloaded_pe_entry	*pe_entry;
	size_t			inline_size;
	size_t			cmd_len;
	uint			i;
	struct zhpe_offloaded_msg_hdr	*zhdr;
	union zhpe_offloaded_msg_payload	*zpay;
	uint64_t		lzaddr;
	const struct fi_msg	*msg;
	const struct fi_msg_tagged *tmsg;
	size_t			iov_count;
	const struct iovec	*iov;
	void			**desc;
	fi_addr_t		fiaddr;
	uint64_t		cq_data;
	uint64_t		tag;
	uint64_t		*data;
	uint64_t		op_flags;
	struct zhpe_offloaded_conn	*conn;
	struct zhpe_offloaded_tx_ctx	*tx_ctx;
	struct zhpe_offloaded_ep		*zhpe_offloaded_ep;
	struct zhpe_offloaded_ep_attr	*ep_attr;
	struct zhpe_offloaded_mr		*zmr;
	void			*context;
	uint64_t		base;
	void			*nulldesc;

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(SEND, 0));

	switch (ep->fid.fclass) {
	case FI_CLASS_EP:
		zhpe_offloaded_ep = container_of(ep, struct zhpe_offloaded_ep, ep);
		ep_attr = zhpe_offloaded_ep->attr;
		tx_ctx = ep_attr->tx_ctx;
		op_flags = zhpe_offloaded_ep->tx_attr.op_flags;
		break;
	case FI_CLASS_TX_CTX:
		tx_ctx = container_of(ep, struct zhpe_offloaded_tx_ctx, ctx);
		ep_attr = tx_ctx->ep_attr;
		op_flags = tx_ctx->attr.op_flags;
		break;
	default:
		zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(SEND, 0));
		ZHPE_OFFLOADED_LOG_ERROR("Invalid EP type\n");
		goto done;
	}

	if (!tx_ctx->enabled) {
		ret = -FI_EOPBADSTATE;
		goto done;
	}

	if (OFI_LIKELY(!(flags & ZHPE_OFFLOADED_TRIGGERED_OP))) {
		if (flags &
		    ~(ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS |
		      FI_COMPLETION | FI_TRIGGER | FI_INJECT |
		      FI_REMOTE_CQ_DATA | FI_INJECT_COMPLETE |
		      FI_TRANSMIT_COMPLETE | FI_DELIVERY_COMPLETE | FI_FENCE |
		      FI_MSG | FI_SEND))
			goto done;
		flags |= (FI_MSG | FI_SEND);

		flags = zhpe_offloaded_tx_fixup_completion(flags, op_flags, tx_ctx);
	}

	if (flags & FI_TRIGGER) {
		if (tagged)
			ret = zhpe_offloaded_queue_tmsg_op(ep, vmsg, flags, FI_OP_TSEND);
		else
			ret = zhpe_offloaded_queue_tmsg_op(ep, vmsg, flags, FI_OP_SEND);
		if (ret != 1)
			goto done;
	}

	inline_size = ZHPE_OFFLOADED_RING_ENTRY_LEN;

	if (flags & FI_REMOTE_CQ_DATA) {
		hdr.flags |= ZHPE_OFFLOADED_MSG_REMOTE_CQ_DATA;
		inline_size -= sizeof(cq_data);
	}
	if (tagged) {
		hdr.flags |= ZHPE_OFFLOADED_MSG_TAGGED;
		inline_size -= sizeof(tag);
		tmsg = vmsg;
		iov_count = tmsg->iov_count;
		iov = tmsg->msg_iov;
		desc = tmsg->desc;
		if (!desc) {
			desc = &nulldesc;
			nulldesc = NULL;
		}
		fiaddr = tmsg->addr;
		cq_data = tmsg->data;
		tag = tmsg->tag;
		context = tmsg->context;
	} else {
		msg = vmsg;
		iov_count = msg->iov_count;
		iov = msg->msg_iov;
		desc = msg->desc;
		if (!desc) {
			desc = &nulldesc;
			nulldesc = NULL;
		}
		fiaddr = msg->addr;
		cq_data = msg->data;
		tag = 0;
		context = msg->context;
	}

	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(SEND, 10));
	ret = zhpe_offloaded_ep_get_conn(ep_attr, fiaddr, &conn);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(SEND, 10));
	if (ret < 0)
		goto done;

	ZHPE_OFFLOADED_LOG_DBG("New sendmsg on TX: %p using conn: %p\n",
		      tx_ctx, conn);

	/* FIXME: IOV > 1
	 * While some of the loops support iov size > 1, the
	 * fundamental protocol currently does not.
	 */
	zhpe_offloaded_tx_reserve_vars(ret, zhpe_offloaded_pe_tx_handle_entry, conn, context,
			     tindex, pe_entry, zhdr, lzaddr, done, 0);
	hdr.rx_id = zhpe_offloaded_get_rx_id(tx_ctx, fiaddr);
	hdr.pe_entry_id = htons(tindex);

	/* FIXME: zhpe_offloaded_ep_max_eager_sz  */
	inline_size -= sizeof(*zhdr);

	ret = zhpe_offloaded_check_user_iov(iov, desc, iov_count, ZHPEQ_MR_SEND,
				  &pe_entry->lstate, ZHPE_OFFLOADED_EP_MAX_IOV_LIMIT,
				  &pe_entry->rem);
	if (ret < 0)
		goto done;

	/* Build TX command. */
	if (pe_entry->rem > inline_size) {
		if (pe_entry->lstate.missing) {
			zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(SEND, 20));
			ret = zhpe_offloaded_mr_reg_int_iov(ep_attr->domain,
						  &pe_entry->lstate);
			zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(SEND, 20));
			if (ret < 0)
				goto done;
		}
		for (i = 0; i < pe_entry->lstate.cnt; i++) {
			zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(SEND, 30));
			ret = zhpe_offloaded_conn_key_export(conn, hdr,
						   pe_entry->liov[i].iov_desc);
			zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(SEND, 30));
			if (ret < 0)
				goto done;
		}
		/* Align payload to uint64_t boundary. */
		zpay = zhpe_offloaded_pay_ptr(conn, zhdr, 0, __alignof__(*zpay));
		zpay->indirect.tag = htobe64(tag);
		zpay->indirect.cq_data = htobe64(cq_data);
		base = (uintptr_t)pe_entry->liov[0].iov_base;
		if ((zmr = pe_entry->liov[0].iov_desc) &&
		    (zmr->kdata->z.access & ZHPEQ_MR_KEY_ZERO_OFF))
			base -= zmr->kdata->z.vaddr;
		zpay->indirect.vaddr = htobe64(base);
		zpay->indirect.len =
			htobe64((uintptr_t)pe_entry->liov[0].iov_len);
		zpay->indirect.key = htobe64(zmr->zkey.key);
		cmd_len = zpay->indirect.end - (char *)zhdr;
		pe_entry->pe_root.compstat.completions++;
		if (flags & FI_DELIVERY_COMPLETE)
			hdr.flags |= ZHPE_OFFLOADED_MSG_DELIVERY_COMPLETE;
		else {
			hdr.flags |= ZHPE_OFFLOADED_MSG_TRANSMIT_COMPLETE;
			if (flags & FI_INJECT_COMPLETE) {
				flags &= ~FI_INJECT_COMPLETE;
				flags |= FI_TRANSMIT_COMPLETE;
			}
		}
	} else {
		hdr.flags |= ZHPE_OFFLOADED_MSG_INLINE;
		hdr.inline_len = pe_entry->rem;
		memcpy(zhpe_offloaded_pay_ptr(conn, zhdr, 0, sizeof(int)),
		       iov[0].iov_base, pe_entry->rem);

		data = zhpe_offloaded_pay_ptr(conn, zhdr, pe_entry->rem,
				    __alignof__(*data));
		if (tagged)
			*data++ = htobe64(tag);
		if (hdr.flags & ZHPE_OFFLOADED_MSG_REMOTE_CQ_DATA)
			*data++ = htobe64(cq_data);
		cmd_len = (char *)data - (char *)zhdr;
		if (flags & FI_DELIVERY_COMPLETE) {
			hdr.flags |= ZHPE_OFFLOADED_MSG_DELIVERY_COMPLETE;
			pe_entry->pe_root.compstat.completions++;
		}
	}
	hdr.op_type = ZHPE_OFFLOADED_OP_SEND;
	*zhdr = hdr;
	pe_entry->flags = flags;
	zhpe_offloaded_stats_stamp(zhpe_offloaded_stats_subid(SEND, 35), (uintptr_t)pe_entry,
			 pe_entry->rem, fiaddr, flags, hdr.flags);
	zhpe_offloaded_stats_start(zhpe_offloaded_stats_subid(SEND, 40));
	ret = zhpe_offloaded_pe_tx_ring(pe_entry, zhdr, lzaddr, cmd_len);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(SEND, 40));
 done:
	if (ret < 0 && tindex != -1)
		zhpe_offloaded_tx_release(pe_entry);
	zhpe_offloaded_stats_stop(zhpe_offloaded_stats_subid(SEND, 0));

	return ret;
}

ssize_t zhpe_offloaded_do_sendmsg(struct fid_ep *ep, const void *vmsg,
			uint64_t flags, bool tagged)
{
    PRINT_DEBUG_LIBFAB;
	struct zhpe_offloaded_ep		*zhpe_offloaded_ep = container_of(ep, struct zhpe_offloaded_ep, ep);
	/* Used by trigger: flags are assumed to be correct. */
	return do_sendmsg(ep, vmsg, flags, tagged,
			  zhpe_offloaded_needs_locking(zhpe_offloaded_ep->attr->domain));
}

#define MSG_OPS(_name, _lock)						\
									\
static ssize_t zhpe_offloaded_ep_recvmsg##_name(struct fid_ep *ep,		\
				      const struct fi_msg *msg,		\
				      uint64_t flags)			\
{									\
    PRINT_DEBUG_LIBFAB;             \
	if (flags & ZHPE_OFFLOADED_BAD_FLAGS_MASK)				\
		return -EINVAL;						\
									\
	return do_recvmsg(ep, msg, flags, false, _lock);		\
}									\
									\
static ssize_t zhpe_offloaded_ep_recv##_name(struct fid_ep *ep, void *buf,	\
				   size_t len, void *desc,		\
				   fi_addr_t src_addr, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB; \
	struct fi_msg msg;						\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = buf;						\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.desc = &desc;						\
	msg.iov_count = 1;						\
	msg.addr = src_addr;						\
	msg.context = context;						\
									\
	return do_recvmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, false, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_recvv##_name(struct fid_ep *ep,			\
				    const struct iovec *iov,		\
				    void **desc, size_t count,		\
				    fi_addr_t src_addr,	void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg msg;						\
									\
	memset(&msg, 0, sizeof(msg));					\
									\
	msg.msg_iov = iov;						\
	msg.desc = desc;						\
	msg.iov_count = count;						\
	msg.addr = src_addr;						\
	msg.context = context;						\
									\
	return do_recvmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, false, _lock);	\
}									\
									\
									\
static ssize_t zhpe_offloaded_ep_sendmsg##_name(struct fid_ep *ep,		\
				      const struct fi_msg *msg,		\
				      uint64_t flags)			\
{									\
    PRINT_DEBUG_LIBFAB;     \
	if (flags & ZHPE_OFFLOADED_BAD_FLAGS_MASK)				\
		return -EINVAL;						\
	return do_sendmsg(ep, msg, flags, false, _lock);		\
}									\
									\
static ssize_t zhpe_offloaded_ep_send##_name(struct fid_ep *ep, const void *buf,	\
				   size_t len,void *desc,		\
				   fi_addr_t dest_addr, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg msg;						\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.desc = &desc;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.context = context;						\
									\
	return do_sendmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, false, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_sendv##_name(struct fid_ep *ep,			\
				    const struct iovec *iov,		\
				    void **desc, size_t count,		\
				    fi_addr_t dest_addr, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg msg;						\
									\
	memset(&msg, 0, sizeof(msg));					\
									\
	msg.msg_iov = iov;						\
	msg.desc = desc;						\
	msg.iov_count = count;						\
	msg.addr = dest_addr;						\
	msg.context = context;						\
									\
	return do_sendmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, false, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_senddata##_name(struct fid_ep *ep,		\
				       const void *buf, size_t len,	\
				       void *desc, uint64_t data,	\
				       fi_addr_t dest_addr,		\
				       void *context)			\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg msg;						\
	struct iovec msg_iov;						\
									\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.desc = &desc;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.context = context;						\
	msg.data = data;						\
									\
	return do_sendmsg(ep, &msg,					\
			  FI_REMOTE_CQ_DATA | ZHPE_OFFLOADED_USE_OP_FLAGS,	\
			  false, _lock);				\
}									\
									\
static ssize_t zhpe_offloaded_ep_inject##_name(struct fid_ep *ep,			\
				     const void *buf, size_t len,	\
				     fi_addr_t dest_addr)		\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg msg;						\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
									\
	return do_sendmsg(ep, &msg,					\
			  (FI_INJECT | ZHPE_OFFLOADED_NO_COMPLETION |		\
			   ZHPE_OFFLOADED_USE_OP_FLAGS), false, _lock);		\
}									\
									\
static ssize_t zhpe_offloaded_ep_injectdata##_name(struct fid_ep *ep,		\
					 const void *buf, size_t len,	\
					 uint64_t data,			\
					 fi_addr_t dest_addr)		\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg msg;						\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.data = data;						\
									\
	return do_sendmsg(ep, &msg,					\
			  (FI_REMOTE_CQ_DATA | FI_INJECT |		\
			   ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS),	\
			  false, _lock);				\
}									\
									\
struct fi_ops_msg zhpe_offloaded_ep_msg_ops##_name = {				\
	.size		= sizeof(struct fi_ops_msg),			\
	.recv		= zhpe_offloaded_ep_recv##_name,				\
	.recvv		= zhpe_offloaded_ep_recvv##_name,				\
	.recvmsg	= zhpe_offloaded_ep_recvmsg##_name,			\
	.send		= zhpe_offloaded_ep_send##_name,				\
	.sendv		= zhpe_offloaded_ep_sendv##_name,				\
	.sendmsg	= zhpe_offloaded_ep_sendmsg##_name,			\
	.inject		= zhpe_offloaded_ep_inject##_name,			\
	.senddata	= zhpe_offloaded_ep_senddata##_name,			\
	.injectdata	= zhpe_offloaded_ep_injectdata##_name,			\
};

MSG_OPS(_unlocked, false)
MSG_OPS(_locked, true)

#define TMSG_OPS(_name, _lock)						\
									\
static ssize_t zhpe_offloaded_ep_trecvmsg##_name(struct fid_ep *ep,		\
				       const struct fi_msg_tagged *msg,	\
				       uint64_t flags)			\
{									\
    PRINT_DEBUG_LIBFAB; \
	if (flags & ZHPE_OFFLOADED_PROV_FLAGS)					\
		return -FI_EINVAL;					\
									\
	return do_recvmsg(ep, msg, flags, true, _lock);			\
}									\
									\
static ssize_t zhpe_offloaded_ep_trecv##_name(struct fid_ep *ep, void *buf,	\
				    size_t len,	void *desc,		\
				    fi_addr_t src_addr, uint64_t tag,	\
				    uint64_t ignore, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = buf;						\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.desc = &desc;						\
	msg.iov_count = 1;						\
	msg.addr = src_addr;						\
	msg.context = context;						\
	msg.tag = tag;							\
	msg.ignore = ignore;						\
									\
	return do_recvmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, true, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_trecvv##_name(struct fid_ep *ep,			\
				    const struct iovec *iov,		\
				     void **desc, size_t count,		\
				     fi_addr_t src_addr, uint64_t tag,	\
				     uint64_t ignore, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
									\
	memset(&msg, 0, sizeof(msg));					\
									\
	msg.msg_iov = iov;						\
	msg.desc = desc;						\
	msg.iov_count = count;						\
	msg.addr = src_addr;						\
	msg.context = context;						\
	msg.tag = tag;							\
	msg.ignore = ignore;						\
									\
	return do_recvmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, true, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_tsendmsg##_name(struct fid_ep *ep,		\
				       const struct fi_msg_tagged *msg,	\
				       uint64_t flags)			\
{									\
    PRINT_DEBUG_LIBFAB;     \
	if (flags & ZHPE_OFFLOADED_BAD_FLAGS_MASK)				\
		return -EINVAL;						\
									\
	return do_sendmsg(ep, msg, flags, true, _lock);			\
}									\
									\
static ssize_t zhpe_offloaded_ep_tsend##_name(struct fid_ep *ep,			\
				    const void *buf, size_t len,	\
				    void *desc, fi_addr_t dest_addr,	\
				    uint64_t tag, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.desc = &desc;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.context = context;						\
	msg.tag = tag;							\
									\
	return do_sendmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, true, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_tsendv##_name(struct fid_ep *ep,			\
				     const struct iovec *iov,		\
				     void **desc, size_t count,		\
				     fi_addr_t dest_addr, uint64_t tag,	\
				     void *context)			\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
									\
	memset(&msg, 0, sizeof(msg));					\
									\
	msg.msg_iov = iov;						\
	msg.desc = desc;						\
	msg.iov_count = count;						\
	msg.addr = dest_addr;						\
	msg.context = context;						\
	msg.tag = tag;							\
									\
	return do_sendmsg(ep, &msg, ZHPE_OFFLOADED_USE_OP_FLAGS, true, _lock);	\
}									\
									\
static ssize_t zhpe_offloaded_ep_tsenddata##_name(struct fid_ep *ep,		\
					const void *buf, size_t len,	\
					void *desc, uint64_t data,	\
					fi_addr_t dest_addr,		\
					uint64_t tag, void *context)	\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.desc = desc;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.context = context;						\
	msg.data = data;						\
	msg.tag = tag;							\
									\
	return do_sendmsg(ep, &msg,					\
			  FI_REMOTE_CQ_DATA | ZHPE_OFFLOADED_USE_OP_FLAGS,	\
			  true, _lock);					\
}									\
									\
static ssize_t zhpe_offloaded_ep_tinject##_name(struct fid_ep *ep,		\
				      const void *buf, size_t len,	\
				      fi_addr_t dest_addr,		\
				      uint64_t tag)			\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.tag = tag;							\
									\
	return do_sendmsg(ep, &msg,					\
			  (FI_INJECT | ZHPE_OFFLOADED_NO_COMPLETION |		\
			   ZHPE_OFFLOADED_USE_OP_FLAGS), true, _lock);		\
}									\
									\
static ssize_t zhpe_offloaded_ep_tinjectdata##_name(struct fid_ep *ep,		\
					  const void *buf,		\
					  size_t len, uint64_t data,	\
					  fi_addr_t dest_addr,		\
					  uint64_t tag)			\
{									\
    PRINT_DEBUG_LIBFAB;     \
	struct fi_msg_tagged msg;					\
	struct iovec msg_iov;						\
									\
	memset(&msg, 0, sizeof(msg));					\
	msg_iov.iov_base = (void *) buf;				\
	msg_iov.iov_len = len;						\
									\
	msg.msg_iov = &msg_iov;						\
	msg.iov_count = 1;						\
	msg.addr = dest_addr;						\
	msg.data = data;						\
	msg.tag = tag;							\
									\
	return do_sendmsg(ep, &msg,					\
			  (FI_REMOTE_CQ_DATA | FI_INJECT |		\
			   ZHPE_OFFLOADED_NO_COMPLETION | ZHPE_OFFLOADED_USE_OP_FLAGS),	\
			  true, _lock);					\
}									\
									\
struct fi_ops_tagged zhpe_offloaded_ep_tagged##_name = {				\
	.size		= sizeof(struct fi_ops_tagged),			\
	.recv		= zhpe_offloaded_ep_trecv##_name,				\
	.recvv		= zhpe_offloaded_ep_trecvv##_name,			\
	.recvmsg	= zhpe_offloaded_ep_trecvmsg##_name,			\
	.send		= zhpe_offloaded_ep_tsend##_name,				\
	.sendv		= zhpe_offloaded_ep_tsendv##_name,			\
	.sendmsg	= zhpe_offloaded_ep_tsendmsg##_name,			\
	.inject		= zhpe_offloaded_ep_tinject##_name,			\
	.senddata	= zhpe_offloaded_ep_tsenddata##_name,			\
	.injectdata	= zhpe_offloaded_ep_tinjectdata##_name,			\
};

TMSG_OPS(_unlocked, false)
TMSG_OPS(_locked, true)
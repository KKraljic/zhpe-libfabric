/*
 * Copyright (c) 2014 Intel Corporation, Inc.  All rights reserved.
 * Copyright (c) 2016 Cisco Systems, Inc.  All rights reserved.
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

#include <zhpe.h>

#define ZHPE_OFFLOADED_LOG_DBG(...) _ZHPE_OFFLOADED_LOG_DBG(FI_LOG_FABRIC, __VA_ARGS__)
#define ZHPE_OFFLOADED_LOG_ERROR(...) _ZHPE_OFFLOADED_LOG_ERROR(FI_LOG_FABRIC, __VA_ARGS__)

int zhpe_offloaded_pe_waittime = ZHPE_OFFLOADED_PE_WAITTIME;
const char zhpe_offloaded_fab_name[] = "zhpe_offloaded_offloaded";
const char zhpe_offloaded_dom_name[] = "zhpe_offloaded_offloaded";
const char zhpe_offloaded_prov_name[] = "zhpe_offloaded_offloaded";
int zhpe_offloaded_conn_retry = ZHPE_OFFLOADED_CM_DEF_RETRY;
int zhpe_offloaded_cm_def_map_sz = ZHPE_OFFLOADED_CMAP_DEF_SZ;
int zhpe_offloaded_av_def_sz = ZHPE_OFFLOADED_AV_DEF_SZ;
int zhpe_offloaded_cq_def_sz = ZHPE_OFFLOADED_CQ_DEF_SZ;
int zhpe_offloaded_eq_def_sz = ZHPE_OFFLOADED_EQ_DEF_SZ;
char *zhpe_offloaded_pe_affinity_str = NULL;
size_t zhpe_offloaded_ep_max_eager_sz = ZHPE_OFFLOADED_EP_MAX_EAGER_SZ;
int zhpe_offloaded_mr_cache_enable = ZHPE_OFFLOADED_MR_CACHE_ENABLE;
int zhpe_offloaded_mr_cache_merge_regions = ZHPE_OFFLOADED_MR_CACHE_MERGE_REGIONS;
size_t zhpe_offloaded_mr_cache_max_cnt = ZHPE_OFFLOADED_MR_CACHE_MAX_CNT;
size_t zhpe_offloaded_mr_cache_max_size = ZHPE_OFFLOADED_MR_CACHE_MAX_SIZE;

const struct fi_fabric_attr zhpe_offloaded_fabric_attr = {
	.fabric = NULL,
	.name = NULL,
	.prov_name = NULL,
	.prov_version = FI_VERSION(ZHPE_OFFLOADED_MAJOR_VERSION, ZHPE_OFFLOADED_MINOR_VERSION),
};

static DEFINE_LIST(zhpe_offloaded_fab_list);
static DEFINE_LIST(zhpe_offloaded_dom_list);
static fastlock_t zhpe_offloaded_list_lock;
static int read_default_params;

void zhpe_offloaded_dom_add_to_list(struct zhpe_offloaded_domain *domain)
{
	fastlock_acquire(&zhpe_offloaded_list_lock);
	dlist_insert_tail(&domain->dom_lentry, &zhpe_offloaded_dom_list);
	fastlock_release(&zhpe_offloaded_list_lock);
}

static inline int zhpe_offloaded_dom_check_list_internal(struct zhpe_offloaded_domain *domain)
{
	struct zhpe_offloaded_domain	*dom_entry;

	dlist_foreach_container(&zhpe_offloaded_dom_list, struct zhpe_offloaded_domain, dom_entry,
				dom_lentry) {
		if (dom_entry == domain)
			return 1;
	}
	return 0;
}

int zhpe_offloaded_dom_check_list(struct zhpe_offloaded_domain *domain)
{
	int found;
	fastlock_acquire(&zhpe_offloaded_list_lock);
	found = zhpe_offloaded_dom_check_list_internal(domain);
	fastlock_release(&zhpe_offloaded_list_lock);
	return found;
}

void zhpe_offloaded_dom_remove_from_list(struct zhpe_offloaded_domain *domain)
{
	fastlock_acquire(&zhpe_offloaded_list_lock);
	if (zhpe_offloaded_dom_check_list_internal(domain))
		dlist_remove(&domain->dom_lentry);

	fastlock_release(&zhpe_offloaded_list_lock);
}

struct zhpe_offloaded_domain *zhpe_offloaded_dom_list_head(void)
{
	struct zhpe_offloaded_domain *domain;
	fastlock_acquire(&zhpe_offloaded_list_lock);
	if (dlist_empty(&zhpe_offloaded_dom_list)) {
		domain = NULL;
	} else {
		domain = container_of(zhpe_offloaded_dom_list.next,
				      struct zhpe_offloaded_domain, dom_lentry);
	}
	fastlock_release(&zhpe_offloaded_list_lock);
	return domain;
}

int zhpe_offloaded_dom_check_manual_progress(struct zhpe_offloaded_fabric *fabric)
{
	struct zhpe_offloaded_domain	*dom_entry;

	dlist_foreach_container(&zhpe_offloaded_dom_list, struct zhpe_offloaded_domain, dom_entry,
				dom_lentry) {
		if (dom_entry->fab == fabric &&
		    dom_entry->progress_mode == FI_PROGRESS_MANUAL)
			return 1;
	}
	return 0;
}

void zhpe_offloaded_fab_add_to_list(struct zhpe_offloaded_fabric *fabric)
{
	fastlock_acquire(&zhpe_offloaded_list_lock);
	dlist_insert_tail(&fabric->fab_lentry, &zhpe_offloaded_fab_list);
	fastlock_release(&zhpe_offloaded_list_lock);
}

static inline int zhpe_offloaded_fab_check_list_internal(struct zhpe_offloaded_fabric *fabric)
{
	struct zhpe_offloaded_fabric	*fab_entry;

	dlist_foreach_container(&zhpe_offloaded_fab_list, struct zhpe_offloaded_fabric, fab_entry,
				fab_lentry) {
		if (fab_entry == fabric)
			return 1;
	}
	return 0;
}

int zhpe_offloaded_fab_check_list(struct zhpe_offloaded_fabric *fabric)
{
	int found;
	fastlock_acquire(&zhpe_offloaded_list_lock);
	found = zhpe_offloaded_fab_check_list_internal(fabric);
	fastlock_release(&zhpe_offloaded_list_lock);
	return found;
}

void zhpe_offloaded_fab_remove_from_list(struct zhpe_offloaded_fabric *fabric)
{
	fastlock_acquire(&zhpe_offloaded_list_lock);
	if (zhpe_offloaded_fab_check_list_internal(fabric))
		dlist_remove(&fabric->fab_lentry);

	fastlock_release(&zhpe_offloaded_list_lock);
}

struct zhpe_offloaded_fabric *zhpe_offloaded_fab_list_head(void)
{
	struct zhpe_offloaded_fabric *fabric;
	fastlock_acquire(&zhpe_offloaded_list_lock);
	if (dlist_empty(&zhpe_offloaded_fab_list))
		fabric = NULL;
	else
		fabric = container_of(zhpe_offloaded_fab_list.next,
				      struct zhpe_offloaded_fabric, fab_lentry);
	fastlock_release(&zhpe_offloaded_list_lock);
	return fabric;
}

int zhpe_offloaded_verify_fabric_attr(struct fi_fabric_attr *attr)
{
	if (!attr)
		return 0;

	if (attr->prov_version) {
		if (attr->prov_version !=
		   FI_VERSION(ZHPE_OFFLOADED_MAJOR_VERSION, ZHPE_OFFLOADED_MINOR_VERSION))
			return -FI_ENODATA;
	}

	return 0;
}

int zhpe_offloaded_verify_info(uint32_t api_version, const struct fi_info *hints,
		     uint64_t flags)
{
	int			ret = 0;
	uint64_t		caps;
	enum fi_ep_type		ep_type;
	struct zhpe_offloaded_domain	*domain;
	struct zhpe_offloaded_fabric	*fabric;
	struct addrinfo		ai;
	struct addrinfo		*rai;

	if (!hints)
		return 0;

	ep_type = hints->ep_attr ? hints->ep_attr->type : FI_EP_UNSPEC;
	switch (ep_type) {

	/* FIXME: Debug FI_EP_MSG */
	case FI_EP_MSG:
		return -FI_ENODATA;
#if 0
		caps = ZHPE_OFFLOADED_EP_MSG_CAP;
		ret = zhpe_offloaded_msg_verify_ep_attr(hints->ep_attr,
					      hints->tx_attr,
					      hints->rx_attr);
#endif
		break;

	case FI_EP_UNSPEC:
		/* UNSPEC => RDM, for now. */
	case FI_EP_RDM:
		caps = ZHPE_OFFLOADED_EP_RDM_CAP;
		ret = zhpe_offloaded_rdm_verify_ep_attr(hints->ep_attr,
					      hints->tx_attr,
					      hints->rx_attr);
		break;

	default:
		ret = -FI_ENODATA;
		break;

	}
	if (ret < 0)
		return ret;

	if ((caps | hints->caps) != caps) {
		ZHPE_OFFLOADED_LOG_DBG("Unsupported capabilities\n");
		return -FI_ENODATA;
	}

	switch (hints->addr_format) {

	case FI_FORMAT_UNSPEC:

	case FI_SOCKADDR:
		/* FIXME: Think about FI_SOCKADDR vs IPV6 some more. */
	case FI_SOCKADDR_IN:
		break;

	case FI_SOCKADDR_IN6:
		/* Are IPV6 addresses configured? */
		zhpe_offloaded_getaddrinfo_hints_init(&ai, AF_INET6);
		ai.ai_flags |= AI_PASSIVE;
		ret = zhpe_offloaded_getaddrinfo(NULL, "0", &ai, &rai);
		if (ret < 0)
			/* No. */
			return -FI_ENODATA;
		freeaddrinfo(rai);
		break;

	default:
		ZHPE_OFFLOADED_LOG_DBG("Unsupported address format\n");
		return -FI_ENODATA;
	}

	if (hints->domain_attr && hints->domain_attr->domain) {
		domain = container_of(hints->domain_attr->domain,
				      struct zhpe_offloaded_domain, dom_fid);
		if (!zhpe_offloaded_dom_check_list(domain)) {
			ZHPE_OFFLOADED_LOG_DBG("no matching domain\n");
			return -FI_ENODATA;
		}
	}
	ret = zhpe_offloaded_verify_domain_attr(api_version, hints);
	if (ret < 0)
		return ret;

	if (hints->fabric_attr && hints->fabric_attr->fabric) {
		fabric = container_of(hints->fabric_attr->fabric,
				      struct zhpe_offloaded_fabric, fab_fid);
		if (!zhpe_offloaded_fab_check_list(fabric)) {
			ZHPE_OFFLOADED_LOG_DBG("no matching fabric\n");
			return -FI_ENODATA;
		}
	}
	ret = zhpe_offloaded_verify_fabric_attr(hints->fabric_attr);
	if (ret < 0)
		return ret;

	return 0;
}

static int zhpe_offloaded_trywait(struct fid_fabric *fabric, struct fid **fids, int count)
{
	/* we're always ready to wait! */
	return 0;
}

static struct fi_ops_fabric zhpe_offloaded_fab_ops = {
	.size = sizeof(struct fi_ops_fabric),
	.domain = zhpe_offloaded_domain,
	.passive_ep = zhpe_offloaded_msg_passive_ep,
	.eq_open = zhpe_offloaded_eq_open,
	.wait_open = zhpe_offloaded_wait_open,
	.trywait = zhpe_offloaded_trywait
};

static int zhpe_offloaded_fabric_close(fid_t fid)
{
	struct zhpe_offloaded_fabric *fab;
	fab = container_of(fid, struct zhpe_offloaded_fabric, fab_fid.fid);
	if (atm_load_rlx(&fab->ref))
		return -FI_EBUSY;

	zhpe_offloaded_fab_remove_from_list(fab);
	fastlock_destroy(&fab->lock);
	free(fab);
	return 0;
}

static int zhpe_offloaded_fabric_ext_lookup(const char *url, void **sa, size_t *sa_len)
{
	int			ret = -FI_EINVAL;
	const char		fam_pfx[] = "zhpe_offloaded_offloaded:///fam";
	const size_t		fam_pfx_len = strlen(fam_pfx);
	const char		*p = url;
	struct sockaddr_zhpe	*sz;
	char			*e;
	ulong			v;

	if (!sa)
		goto done;
	*sa = NULL;
	if (!url || !sa_len || !zhpeq_is_asic())
		goto done;
	if (strncmp(url, fam_pfx, fam_pfx_len)) {
		ret = -FI_ENOENT;
		goto done;
	}
	p += fam_pfx_len;
	if (!*p)
		goto done;
	errno = 0;
	v = strtoul(p, &e, 0);
	if (errno) {
		ret = -errno;
		goto done;
	}
	if (*e)
		goto done;
	*sa_len = 2 * sizeof(*sz);
	sz = calloc(1, *sa_len);
	if (!sz) {
		ret = -errno;
		goto done;
	}
	*sa = sz;
	sz->sz_family = AF_ZHPE;
	v += 0x40;
	sz->sz_uuid[0] = v >> 20;
	sz->sz_uuid[1] = v >> 12;
	sz->sz_uuid[2] = v >> 4;
	sz->sz_uuid[3] = v << 4;
	/* Assume 32 GB for now. */
	sz->sz_queue = ZHPE_OFFLOADED_SA_TYPE_FAM | 32;

	ret = 0;
 done:
	return ret;
}

static struct fi_zhpe_offloaded_ext_ops_v1 zhpe_offloaded_fabric_ext_ops_v1 = {
	.lookup			= zhpe_offloaded_fabric_ext_lookup,
};

static int zhpe_offloaded_fabric_ops_open(struct fid *fid, const char *ops_name,
				uint64_t flags, void **ops, void *context)
{
	int			ret = 0;

	if (!fid || fid->fclass != FI_CLASS_FABRIC ||
	    !ops_name || flags || context) {
		ret = -FI_EINVAL;
		goto done;
	}
	if (!strcmp(ops_name, FI_ZHPE_OFFLOADED_OPS_V1))
		*ops = &zhpe_offloaded_fabric_ext_ops_v1;
	else {
		ret = -FI_EINVAL;
		goto done;
	}
 done:
	return ret;
}

static struct fi_ops zhpe_offloaded_fab_fi_ops = {
	.size = sizeof(struct fi_ops),
	.close = zhpe_offloaded_fabric_close,
	.bind = fi_no_bind,
	.control = fi_no_control,
	.ops_open = zhpe_offloaded_fabric_ops_open,
};

static void zhpe_offloaded_read_default_params()
{
	if (!read_default_params) {
		fi_param_get_int(&zhpe_offloaded_prov, "pe_waittime", &zhpe_offloaded_pe_waittime);
		fi_param_get_int(&zhpe_offloaded_prov, "max_conn_retry",
				 &zhpe_offloaded_conn_retry);
		fi_param_get_int(&zhpe_offloaded_prov, "def_av_sz", &zhpe_offloaded_av_def_sz);
		fi_param_get_int(&zhpe_offloaded_prov, "def_cq_sz", &zhpe_offloaded_cq_def_sz);
		fi_param_get_int(&zhpe_offloaded_prov, "def_eq_sz", &zhpe_offloaded_eq_def_sz);
		if (fi_param_get_str(&zhpe_offloaded_prov, "pe_affinity",
				     &zhpe_offloaded_pe_affinity_str) != FI_SUCCESS)
			zhpe_offloaded_pe_affinity_str = NULL;
		fi_param_get_size_t(&zhpe_offloaded_prov, "ep_max_eager_sz",
				    &zhpe_offloaded_ep_max_eager_sz);
		fi_param_get_bool(&zhpe_offloaded_prov, "mr_cache_enable",
				  &zhpe_offloaded_mr_cache_enable);
		fi_param_get_bool(&zhpe_offloaded_prov, "mr_cache_merge_regions",
				  &zhpe_offloaded_mr_cache_merge_regions);
		fi_param_get_size_t(&zhpe_offloaded_prov, "mr_cache_max_cnt",
				    &zhpe_offloaded_mr_cache_max_cnt);
		fi_param_get_size_t(&zhpe_offloaded_prov, "mr_cache_max_size",
				    &zhpe_offloaded_mr_cache_max_size);

		read_default_params = 1;
	}
}

static int zhpe_offloaded_fabric(struct fi_fabric_attr *attr,
		       struct fid_fabric **fabric, void *context)
{
	struct zhpe_offloaded_fabric *fab;

	fab = calloc(1, sizeof(*fab));
	if (!fab)
		return -FI_ENOMEM;

	zhpe_offloaded_read_default_params();

	fastlock_init(&fab->lock);
	dlist_init(&fab->service_list);

	fab->fab_fid.fid.fclass = FI_CLASS_FABRIC;
	fab->fab_fid.fid.context = context;
	fab->fab_fid.fid.ops = &zhpe_offloaded_fab_fi_ops;
	fab->fab_fid.ops = &zhpe_offloaded_fab_ops;
	*fabric = &fab->fab_fid;
	zhpe_offloaded_fab_add_to_list(fab);
	return 0;
}

static int zhpe_offloaded_fi_checkinfo(struct fi_info *info, const struct fi_info *hints)
{
	if (hints && hints->domain_attr && hints->domain_attr->name &&
            strcmp(info->domain_attr->name, hints->domain_attr->name))
		return -FI_ENODATA;

	if (hints && hints->fabric_attr && hints->fabric_attr->name &&
            strcmp(info->fabric_attr->name, hints->fabric_attr->name))
		return -FI_ENODATA;

	return 0;
}

static bool hints_addr_valid(const struct fi_info *hints,
			     const void *addr, size_t addr_len)
{
	const union sockaddr_in46 *sa = addr;

	if (hints->addr_format == FI_SOCKADDR_IN6) {
		if (sa->sa_family != AF_INET6)
			return false;
	} else if (sa->sa_family != AF_INET)
		return false;

	return sockaddr_valid(addr, addr_len, true);
}

static int zhpe_offloaded_ep_getinfo(uint32_t api_version, const char *node,
			   const char *service, uint64_t flags,
			   const struct fi_info *hints,
			   enum fi_ep_type ep_type, struct fi_info **info)
{
	int			ret = 0;
	struct addrinfo		*rai = NULL;
	union sockaddr_in46	*src_addr = NULL;
	union sockaddr_in46	*dest_addr = NULL;
	struct addrinfo		ai;
#if ENABLE_DEBUG
	char			ntop[INET6_ADDRSTRLEN];
#endif

	zhpe_offloaded_getaddrinfo_hints_init(&ai, zhpe_offloaded_sa_family(hints));

	if (flags & FI_NUMERICHOST)
		ai.ai_flags |= AI_NUMERICHOST;

	if (flags & FI_SOURCE) {
		if (node || service) {
			ai.ai_flags |= AI_PASSIVE;
			ret = zhpe_offloaded_getaddrinfo(node, service, &ai, &rai);
			if (ret < 0)
				return -FI_ENODATA;
			src_addr = (void *)rai->ai_addr;
		}
	} else {
		if (hints && hints->src_addr) {
			if (!hints_addr_valid(hints, hints->src_addr,
					      hints->src_addrlen))
				return -FI_ENODATA;
			src_addr = hints->src_addr;
		}

		if (node || service) {
			ret = zhpe_offloaded_getaddrinfo(node, service, &ai, &rai);
			if (ret < 0)
				return -FI_ENODATA;
			dest_addr = (void *)rai->ai_addr;
		} else  if (hints && hints->dest_addr) {
			if (!hints_addr_valid(hints, hints->dest_addr,
					      hints->dest_addrlen))
				return -FI_ENODATA;
			dest_addr = hints->dest_addr;
		}
		if (dest_addr && !src_addr) {
			ai.ai_flags |= AI_PASSIVE;
			ret = zhpe_offloaded_getaddrinfo(NULL, "0", &ai, &rai);
			if (ret < 0)
				return -FI_ENODATA;
			src_addr = (void *)rai->ai_addr;
		}
	}

	if (src_addr)
		ZHPE_OFFLOADED_LOG_DBG("src_addr: %s\n",
			     sockaddr_ntop(src_addr, ntop, sizeof(ntop)));
	if (dest_addr)
		ZHPE_OFFLOADED_LOG_DBG("dest_addr: %s\n",
			     sockaddr_ntop(dest_addr, ntop, sizeof(ntop)));

	switch (ep_type) {
	case FI_EP_MSG:
		ret = zhpe_offloaded_msg_fi_info(api_version, src_addr, dest_addr,
				       hints, info);
		break;
	case FI_EP_RDM:
		ret = zhpe_offloaded_rdm_fi_info(api_version, src_addr, dest_addr,
				       hints, info);
		break;
	default:
		ret = -FI_ENODATA;
		break;
	}

	if (rai)
		freeaddrinfo(rai);

	if (ret == 0)
		return zhpe_offloaded_fi_checkinfo(*info, hints);

	return ret;
}

static inline int do_ep_getinfo(uint32_t api_version, const char *node,
				const char *service, uint64_t flags,
				const struct fi_info *hints,
				struct fi_info **info, struct fi_info **tail,
				enum fi_ep_type ep_type)
{
	int			ret;
	struct fi_info		*cur;

	ret = zhpe_offloaded_ep_getinfo(api_version, node, service, flags,
			      hints, ep_type,  &cur);
	if (ret < 0)
		goto done;
	if (!*info)
		*info = cur;
	else
		(*tail)->next = cur;
	for (*tail = cur; (*tail)->next; *tail = (*tail)->next)
		;
 done:
	return ret;
}

static int zhpe_offloaded_node_getinfo(uint32_t api_version, const char *node,
			     const char *service,
			     uint64_t flags, const struct fi_info *hints,
			     struct fi_info **info, struct fi_info **tail)
{
	int			ret;
	enum fi_ep_type		ep_type;

	if (hints && hints->ep_attr) {
		ep_type = hints->ep_attr->type;

		switch (ep_type) {

		case FI_EP_RDM:
		case FI_EP_MSG:
			ret = do_ep_getinfo(api_version, node, service, flags,
					    hints, info, tail, ep_type);
			goto done;

		case FI_EP_UNSPEC:
			break;

		default:
			ret = -FI_ENODATA;
			goto done;
		}
	}
	for (ep_type = FI_EP_MSG; ep_type <= FI_EP_RDM; ep_type++) {
		ret = do_ep_getinfo(api_version, node, service, flags,
				    hints, info, tail, ep_type);
		if (ret < 0) {
			if (ret == -FI_ENODATA)
				continue;
			goto done;
		}
	}
 done:
	if (ret < 0) {
		fi_freeinfo(*info);
		*info = NULL;
	}

	return ret;
}

static int zhpe_offloaded_getinfo(uint32_t api_version, const char *node,
			const char *service,
			uint64_t flags, const struct fi_info *hints,
			struct fi_info **info)
{
	int			ret = 0;
	struct fi_info		*tail;

	ret = zhpeq_init(ZHPEQ_API_VERSION);
	if (ret < 0) {
		ZHPE_OFFLOADED_LOG_ERROR("zhpeq_init() returned error:%s\n",
			       strerror(-ret));
		return -FI_ENODATA;
	}

	*info = tail = NULL;

	ret = zhpe_offloaded_verify_info(api_version, hints, flags);
	if (ret < 0)
		return ret;

	if (!(node ||
	      (!(flags & FI_SOURCE) && hints && 
	       (hints->src_addr || hints->dest_addr)))) {
		flags |= FI_SOURCE;
		if (!service)
			service = "0";
	}

	return zhpe_offloaded_node_getinfo(api_version, node, service, flags, hints,
				 info, &tail);
}

static void fi_zhpe_offloaded_fini(void)
{
	fastlock_destroy(&zhpe_offloaded_list_lock);
}

struct fi_provider zhpe_offloaded_prov = {
	.name = zhpe_offloaded_prov_name,
	.version = FI_VERSION(ZHPE_OFFLOADED_MAJOR_VERSION, ZHPE_OFFLOADED_MINOR_VERSION),
	.fi_version = FI_VERSION(1, 6),
	.getinfo = zhpe_offloaded_getinfo,
	.fabric = zhpe_offloaded_fabric,
	.cleanup = fi_zhpe_offloaded_fini
};

ZHPE_OFFLOADED_INI
{
	fi_param_define(&zhpe_offloaded_prov, "pe_waittime", FI_PARAM_INT,
			"How many milliseconds to spin while waiting"
			" for progress");

	fi_param_define(&zhpe_offloaded_prov, "max_conn_retry", FI_PARAM_INT,
			"Number of connection retries before reporting"
			" as failure");

	fi_param_define(&zhpe_offloaded_prov, "def_av_sz", FI_PARAM_INT,
			"Default address vector size");

	fi_param_define(&zhpe_offloaded_prov, "def_cq_sz", FI_PARAM_INT,
			"Default completion queue size");

	fi_param_define(&zhpe_offloaded_prov, "def_eq_sz", FI_PARAM_INT,
			"Default event queue size");

	fi_param_define(&zhpe_offloaded_prov, "pe_affinity", FI_PARAM_STRING,
			"If specified, bind the progress thread to the"
			" indicated range(s) of Linux virtual processor ID(s)."
			" This option is currently not supported on OS X."
			" Usage: id_start[-id_end[:stride]][,]");

	fi_param_define(&zhpe_offloaded_prov, "ep_max_eager_sz", FI_PARAM_SIZE_T,
			"Maximum size of eager message");

	fi_param_define(&zhpe_offloaded_prov, "mr_cache_enable", FI_PARAM_BOOL,
			"Enable/disable registration cache");

	fi_param_define(&zhpe_offloaded_prov, "mr_cache_merge_regions", FI_PARAM_BOOL,
			"Enable/disable merging cache regions");

	fi_param_define(&zhpe_offloaded_prov, "mr_cache_max_cnt", FI_PARAM_SIZE_T,
			"Maximum number of registrations in cache");

	fi_param_define(&zhpe_offloaded_prov, "mr_cache_max_size", FI_PARAM_SIZE_T,
			"Maximum total size of cached registrations");

#ifdef HAVE_ZHPE_OFFLOADED_STATS
	fi_param_define(&zhpe_offloaded_prov, "stats_dir", FI_PARAM_STRING,
			"Enables simulator statistics collection into the"
			" specified directory.");

	fi_param_define(&zhpe_offloaded_prov, "stats_unique", FI_PARAM_STRING,
			"Uniquifier for filenames in stats directory.");
#endif

	fastlock_init(&zhpe_offloaded_list_lock);

	return &zhpe_offloaded_prov;
}

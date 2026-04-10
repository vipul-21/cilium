/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __LIB_MESH_H_
#define __LIB_MESH_H_

#include "common.h"
#include "eps.h"

/* DSCP value used to signal mTLS mesh (HBONE) traffic to ztunnel.
 * Stamped by BPF when both source and destination are meshed.
 * iptables PREROUTING in the pod netns matches this and REDIRECTs
 * to port 15008 (ztunnel HBONE inbound).
 * TOS byte = DSCP << 2 = 0x17 << 2 = 0x5c.
 */
#define DSCP_MESHED_MARK	0x17
#define TOS_MESHED_MARK		(DSCP_MESHED_MARK << 2)

/* is_ip4_meshed checks if the given IPv4 address belongs to a meshed endpoint
 * by looking up the local endpoint map and ipcache for the meshed flag.
 */
static __always_inline bool is_ip4_meshed(__u32 ip4)
{
	const struct endpoint_info *ep;

	ep = __lookup_ip4_endpoint(ip4);
	if (ep && (ep->flags & ENDPOINT_F_MESHED))
		return true;

	const struct remote_endpoint_info *info;

	info = lookup_ip4_remote_endpoint(ip4, 0);
	if (info && info->flag_meshed)
		return true;

	return false;
}

/* ipv4_set_dscp_meshed stamps the DSCP meshed mark on the packet's
 * TOS byte and updates the IPv4 header checksum accordingly.
 * Returns 0 on success, negative on failure.
 */
static __always_inline int
ipv4_set_dscp_meshed(struct __ctx_buff *ctx, int l3_off, struct iphdr *ip4)
{
	__u8 old_tos = ip4->tos;
	__u8 new_tos = (old_tos & 0x3) | TOS_MESHED_MARK;
	int ret;

	if (old_tos == new_tos)
		return 0;

	ret = l3_csum_replace(ctx, l3_off + offsetof(struct iphdr, check),
			      bpf_htons((__u16)old_tos), bpf_htons((__u16)new_tos), 2);
	if (ret < 0)
		return ret;

	return ctx_store_bytes(ctx, l3_off + offsetof(struct iphdr, tos),
			       &new_tos, sizeof(new_tos), 0);
}

#endif /* __LIB_MESH_H_ */

/*
 * mixed_mode/mixed_mode.c - Module for querying DNSSEC not enabled NS for Insecure zones
 * 
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Author: Tomas Hozza <thozza@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */ 

/**
 * \file
 *
 * This file contains a module that performs queries to NS possibly
 * without DNSSEC support for Insecure zones.
 *
 * Usable for split DNS view, or if connected to corporate network
 * without DNSSEC enabled nameservers. Most usable together with
 * dnssec-trigger
 */

#include "config.h"
#include "mixed_mode/mixed_mode.h"
#include "mixed_mode/mm_fwds.h"
#include "services/cache/rrset.h"
#include "services/cache/dns.h"
#include "services/outbound_list.h"
#include "util/config_file.h"
#include "util/data/msgreply.h"
#include "util/data/packed_rrset.h"
#include "util/fptr_wlist.h"
#include "util/net_help.h"
#include "util/regional.h"
#include "sldns/sbuffer.h"

/**
 * Flush the queried name from from rrset and msg caches
 */
static void
flush_query_from_cache(struct module_qstate* qstate)
{
	log_query_info(VERB_ALGO, "mixed-mode: flushing query from cache", &qstate->qinfo);

	hashvalue_t h;
	rrset_cache_remove(qstate->env->rrset_cache, qstate->qinfo.qname, qstate->qinfo.qname_len,
			   qstate->qinfo.qtype, qstate->qinfo.qclass, 0);

	if(qstate->qinfo.qtype == LDNS_RR_TYPE_SOA)
		rrset_cache_remove(qstate->env->rrset_cache, qstate->qinfo.qname, qstate->qinfo.qname_len,
				   qstate->qinfo.qtype, qstate->qinfo.qclass, PACKED_RRSET_SOA_NEG);

	h = query_info_hash(&qstate->qinfo, 0);
	slabhash_remove(qstate->env->msg_cache, h, &qstate->qinfo);

	if(qstate->qinfo.qtype == LDNS_RR_TYPE_AAAA) {
		/* for AAAA also flush dns64 bit_cd packet */
		h = query_info_hash(&qstate->qinfo, BIT_CD);
		slabhash_remove(qstate->env->msg_cache, h, &qstate->qinfo);
	}
}

//------------------------------------------------------------------------------------

/**
 * New query for mixed-mode module. Allocate and initialize the
 * module state per query.
 */
static int mixed_mode_newq(struct module_qstate* qstate, int id)
{
	struct mixed_mode_qstate* mmq = (struct mixed_mode_qstate*)regional_alloc(qstate->region, sizeof(*mmq));
	if (!mmq)
		return 0;

	qstate->minfo[id] = (void*)mmq;

	mmq->state = MIXED_MODE_NEW_CLIENT_QUERY;
	mmq->forwarder = NULL;
	mmq->response = NULL;
	outbound_list_init(&mmq->outlist);

	return 1;
}

/*
 * Send outbound query to a forwarder
 */
static void send_query_to_forwarder(struct module_qstate* qstate, struct mixed_mode_env* mme,
				   struct mixed_mode_qstate* mmq, int id)
{
	struct outbound_entry* outq;
	struct sock_list* target = NULL;

	if (!qstate->env->mm_fwds->list)
		verbose(VERB_ALGO, "mixed-mode: No forwarders configured!");

	/* check if we have some forwarder to send query to */
	if (!mmq->forwarder) {
		mmq->forwarder = qstate->env->mm_fwds->list;
		target = mmq->forwarder;
	}
	/* we already forwarded the query to some resolver, use next one */
	else if (mmq->forwarder->next) {
		mmq->forwarder = mmq->forwarder->next;
		target = mmq->forwarder;
	}

	/* do we have some target to send the query to? If not, just end */
	if (!target) {
		verbose(VERB_ALGO, "mixed-mode: No more forwarders to try");
		mmq->state = MIXED_MODE_FINISHED;
		qstate->ext_state[id] = module_finished;
		return;
	}

	log_query_info(VERB_ALGO, "mixed-mode: sending query:", &qstate->qinfo);
	log_name_addr(VERB_ALGO, "mixed-mode: sending to target:", qstate->qinfo.qname, &target->addr, target->len);

	/* send the query to the insecure resolver */
	fptr_ok(fptr_whitelist_modenv_send_query(qstate->env->send_query));
	outq = (*qstate->env->send_query)(
		qstate->qinfo.qname, qstate->qinfo.qname_len,
		qstate->qinfo.qtype, qstate->qinfo.qclass,
		qstate->query_flags, 0 /* dnssec */,
		0 /* want_dnssec */, 0 /* caps fallback */, &target->addr,
		target->len, qstate->qinfo.qname /* DP zone name */, qstate->qinfo.qname_len /* DP zone name len */, qstate);

	if(!outq) {
		log_addr(VERB_ALGO, "mixed-mode: error sending query to insecure forwarder",
			 &target->addr, target->len);
		mmq->state = MIXED_MODE_FINISHED;
		qstate->ext_state[id] = module_error;
		return;
	}

	outbound_list_insert(&mmq->outlist, outq);
	mmq->state = MIXED_MODE_WAIT_OUTBOUND_QUERY;
	qstate->ext_state[id] = module_wait_reply;
}

/*
 * Process response from the upstream resolver.
 */
static void handle_response(struct module_qstate* qstate, struct mixed_mode_env* mme,
			    struct mixed_mode_qstate* mmq, int id, struct outbound_entry* outbound,
			    enum module_ev event)
{
	struct msg_parse* prs;
	sldns_buffer* pkt;

	verbose(VERB_ALGO, "mixed-mode: new external response event");

	mmq->state = MIXED_MODE_HAVE_RESPONSE;

	/* No reply, try other forwarders */
	if (event == module_event_noreply) {
		/* send_query_to_forwarder sets up the external state if necessary */
		send_query_to_forwarder(qstate, mme, mmq, id);
		goto exit;
	}

	/* parse the message */
	prs = (struct msg_parse*)regional_alloc(qstate->env->scratch, sizeof(struct msg_parse));
	if(!prs) {
		log_err("mixed-mode: out of memory on incoming message");
		qstate->ext_state[id] = module_error;
		goto exit;
	}

	memset(prs, 0, sizeof(*prs));
	pkt = qstate->reply->c->buffer;
	sldns_buffer_set_position(pkt, 0);
	if(parse_packet(pkt, prs, qstate->env->scratch) != LDNS_RCODE_NOERROR) {
		verbose(VERB_ALGO, "mixed-mode: parse error on reply packet");
		qstate->ext_state[id] = module_error;
		goto exit;
	}

	/* allocate response dns_msg in region */
	mmq->response = (struct dns_msg*)regional_alloc(qstate->region, sizeof(struct dns_msg));
	if(!mmq->response) {
		log_err("mixed-mode: out of memory on incoming message");
		qstate->ext_state[id] = module_error;
		goto exit;
	}
	memset(mmq->response, 0, sizeof(*mmq->response));
	if(!parse_create_msg(pkt, prs, NULL, &mmq->response->qinfo, &mmq->response->rep, qstate->region)) {
		log_err("mixed-mode: failed to allocate incoming dns_msg");
		qstate->ext_state[id] = module_error;
		goto exit;
	}

	log_query_info(VERB_DETAIL, "mixed-mode: response for", &qstate->qinfo);
	log_name_addr(VERB_DETAIL, "mixed-mode: reply from", qstate->qinfo.qname, &qstate->reply->addr, qstate->reply->addrlen);
	log_dns_msg("mixed-mode: incoming packet:", &mmq->response->qinfo, mmq->response->rep);

	mmq->state = MIXED_MODE_FINISHED;

	/* We have to flush the cache for this query, to prevent unbound from responding
	 * directly from cache next time! */
	flush_query_from_cache(qstate);

	/* We used insecure forwarder. If validator is used, the need_to_validate is set.
	 * In such case the mesh returns SERVFAIL is message is unchecked!
	 * set the security state from the original response - which is INSECURE or INDETERMINATE */
	mmq->response->rep->security = qstate->return_msg->rep->security;

	/* copy the response */
	qstate->return_rcode = LDNS_RCODE_NOERROR;
	qstate->return_msg = mmq->response;

	/* make sure QR flag is on */
	qstate->return_msg->rep->flags |= BIT_QR;

	outbound_list_clear(&mmq->outlist); // close all outstanding outbound requests
	qstate->ext_state[id] = module_finished;
	return;

exit:
	outbound_list_remove(&mmq->outlist, outbound);
}

/**
 * Handle finished query pased from succesing module.
 */
static void handle_event_moddone(struct module_qstate* qstate, struct mixed_mode_env* mme,
				 struct mixed_mode_qstate* mmq, int id)
{
	/* If it was query generated by the client, handle it */
	if (mmq->state == MIXED_MODE_NEW_CLIENT_QUERY) {

		verbose(VERB_ALGO, "mixed-mode: handling query in state MIXED_MODE_NEW_CLIENT_QUERY");

		/* The response is INSECURE or INDETERMINATE */
		if ((qstate->return_msg && qstate->return_msg->rep &&
			(qstate->return_msg->rep->security == sec_status_insecure ||
			qstate->return_msg->rep->security == sec_status_indeterminate))) {

			verbose(VERB_ALGO, "mixed-mode: handling INSECURE/INDETERMINATE answer");
			verbose(VERB_QUERY, "mixed-mode: trying an insecure forwarder");

			(void)send_query_to_forwarder(qstate, mme, mmq, id);
			return;
		}
		else {
			if (qstate->return_msg) {
				verbose(VERB_ALGO, "mixed-mode: query not INSECURE nor INDETERMINATE, result %d", qstate->return_msg->rep->security);
			}
			else {
				verbose(VERB_ALGO, "mixed-mode: no response!");
			}
		}
	}
	else {
		verbose(VERB_ALGO, "mixed-mode: moddone with query in unexpected state %d", mmq->state);
	}

	qstate->ext_state[id] = module_finished;
}

/**
 * Initializes this instance of the mixed-mode module.
 *
 * \param env Global state of all module instances.
 * \param id  This instance's ID number.
 */
int mixed_mode_init(struct module_env* env, int id)
{
	struct mixed_mode_env* mme = (struct mixed_mode_env*)calloc(1, sizeof(struct mixed_mode_env));
	if (!mme) {
		log_err("mixed-mode: malloc of module environment failed");
		return 0;
	}

	env->mm_fwds = mm_forwards_create();
	if (!env->mm_fwds) {
		log_err("mixed-mode: out of memory!");
		free(mme);
		return 0;
	}

	if (!mm_forwards_apply_cfg(env->mm_fwds, env->cfg)) {
		log_err("mixed-mode: could not apply configuration settings.");
		free(mme);
		return 0;
	}

	env->modinfo[id] = (void*)mme;
	return 1;
}

/**
 * Deinitializes this instance of the mixed-mode module.
 *
 * \param env Global state of all module instances.
 * \param id  This instance's ID number.
 */
void mixed_mode_deinit(struct module_env* env, int id)
{
	if (!env)
		return;

	struct mixed_mode_env* mme = env->modinfo[id];

	mm_forwards_destroy(&env->mm_fwds);

	/* free the module environment structure */
	free(mme);
	env->modinfo[id] = NULL;
}

/**
 * This is the module's main() function. It gets called each time a query
 * receives an event which we may need to handle. We respond by updating the
 * state of the query.
 *
 * \param qstate   Structure containing the state of the query.
 * \param event    Event that has just been received.
 * \param id       This module's instance ID.
 * \param outbound State of a DNS query on an authoritative server.
 */
void mixed_mode_operate(struct module_qstate* qstate, enum module_ev event, int id,
			struct outbound_entry* outbound)
{
	struct mixed_mode_env* mme = (struct mixed_mode_env*)qstate->env->modinfo[id];
	struct mixed_mode_qstate* mmq = (struct mixed_mode_qstate*)qstate->minfo[id];

	verbose(VERB_QUERY, "mixed-mode[module %d] operate: extstate:%s event:%s",
		id, strextstate(qstate->ext_state[id]),
		strmodulevent(event));
	log_query_info(VERB_QUERY, "mixed-mode operate: query", &qstate->qinfo);

	switch(event) {
		case module_event_new:
		case module_event_pass:
			/* handle ONLY queries from clients. such queries have mesh_reply in 'reply_list' */
			if (mmq == NULL && qstate->mesh_info->reply_list != NULL) {
				log_addr(VERB_ALGO, "mixed-mode: query from client",
					 &qstate->mesh_info->reply_list->query_reply.addr,
					 qstate->mesh_info->reply_list->query_reply.addrlen);

				if (!mixed_mode_newq(qstate, id)) {
					log_err("mixed-mode: malloc failed");
					qstate->ext_state[id] = module_error;
					break;
				}
			}

			/* Nothing to do here for us, just pass it */
			verbose(VERB_ALGO, "mixed-mode: pass to next module");
			qstate->ext_state[id] = module_wait_module;
			break;

		case module_event_moddone:
			/* Query retured by succesing module, let's inspect it */
			verbose(VERB_ALGO, "mixed-mode: next module returned");
			if (mmq) {
				handle_event_moddone(qstate, mme, mmq, id);
			}
			else {
				verbose(VERB_ALGO, "mixed-mode: internal sub-query -> skipping");
				qstate->ext_state[id] = module_finished;
			}
			break;

		case module_event_reply:
		case module_event_noreply:
			/* reply, no reply, timeout, error */
			verbose(VERB_ALGO, "mixed-mode: reply/no-reply event");
			handle_response(qstate,mme, mmq, id, outbound, event);
			break;

		default:
			qstate->ext_state[id] = module_finished;
			break;
	}
}

/**
 * This function is called when a sub-query finishes to inform the parent query.
 *
 * \param qstate State of the sub-query.
 * \param id     This module's instance ID.
 * \param super  State of the super-query.
 */
void
mixed_mode_inform_super(struct module_qstate* qstate, int id,
		struct module_qstate* super)
{
	log_query_info(VERB_ALGO, "mixed-mode: inform_super, sub is", &qstate->qinfo);
	log_query_info(VERB_ALGO, "mixed-mode: super is", &super->qinfo);

	return;
}

/**
 * Clear module-specific data from query state.
 *
 * \param qstate Query state.
 * \param id     This module's instance ID.
 */
void
mixed_mode_clear(struct module_qstate* qstate, int id)
{
	qstate->minfo[id] = NULL;
}

/**
 * Returns the amount of global memory that this module uses, not including
 * per-query data.
 *
 * \param env Module environment.
 * \param id  This module's instance ID.
 */
size_t
mixed_mode_get_mem(struct module_env* env, int id)
{
	size_t size = 0;
	struct mixed_mode_env* mme = (struct mixed_mode_env*)env->modinfo[id];

	if (!mme)
		return size;

	/* size of the module environment structure itself */
	size += sizeof(*mme);

	return size;
}

/**
 * The mixed-mode function block.
 */
static struct module_func_block mixed_mode_block = {
	"mixed-mode",
	&mixed_mode_init, &mixed_mode_deinit, &mixed_mode_operate, &mixed_mode_inform_super,
	&mixed_mode_clear, &mixed_mode_get_mem
};

/**
 * Function for returning the above function block.
 */
struct module_func_block * mixed_mode_get_funcblock()
{
	return &mixed_mode_block;
}

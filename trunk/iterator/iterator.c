/*
 * iterator/iterator.c - iterative resolver DNS query response module
 *
 * Copyright (c) 2007, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file contains a module that performs recusive iterative DNS query
 * processing.
 */

#include "config.h"
#include "iterator/iterator.h"
#include "iterator/iter_utils.h"
#include "iterator/iter_hints.h"
#include "iterator/iter_delegpt.h"
#include "iterator/iter_resptype.h"
#include "iterator/iter_scrub.h"
#include "services/cache/dns.h"
#include "util/module.h"
#include "util/netevent.h"
#include "util/net_help.h"
#include "util/region-allocator.h"
#include "util/data/dname.h"
#include "util/data/msgencode.h"

/** iterator init */
static int 
iter_init(struct module_env* env, int id)
{
	struct iter_env* iter_env = (struct iter_env*)calloc(1,
		sizeof(struct iter_env));
	if(!iter_env) {
		log_err("malloc failure");
		return 0;
	}
	env->modinfo[id] = (void*)iter_env;
	if(!iter_apply_cfg(iter_env, env->cfg)) {
		log_err("iterator: could not apply configuration settings.");
		return 0;
	}
	return 1;
}

/** iterator deinit */
static void 
iter_deinit(struct module_env* env, int id)
{
	struct iter_env* iter_env;
	if(!env || !env->modinfo)
		return;
	iter_env = (struct iter_env*)env->modinfo[id];
	free(iter_env->target_fetch_policy);
	hints_delete(iter_env->hints);
	if(iter_env)
		free(iter_env);
}

/** new query for iterator */
static int
iter_new(struct module_qstate* qstate, int id)
{
	struct iter_qstate* iq = (struct iter_qstate*)region_alloc(
		qstate->region, sizeof(struct iter_qstate));
	qstate->minfo[id] = iq;
	if(!iq) 
		return 0;
	memset(iq, 0, sizeof(*iq));
	iq->state = INIT_REQUEST_STATE;
	iq->final_state = FINISHED_STATE;
	iq->prepend_list = NULL;
	iq->prepend_last = NULL;
	iq->dp = NULL;
	iq->num_target_queries = -1; /* default our targetQueries counter. */
	iq->num_current_queries = 0;
	iq->query_restart_count = 0;
	iq->referral_count = 0;
	iq->priming_stub = 0;
	iq->orig_qflags = qstate->query_flags;
	/* remove all weird bits from the query flags */
	qstate->query_flags &= (BIT_RD | BIT_CD);
	outbound_list_init(&iq->outlist);
	return 1;
}

/** new query for iterator in forward mode */
static int
fwd_new(struct module_qstate* qstate, int id)
{
	struct iter_qstate* iq = (struct iter_qstate*)region_alloc(
		qstate->region, sizeof(struct iter_qstate));
	struct module_env* env = qstate->env;
	struct iter_env* ie = (struct iter_env*)env->modinfo[id];
	struct outbound_entry* e;
	uint16_t flags = 0; /* opcode=query, no flags */
	int dnssec = 1; /* always get dnssec info */
	qstate->minfo[id] = iq;
	if(!iq) 
		return 0;
	memset(iq, 0, sizeof(*iq));
	outbound_list_init(&iq->outlist);
	e = (*env->send_query)(qstate->qinfo.qname, qstate->qinfo.qname_len,
		qstate->qinfo.qtype, qstate->qinfo.qclass, flags, dnssec, 
		&ie->fwd_addr, ie->fwd_addrlen, qstate);
	if(!e) 
		return 0;
	outbound_list_insert(&iq->outlist, e);
	qstate->ext_state[id] = module_wait_reply;
	return 1;
}

/** iterator handle reply from authoritative server */
static int
iter_handlereply(struct module_qstate* qstate, int id,
        struct outbound_entry* ATTR_UNUSED(outbound))
{
	struct module_env* env = qstate->env;
	uint16_t us = qstate->edns.udp_size;
	struct query_info reply_qinfo;
	struct reply_info* reply_msg;
	struct edns_data reply_edns;
	int r;
	if((r=reply_info_parse(qstate->reply->c->buffer, env->alloc, 
		&reply_qinfo, &reply_msg, qstate->scratch, 
		&reply_edns))!=0)
		return 0;

	qstate->edns.edns_version = EDNS_ADVERTISED_VERSION;
	qstate->edns.udp_size = EDNS_ADVERTISED_SIZE;
	qstate->edns.ext_rcode = 0;
	qstate->edns.bits &= EDNS_DO;
	if(!reply_info_answer_encode(&reply_qinfo, reply_msg, 0, 
		qstate->query_flags, qstate->buf, 0, 0, 
		qstate->scratch, us, &qstate->edns))
		return 0;
	dns_cache_store_msg(qstate->env, &reply_qinfo, qstate->query_hash, 
		reply_msg);
	qstate->ext_state[id] = module_finished;
	return 1;
}

/** perform forwarder functionality */
static void 
perform_forward(struct module_qstate* qstate, enum module_ev event, int id,
	struct outbound_entry* outbound)
{
	verbose(VERB_ALGO, "iterator: forwarding");
	if(event == module_event_new) {
		if(!fwd_new(qstate, id))
			qstate->ext_state[id] = module_error;
		return;
	}
	/* it must be a query reply */
	if(!outbound) {
		verbose(VERB_ALGO, "query reply was not serviced");
		qstate->ext_state[id] = module_error;
		return;
	}
	if(event == module_event_timeout || event == module_event_error) {
		qstate->ext_state[id] = module_error;
		return;
	}
	if(event == module_event_reply) {
		if(!iter_handlereply(qstate, id, outbound))
			qstate->ext_state[id] = module_error;
		return;
	}
	log_err("bad event for iterator[forwarding]");
	qstate->ext_state[id] = module_error;
}

/**
 * Transition to the next state. This can be used to advance a currently
 * processing event. It cannot be used to reactivate a forEvent.
 *
 * @param qstate: query state
 * @param iq: iterator query state
 * @param nextstate The state to transition to.
 * @return true. This is so this can be called as the return value for the
 *         actual process*State() methods. (Transitioning to the next state
 *         implies further processing).
 */
static int
next_state(struct module_qstate* qstate, struct iter_qstate* iq, 
	enum iter_state nextstate)
{
	/* If transitioning to a "response" state, make sure that there is a
	 * response */
	if(iter_state_is_responsestate(nextstate)) {
		if(qstate->reply == NULL || iq->response == NULL) {
			log_err("transitioning to response state sans "
				"response.");
		}
	}
	iq->state = nextstate;
	return 1;
}

/**
 * Transition an event to its final state. Final states always either return
 * a result up the module chain, or reactivate a dependent event. Which
 * final state to transtion to is set in the module state for the event when
 * it was created, and depends on the original purpose of the event.
 *
 * The response is stored in the qstate->buf buffer.
 *
 * @param qstate: query state
 * @param iq: iterator query state
 * @return false. This is so this method can be used as the return value for
 *         the processState methods. (Transitioning to the final state
 */
static int
final_state(struct module_qstate* qstate, struct iter_qstate* iq)
{
	return next_state(qstate, iq, iq->final_state);
}

/**
 * Return an error to the client
 */
static int
error_response(struct module_qstate* qstate, struct iter_qstate* iq, int rcode)
{
	log_info("err response %s", ldns_lookup_by_id(ldns_rcodes, rcode)?
		ldns_lookup_by_id(ldns_rcodes, rcode)->name:"??");
	qinfo_query_encode(qstate->buf, &qstate->qinfo);
	LDNS_RCODE_SET(ldns_buffer_begin(qstate->buf), rcode);
	LDNS_QR_SET(ldns_buffer_begin(qstate->buf));
	return final_state(qstate, iq);
}

#if 0
/** prepend the prepend list in the answer section of dns_msg */
static int
iter_prepend(struct iter_qstate* iq, struct dns_msg* msg, 
	struct region* region)
{
	struct packed_rrset_list* p;
	struct ub_packed_rrset_key** sets;
	size_t num = 0;
	for(p = iq->prepend_list; p; p = p->next)
		num++;
	if(num == 0)
		return 1;
	sets = region_alloc(region, (num+msg->rep->rrset_count) *
		sizeof(struct ub_packed_rrset_key*));
	if(!sets) 
		return 0;
	memcpy(sets+num, msg->rep->rrsets, msg->rep->rrset_count *
		sizeof(struct ub_packed_rrset_key*));
	num = 0;
	for(p = iq->prepend_list; p; p = p->next) {
		sets[num] = (struct ub_packed_rrset_key*)region_alloc(region,
			sizeof(struct ub_packed_rrset_key));
		if(!sets[num])
			return 0;
		sets[num]->rk = *p->rrset.k;
		sets[num]->entry.data = p->rrset.d;
		num++;
	}
	msg->rep->rrsets = sets;
	return 1;
}

/**
 * Encode response message for iterator responses. Into response buffer.
 * On error an error message is encoded.
 * @param qstate: query state. With qinfo information.
 * @param iq: iterator query state. With qinfo original and prepend list.
 * @param msg: answer message.
 */
static void 
iter_encode_respmsg(struct module_qstate* qstate, struct iter_qstate* iq, 
	struct dns_msg* msg)
{
	struct query_info qinf = qstate->qinfo;
	uint32_t now = time(NULL);
	struct edns_data edns;
	if(iq->orig_qname) {
		qinf.qname = iq->orig_qname;
		qinf.qname_len = iq->orig_qnamelen;
	}
	if(iq->prepend_list) {
		if(!iter_prepend(iq, msg, qstate->region)) {
			error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
			return;
		}
	}

	edns.edns_present = qstate->edns.edns_present;
	edns.edns_version = EDNS_ADVERTISED_VERSION;
	edns.udp_size = EDNS_ADVERTISED_SIZE;
	edns.ext_rcode = 0;
	edns.bits = qstate->edns.bits & EDNS_DO;
	if(!reply_info_answer_encode(&qinf, msg->rep, 0, iq->orig_qflags, 
		qstate->buf, now, 1, qstate->scratch, qstate->edns.udp_size, 
		&edns)) {
		/* encode servfail */
		error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
		return;
	}
}
#endif

/**
 * Add rrset to prepend list
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param rrset: rrset to add.
 * @return false on failure (malloc).
 */
static int
iter_add_prepend(struct module_qstate* qstate, struct iter_qstate* iq,
	struct ub_packed_rrset_key* rrset)
{
	struct iter_prep_list* p = (struct iter_prep_list*)region_alloc(
		qstate->region, sizeof(struct iter_prep_list));
	if(!p)
		return 0;
	p->rrset = rrset;
	p->next = NULL;
	/* add at end */
	if(iq->prepend_last)
		iq->prepend_last->next = p;
	else	iq->prepend_list = p;
	iq->prepend_last = p;
	return 1;
}

/**
 * Given a CNAME response (defined as a response containing a CNAME or DNAME
 * that does not answer the request), process the response, modifying the
 * state as necessary. This follows the CNAME/DNAME chain and returns the
 * final query name.
 *
 * sets the new query name, after following the CNAME/DNAME chain.
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param msg: the response.
 * @param mname: returned target new query name.
 * @param mname_len: length of mname.
 * @return false on (malloc) error.
 */
static int
handle_cname_response(struct module_qstate* qstate, struct iter_qstate* iq,
        struct dns_msg* msg, uint8_t** mname, size_t* mname_len)
{
	size_t i;
	/* Start with the (current) qname. */
	*mname = qstate->qinfo.qname;
	*mname_len = qstate->qinfo.qname_len;

	/* Iterate over the ANSWER rrsets in order, looking for CNAMEs and 
	 * DNAMES. */
	for(i=0; i<msg->rep->an_numrrsets; i++) {
		struct ub_packed_rrset_key* r = msg->rep->rrsets[i];
		/* If there is a (relevant) DNAME, add it to the list.
		 * We always expect there to be CNAME that was generated 
		 * by this DNAME following, so we don't process the DNAME 
		 * directly.  */
		if(ntohs(r->rk.type) == LDNS_RR_TYPE_DNAME &&
			dname_strict_subdomain_c(*mname, r->rk.dname)) {
			if(!iter_add_prepend(qstate, iq, r))
				return 0;
			continue;
		}

		if(ntohs(r->rk.type) == LDNS_RR_TYPE_CNAME &&
			query_dname_compare(*mname, r->rk.dname) == 0) {
			/* Add this relevant CNAME rrset to the prepend list.*/
			if(!iter_add_prepend(qstate, iq, r))
				return 0;
			get_cname_target(r, mname, mname_len);
		}

		/* Other rrsets in the section are ignored. */
	}
	return 1;
}

/**
 * Generate a subrequest.
 * Generate a local request event. Local events are tied to this module, and
 * have a correponding (first tier) event that is waiting for this event to
 * resolve to continue.
 *
 * @param qname The query name for this request.
 * @param qnamelen length of qname
 * @param qtype The query type for this request.
 * @param qclass The query class for this request.
 * @param qstate The event that is generating this event.
 * @param id: module id.
 * @param initial_state The initial response state (normally this
 *          is QUERY_RESP_STATE, unless it is known that the request won't
 *          need iterative processing
 * @param final_state The final state for the response to this
 *          request.
 * @return generated subquerystate, or NULL on error (malloc).
 */
static struct module_qstate* 
generate_sub_request(uint8_t* qname, size_t qnamelen, uint16_t qtype, 
	uint16_t qclass, struct module_qstate* qstate, int id,
	enum iter_state initial_state, enum iter_state final_state)
{
	struct module_qstate* subq = (struct module_qstate*)malloc(
		sizeof(struct module_qstate));
	struct iter_qstate* subiq;
	if(!subq)
		return NULL;
	memset(subq, 0, sizeof(*subq));
	subq->qinfo.qname = memdup(qname, qnamelen);
	if(!subq->qinfo.qname) {
		free(subq);
		return NULL;
	}
	subq->qinfo.qname_len = qnamelen;
	subq->qinfo.qtype = qtype;
	subq->qinfo.qclass = qclass;
	subq->query_hash = query_info_hash(&subq->qinfo);
	subq->query_flags = 0; /* OPCODE QUERY, no flags */
	subq->edns.udp_size = 65535;
	subq->buf = qstate->buf;
	subq->scratch = qstate->scratch;
	subq->region = region_create(malloc, free);
	if(!subq->region) {
		free(subq->qinfo.qname);
		free(subq);
		return NULL;
	}
	subq->curmod = id;
	subq->ext_state[id] = module_state_initial;
	subq->minfo[id] = region_alloc(subq->region, 
		sizeof(struct iter_qstate));
	if(!subq->minfo[id]) {
		region_destroy(subq->region);
		free(subq->qinfo.qname);
		free(subq);
		return NULL;
	}
	subq->env = qstate->env;
	subq->work_info = qstate->work_info;
	subq->parent = qstate;
	subq->subquery_next = qstate->subquery_first;
	qstate->subquery_first = subq;

	subiq = (struct iter_qstate*)subq->minfo[id];
	memset(subiq, 0, sizeof(*subiq));
	subiq->num_target_queries = -1; /* default our targetQueries counter. */
	outbound_list_init(&subiq->outlist);
	subiq->state = initial_state;
	subiq->final_state = final_state;

	/* RD should be set only when sending the query back through the INIT
	 * state. */
	if(initial_state == INIT_REQUEST_STATE)
		subq->query_flags |= BIT_RD;
	/* We set the CD flag so we can send this through the "head" of 
	 * the resolution chain, which might have a validator. We are 
	 * uninterested in validating things not on the direct resolution 
	 * path.  */
	subq->query_flags |= BIT_CD;
	subiq->orig_qflags = subq->query_flags;
	
	return subq;
}

/**
 * Generate and send a root priming request.
 * @param qstate: the qtstate that triggered the need to prime.
 * @param ie: iterator global state.
 * @param id: module id.
 * @param qclass: the class to prime.
 */
static int
prime_root(struct module_qstate* qstate, struct iter_env* ie, int id, 
	uint16_t qclass)
{
	struct delegpt* dp;
	struct module_qstate* subq;
	struct iter_qstate* subiq;
	verbose(VERB_ALGO, "priming . NS %s", 
		ldns_lookup_by_id(ldns_rr_classes, (int)qclass)?
		ldns_lookup_by_id(ldns_rr_classes, (int)qclass)->name:"??");
	dp = hints_lookup_root(ie->hints, qclass);
	if(!dp) {
		verbose(VERB_ALGO, "Cannot prime due to lack of hints");
		return 0;
	}
	/* Priming requests start at the QUERYTARGETS state, skipping 
	 * the normal INIT state logic (which would cause an infloop). */
	subq = generate_sub_request((uint8_t*)"\000", 1, LDNS_RR_TYPE_NS, 
		qclass, qstate, id, QUERYTARGETS_STATE, PRIME_RESP_STATE);
	if(!subq) {
		log_err("out of memory priming root");
		return 0;
	}
	subiq = (struct iter_qstate*)subq->minfo[id];

	/* Set the initial delegation point to the hint. */
	subiq->dp = dp;
	/* suppress any target queries. */
	subiq->num_target_queries = 0; 
	
	/* this module stops, our submodule starts, and does the query. */
	qstate->ext_state[id] = module_wait_subquery;
	return 1;
}

/**
 * Generate and process a stub priming request. This method tests for the
 * need to prime a stub zone, so it is safe to call for every request.
 *
 * @param qstate: the qtstate that triggered the need to prime.
 * @param iq: iterator query state.
 * @param ie: iterator global state.
 * @param id: module id.
 * @param qname: request name.
 * @param qclass: the class to prime.
 * @return true if a priming subrequest was made, false if not. The will only
 *         issue a priming request if it detects an unprimed stub.
 */
static int
prime_stub(struct module_qstate* qstate, struct iter_qstate* iq, 
	struct iter_env* ie, int id, uint8_t* qname, uint16_t qclass)
{
	/* Lookup the stub hint. This will return null if the stub doesn't 
	 * need to be re-primed. */
	struct delegpt* stub_dp = hints_lookup_stub(ie->hints, qname, qclass, 
		iq->dp);
	struct module_qstate* subq;
	struct iter_qstate* subiq;
	/* The stub (if there is one) does not need priming. */
	if(!stub_dp)
		return 0;

	/* Otherwise, we need to (re)prime the stub. */
	log_nametypeclass("priming stub", stub_dp->name, LDNS_RR_TYPE_NS, 
		qclass);

	/* Stub priming events start at the QUERYTARGETS state to avoid the
	 * redundant INIT state processing. */
	subq = generate_sub_request(stub_dp->name, stub_dp->namelen, 
		LDNS_RR_TYPE_NS, qclass, qstate, id, 
		QUERYTARGETS_STATE, PRIME_RESP_STATE);
	if(!subq) {
		log_err("out of memory priming stub");
		qstate->ext_state[id] = module_error;
		return 1; /* return 1 to make module stop, with error */
	}
	subiq = (struct iter_qstate*)subq->minfo[id];

	/* Set the initial delegation point to the hint. */
	subiq->dp = stub_dp;
	/* suppress any target queries -- although there wouldn't be anyway, 
	 * since stub hints never have missing targets.*/
	subiq->num_target_queries = 0; 
	subiq->priming_stub = 1;
	
	/* this module stops, our submodule starts, and does the query. */
	qstate->ext_state[id] = module_wait_subquery;
	return 1;
}

/** 
 * Process the initial part of the request handling. This state roughly
 * corresponds to resolver algorithms steps 1 (find answer in cache) and 2
 * (find the best servers to ask).
 *
 * Note that all requests start here, and query restarts revisit this state.
 *
 * This state either generates: 1) a response, from cache or error, 2) a
 * priming event, or 3) forwards the request to the next state (init2,
 * generally).
 *
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param ie: iterator shared global environment.
 * @param id: module id.
 * @return true if the event needs more request processing immediately,
 *         false if not.
 */
static int
processInitRequest(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	int d;
	uint8_t* delname;
	size_t delnamelen;
	struct dns_msg* msg;

	log_nametypeclass("resolving", qstate->qinfo.qname, 
		qstate->qinfo.qtype, qstate->qinfo.qclass);
	/* check effort */

	/* We enforce a maximum number of query restarts. This is primarily a
	 * cheap way to prevent CNAME loops. */
	if(iq->query_restart_count > MAX_RESTART_COUNT) {
		verbose(VERB_DETAIL, "request has exceeded the maximum number"
			" of query restarts with %d", iq->query_restart_count);
		return error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
	}

	/* We enforce a maximum recursion/dependency depth -- in general, 
	 * this is unnecessary for dependency loops (although it will 
	 * catch those), but it provides a sensible limit to the amount 
	 * of work required to answer a given query. */
	d = module_subreq_depth(qstate);
	verbose(VERB_ALGO, "request has dependency depth of %d", d);
	if(d > ie->max_dependency_depth) {
		verbose(VERB_DETAIL, "request has exceeded the maximum "
			"dependency depth with depth of %d", d);
		return error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
	}

	/* Resolver Algorithm Step 1 -- Look for the answer in local data. */

	/* This either results in a query restart (CNAME cache response), a
	 * terminating response (ANSWER), or a cache miss (null). */
	
	msg = dns_cache_lookup(qstate->env, qstate->qinfo.qname, 
		qstate->qinfo.qname_len, qstate->qinfo.qtype, 
		qstate->qinfo.qclass, qstate->region, qstate->scratch);
	if(msg) {
		/* handle positive cache response */
		enum response_type type = response_type_from_cache(msg, 
			&qstate->qinfo);

		if(type == RESPONSE_TYPE_CNAME) {
			uint8_t* sname = 0;
			size_t slen = 0;
			verbose(VERB_ALGO, "returning CNAME response from "
				"cache");
			if(!iq->orig_qname) {
				iq->orig_qname = qstate->qinfo.qname;
				iq->orig_qnamelen = qstate->qinfo.qname_len;
			}
			if(!handle_cname_response(qstate, iq, msg, 
				&sname, &slen))
				return error_response(qstate, iq,
					LDNS_RCODE_SERVFAIL);
			qstate->qinfo.qname = sname;
			qstate->qinfo.qname_len = slen;
			/* This *is* a query restart, even if it is a cheap 
			 * one. */
			iq->query_restart_count++;
			return next_state(qstate, iq, INIT_REQUEST_STATE);
		}

		/* it is an answer, response, to final state */
		verbose(VERB_ALGO, "returning answer from cache.");
		iq->response = msg;
		return final_state(qstate, iq);
	}
	
	/* TODO attempt to forward the request */
	/* if (forwardRequest(event, state, req))
	   {
		// the request has been forwarded.
		// forwarded requests need to be immediately sent to the 
		// next state, QUERYTARGETS.
		return nextState(event, req, state, 
			IterEventState.QUERYTARGETS_STATE);
		}
	*/

	/* TODO attempt to find a covering DNAME in the cache */
	/* resp = mDNSCache.findDNAME(req.getQName(), req.getQType(), req
	        .getQClass());
	    if (resp != null)
	{
log.trace("returning synthesized CNAME response from cache: " + resp);
Name cname = handleCNAMEResponse(state, req, resp);
// At this point, we just initiate the query restart.
// This might not be a query restart situation (e.g., qtype == CNAME),
// but
// the answer returned from findDNAME() is likely to be one that we
// don't want to return.
// Thus we allow the cache and other resolution mojo kick in regardless.
req.setQName(cname);
state.queryRestartCount++;
return nextState(event, req, state, IterEventState.INIT_REQUEST_STATE);
}
	*/

	/* Resolver Algorithm Step 2 -- find the "best" servers. */

	/* first, adjust for DS queries. To avoid the grandparent problem, 
	 * we just look for the closest set of server to the parent of qname.
	 */
	delname = qstate->qinfo.qname;
	delnamelen = qstate->qinfo.qname_len;
	if(qstate->qinfo.qtype == LDNS_RR_TYPE_DS && delname[0] != 0) {
		/* do not adjust root label, remove first label from delname */
		size_t lablen = delname[0] + 1;
		delname += lablen;
		delnamelen -= lablen;
	}
	
	/* Lookup the delegation in the cache. If null, then the cache needs 
	 * to be primed for the qclass. */
	iq->dp = dns_cache_find_delegation(qstate->env, delname, delnamelen,
		qstate->qinfo.qtype, qstate->qinfo.qclass, qstate->region, 
		&iq->deleg_msg);

	/* If the cache has returned nothing, then we have a root priming
	 * situation. */
	if(iq->dp == NULL) {
		/* Note that the result of this will set a new
		 * DelegationPoint based on the result of priming. */
		if(!prime_root(qstate, ie, id, qstate->qinfo.qclass))
			return error_response(qstate, iq, LDNS_RCODE_REFUSED);

		/* priming creates an sends a subordinate query, with 
		 * this query as the parent. So further processing for 
		 * this event will stop until reactivated by the results 
		 * of priming. */
		return 0;
	}

	/* Reset the RD flag. If this is a query restart, then the RD 
	 * will have been turned off. */
	if(iq->orig_qflags & BIT_RD)
		qstate->query_flags |= BIT_RD;
	else	qstate->query_flags &= ~BIT_RD;

	/* Otherwise, set the current delegation point and move on to the 
	 * next state. */
	return next_state(qstate, iq, INIT_REQUEST_2_STATE);
}

/** 
 * Process the second part of the initial request handling. This state
 * basically exists so that queries that generate root priming events have
 * the same init processing as ones that do not. Request events that reach
 * this state must have a valid currentDelegationPoint set.
 *
 * This part is primarly handling stub zone priming. Events that reach this
 * state must have a current delegation point.
 *
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param ie: iterator shared global environment.
 * @param id: module id.
 * @return true if the event needs more request processing immediately,
 *         false if not.
 */
static int
processInitRequest2(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	log_nametypeclass("resolving (init part 2): ", qstate->qinfo.qname,
		qstate->qinfo.qtype, qstate->qinfo.qclass);

	/* Check to see if we need to prime a stub zone. */
	if(prime_stub(qstate, iq, ie, id, qstate->qinfo.qname, 
		qstate->qinfo.qclass)) {
		/* A priming sub request was made */
		return 0;
	}

	/* most events just get forwarded to the next state. */
	return next_state(qstate, iq, INIT_REQUEST_3_STATE);
}

/** 
 * Process the third part of the initial request handling. This state exists
 * as a separate state so that queries that generate stub priming events
 * will get the tail end of the init process but not repeat the stub priming
 * check.
 *
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @return true, advancing the event to the QUERYTARGETS_STATE.
 */
static int
processInitRequest3(struct module_qstate* qstate, struct iter_qstate* iq)
{
	log_nametypeclass("resolving (init part 3): ", qstate->qinfo.qname,
		qstate->qinfo.qtype, qstate->qinfo.qclass);
	/* If the RD flag wasn't set, then we just finish with the 
	 * cached referral as the response. */
	if(!(qstate->query_flags & BIT_RD)) {
		iq->response = iq->deleg_msg;
		return final_state(qstate, iq);
	}

	/* After this point, unset the RD flag -- this query is going to 
	 * be sent to an auth. server. */
	qstate->query_flags &= ~BIT_RD;

	/* Jump to the next state. */
	return next_state(qstate, iq, QUERYTARGETS_STATE);
}

/**
 * Given a basic query, generate a "target" query. These are subordinate
 * queries for missing delegation point target addresses.
 *
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param id: module id.
 * @param name: target qname.
 * @param namelen: target qname length.
 * @param qtype: target qtype (either A or AAAA).
 * @param qclass: target qclass.
 * @return true on success, false on failure.
 */
static int
generate_target_query(struct module_qstate* qstate, struct iter_qstate* iq,
        int id, uint8_t* name, size_t namelen, uint16_t qtype, uint16_t qclass)
{
	struct module_qstate* subq = generate_sub_request(name, namelen, qtype,
		qclass, qstate, id, INIT_REQUEST_STATE, TARGET_RESP_STATE);
	struct iter_qstate* subiq;
	if(!subq)
		return 0;
	subiq = (struct iter_qstate*)subq->minfo[id];
	subiq->dp = delegpt_copy(iq->dp, subq->region);
	if(!subiq->dp) {
		subq->ext_state[id] = module_error;
		return 0;
	}
	return 1;
}

/**
 * Given an event at a certain state, generate zero or more target queries
 * for it's current delegation point.
 *
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param ie: iterator shared global environment.
 * @param id: module id.
 * @param maxtargets: The maximum number of targets to query for.
 *	if it is negative, there is no maximum number of targets.
 * @param num: returns the number of queries generated and processed, 
 *	which may be zero if there were no missing targets.
 * @return false on error.
 */
static int
query_for_targets(struct module_qstate* qstate, struct iter_qstate* iq,
        struct iter_env* ie, int id, int maxtargets, int* num)
{
	int query_count = 0;
	int target_count = 0;
	struct delegpt_ns* ns = iq->dp->nslist;

	/* Generate target requests. Basically, any missing targets 
	 * are queried for here, regardless if it is necessary to do 
	 * so to continue processing. */

	/* loop over missing targets */
	for(ns = iq->dp->nslist; ns; ns = ns->next) {
		if(ns->resolved)
			continue;

		/* Sanity check: if the target name is at or *below* the 
		 * delegation point itself, then this will be (potentially) 
		 * unresolvable. This is the one case where glue *must* 
		 * have been present.
		 * FIXME: at this point, this *may* be resolvable, so 
		 * perhaps we should issue the query anyway and let it fail.*/
		if(dname_subdomain_c(ns->name, iq->dp->name)) {
			log_nametypeclass("skipping target name because "
				"it should have been glue", ns->name,
				LDNS_RR_TYPE_NS, qstate->qinfo.qclass);
			continue;
		}

		if(ie->supports_ipv6) {
			/* Send the AAAA request. */
			if(!generate_target_query(qstate, iq, id, 
				ns->name, ns->namelen,
				LDNS_RR_TYPE_AAAA, qstate->qinfo.qclass))
				return 0;
			query_count++;
		}
		/* Send the A request. */
		if(!generate_target_query(qstate, iq, id, 
			ns->name, ns->namelen, 
			LDNS_RR_TYPE_A, qstate->qinfo.qclass))
			return 0;
		query_count++;

		/* mark this target as in progress. */
		ns->resolved = 1;

		/* if maxtargets is negative, there is no maximum, 
		 * otherwise only query for ntarget names. */
		if(maxtargets > 0 && ++target_count > maxtargets)
			break;
	}
	*num = query_count;

	return 1;
}

/** 
 * This is the request event state where the request will be sent to one of
 * its current query targets. This state also handles issuing target lookup
 * queries for missing target IP addresses. Queries typically iterate on
 * this state, both when they are just trying different targets for a given
 * delegation point, and when they change delegation points. This state
 * roughly corresponds to RFC 1034 algorithm steps 3 and 4.
 *
 * @param qstate: query state.
 * @param iq: iterator query state.
 * @param ie: iterator shared global environment.
 * @param id: module id.
 * @return true if the event requires more request processing immediately,
 *         false if not. This state only returns true when it is generating
 *         a SERVFAIL response because the query has hit a dead end.
 */
static int
processQueryTargets(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	int tf_policy, d;
	struct delegpt_addr* target;
	struct outbound_entry* outq;

	/* NOTE: a request will encounter this state for each target it 
	 * needs to send a query to. That is, at least one per referral, 
	 * more if some targets timeout or return throwaway answers. */

	log_nametypeclass("processQueryTargets:", qstate->qinfo.qname,
		qstate->qinfo.qtype, qstate->qinfo.qclass);
	verbose(VERB_ALGO, "processQueryTargets: targetqueries %d, "
		"currentqueries %d", iq->num_target_queries, 
		iq->num_current_queries);

	/* Make sure that we haven't run away */
	/* FIXME: is this check even necessary? */
	if(iq->referral_count > MAX_REFERRAL_COUNT) {
		verbose(VERB_ALGO, "request has exceeded the maximum "
			"number of referrrals with %d", iq->referral_count);
		return error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
	}

	tf_policy = 0;
	d = module_subreq_depth(qstate);
	if(d <= ie->max_dependency_depth) {
		tf_policy = ie->target_fetch_policy[d];
	}

	/* if there is a policy to fetch missing targets 
	 * opportunistically, do it. we rely on the fact that once a 
	 * query (or queries) for a missing name have been issued, 
	 * they will not be show up again. */
	if(tf_policy != 0) {
		if(!query_for_targets(qstate, iq, ie, id, tf_policy, 
			&iq->num_target_queries)) {
			return error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
		}
	} else {
		iq->num_target_queries = 0;
	}

	/* Add the current set of unused targets to our queue. */
	delegpt_add_unused_targets(iq->dp);

	/* Select the next usable target, filtering out unsuitable targets. */
	target = iter_server_selection(ie, qstate->env, iq->dp, 
		iq->dp->name, iq->dp->namelen);

	/* If no usable target was selected... */
	if(!target) {
		/* Here we distinguish between three states: generate a new 
		 * target query, just wait, or quit (with a SERVFAIL).
		 * We have the following information: number of active 
		 * target queries, number of active current queries, 
		 * the presence of missing targets at this delegation 
		 * point, and the given query target policy. */
		
		/* Check for the wait condition. If this is true, then 
		 * an action must be taken. */
		if(iq->num_target_queries==0 && iq->num_current_queries==0) {
			/* If there is nothing to wait for, then we need 
			 * to distinguish between generating (a) new target 
			 * query, or failing. */
			if(delegpt_count_missing_targets(iq->dp) > 0) {
				verbose(VERB_ALGO, "querying for next "
					"missing target");
				if(!query_for_targets(qstate, iq, ie, id, 
						1, &iq->num_target_queries)) {
					return error_response(qstate, iq, 
						LDNS_RCODE_SERVFAIL);
				}
			}
			/* Since a target query might have been made, we 
			 * need to check again. */
			if(iq->num_target_queries == 0) {
				verbose(VERB_ALGO, "out of query targets -- "
					"returning SERVFAIL");
				/* fail -- no more targets, no more hope 
				 * of targets, no hope of a response. */
				return error_response(qstate, iq, 
					LDNS_RCODE_SERVFAIL);
			}
		}

		/* otherwise, we have no current targets, so submerge 
		 * until one of the target or direct queries return. */
		if(iq->num_target_queries>0 && iq->num_current_queries>0)
			verbose(VERB_ALGO, "no current targets -- waiting "
				"for %d targets to resolve or %d outstanding"
				" queries to respond", iq->num_target_queries, 
				iq->num_current_queries);
		else if(iq->num_target_queries>0)
			verbose(VERB_ALGO, "no current targets -- waiting "
				"for %d targets to resolve.",
				iq->num_target_queries);
		else 	verbose(VERB_ALGO, "no current targets -- waiting "
				"for %d outstanding queries to respond.",
				iq->num_current_queries);
		return 0;
	}

	/* We have a valid target. */
	log_nametypeclass("sending query:", qstate->qinfo.qname, 
		qstate->qinfo.qtype, qstate->qinfo.qclass);
	log_addr("sending to target:", &target->addr, target->addrlen);
	outq = (*qstate->env->send_query)(
		qstate->qinfo.qname, qstate->qinfo.qname_len, 
		qstate->qinfo.qtype, qstate->qinfo.qclass, 
		qstate->query_flags, 1, &target->addr, target->addrlen, 
		qstate);
	if(!outq) {
		log_err("out of memory sending query to auth server");
		return error_response(qstate, iq, LDNS_RCODE_SERVFAIL);
	}
	outbound_list_insert(&iq->outlist, outq);
	iq->num_current_queries++;
	qstate->ext_state[id] = module_wait_reply;

	return 0;
}

#if 0
/** TODO */
static int
processQueryResponse(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	return 0;
}

/** TODO */
static int
processPrimeResponse(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	return 0;
}

/** TODO */
static int
processTargetResponse(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	return 0;
}

/** TODO */
static int
processFinished(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	return 0;
}
#endif

/**
 * Handle iterator state.
 * Handle events. This is the real processing loop for events, responsible
 * for moving events through the various states. If a processing method
 * returns true, then it will be advanced to the next state. If false, then
 * processing will stop.
 *
 * @param qstate: query state.
 * @param ie: iterator shared global environment.
 * @param iq: iterator query state.
 * @param id: module id.
 */
static void
iter_handle(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	int cont = 1;
	while(cont) {
		verbose(VERB_ALGO, "iter_handle processing q with state %s",
			iter_state_to_string(iq->state));
		switch(iq->state) {
			case INIT_REQUEST_STATE:
				cont = processInitRequest(qstate, iq, ie, id);
				break;
			case INIT_REQUEST_2_STATE:
				cont = processInitRequest2(qstate, iq, ie, id);
				break;
			case INIT_REQUEST_3_STATE:
				cont = processInitRequest3(qstate, iq);
				break;
			case QUERYTARGETS_STATE:
				cont = processQueryTargets(qstate, iq, ie, id);
				break;
#if 0
			case QUERY_RESP_STATE:
				cont = processQueryResponse(qstate, iq, ie, id);
				break;
			case PRIME_RESP_STATE:
				cont = processPrimeResponse(qstate, iq, ie, id);
				break;
			case TARGET_RESP_STATE:
				cont = processTargetResponse(qstate, iq, ie, id);
				break;
			case FINISHED_STATE:
				cont = processFinished(qstate, iq, ie, id);
				break;
#endif
			default:
				log_warn("iterator: invalid state: %d",
					iq->state);
				cont = 0;
				break;
		}
	}
}

/** 
 * This is the primary entry point for processing request events. Note that
 * this method should only be used by external modules.
 * @param qstate: query state.
 * @param ie: iterator shared global environment.
 * @param iq: iterator query state.
 * @param id: module id.
 */
static void
process_request(struct module_qstate* qstate, struct iter_qstate* iq,
	struct iter_env* ie, int id)
{
	/* external requests start in the INIT state, and finish using the
	 * FINISHED state. */
	iq->state = INIT_REQUEST_STATE;
	iq->final_state = FINISHED_STATE;
	verbose(VERB_ALGO, "process_request: new external request event");
	iter_handle(qstate, iq, ie, id);
}

/** process authoritative server reply */
static void
process_response(struct module_qstate* qstate, struct iter_qstate* iq, 
	struct iter_env* ie, int id, struct outbound_entry* outbound,
	enum module_ev event)
{
	struct msg_parse* prs;
	struct edns_data edns;
	ldns_buffer* pkt;

	verbose(VERB_ALGO, "process_response: new external response event");
	iq->response = NULL;
	iq->state = QUERY_RESP_STATE;
	if(event == module_event_timeout || event == module_event_error) {
		goto handle_it;
	}
	if(event != module_event_reply || !qstate->reply) {
		log_err("Bad event combined with response");
		outbound_list_remove(&iq->outlist, outbound);
		qstate->ext_state[id] = module_error;
		return;
	}

	/* parse message */
	prs = (struct msg_parse*)region_alloc(qstate->scratch, 
		sizeof(struct msg_parse));
	if(!prs) {
		log_err("out of memory on incoming message");
		/* like packet got dropped */
		goto handle_it;
	}
	memset(prs, 0, sizeof(*prs));
	memset(&edns, 0, sizeof(edns));
	pkt = qstate->reply->c->buffer;
	ldns_buffer_set_position(pkt, 0);
	if(!parse_packet(pkt, prs, qstate->scratch))
		goto handle_it;
	/* edns is not examined, but removed from message to help cache */
	if(!parse_extract_edns(prs, &edns))
		goto handle_it;

	/* normalize and sanitize: easy to delete items from linked lists */
	if(!scrub_message(pkt, prs, &qstate->qinfo, iq->dp->name, 
		qstate->scratch))
		goto handle_it;

	/* allocate response dns_msg in region */
	iq->response = dns_alloc_msg(pkt, prs, qstate->region);
	if(!iq->response)
		goto handle_it;

handle_it:
	outbound_list_remove(&iq->outlist, outbound);
	iter_handle(qstate, iq, ie, id);
}

/** iterator operate on a query */
static void 
iter_operate(struct module_qstate* qstate, enum module_ev event, int id,
	struct outbound_entry* outbound)
{
	struct iter_env* ie = (struct iter_env*)qstate->env->modinfo[id];
	struct iter_qstate* iq = (struct iter_qstate*)qstate->minfo[id];
	verbose(VERB_ALGO, "iterator[module %d] operate: extstate:%s event:%s", 
		id, strextstate(qstate->ext_state[id]), strmodulevent(event));
	if(ie->fwd_addrlen != 0) {
		perform_forward(qstate, event, id, outbound);
		return;
	}
	/* perform iterator state machine */
	if(event == module_event_new && iq == NULL) {
		log_info("iter state machine");
		if(!iter_new(qstate, id)) {
			qstate->ext_state[id] = module_error;
			return;
		}
		iq = (struct iter_qstate*)qstate->minfo[id];
		process_request(qstate, iq, ie, id);
		return;
	}
	if(event == module_event_pass) {
		iter_handle(qstate, iq, ie, id);
		return;
	}
	if(outbound) {
		process_response(qstate, iq, ie, id, outbound, event);
		return;
	}
	/* TODO: uhh */

	log_err("bad event for iterator");
	qstate->ext_state[id] = module_error;
}

/** iterator cleanup query state */
static void 
iter_clear(struct module_qstate* qstate, int id)
{
	struct iter_qstate* iq;
	if(!qstate)
		return;
	iq = (struct iter_qstate*)qstate->minfo[id];
	if(iq->orig_qname) {
		/* so the correct qname gets free'd */
		qstate->qinfo.qname = iq->orig_qname;
		qstate->qinfo.qname_len = iq->orig_qnamelen;
	}
	outbound_list_clear(&iq->outlist);
	qstate->minfo[id] = NULL;
}

/**
 * The iterator function block 
 */
static struct module_func_block iter_block = {
	"iterator",
	&iter_init, &iter_deinit, &iter_operate, &iter_clear
};

struct module_func_block* 
iter_get_funcblock()
{
	return &iter_block;
}

const char* 
iter_state_to_string(enum iter_state state)
{
	switch (state)
	{
	case INIT_REQUEST_STATE :
		return "INIT REQUEST STATE";
	case INIT_REQUEST_2_STATE :
		return "INIT REQUEST STATE (stage 2)";
	case INIT_REQUEST_3_STATE:
		return "INIT REQUEST STATE (stage 3)";
	case QUERYTARGETS_STATE :
		return "QUERY TARGETS STATE";
	case PRIME_RESP_STATE :
		return "PRIME RESPONSE STATE";
	case QUERY_RESP_STATE :
		return "QUERY RESPONSE STATE";
	case TARGET_RESP_STATE :
		return "TARGET RESPONSE STATE";
	case FINISHED_STATE :
		return "FINISHED RESPONSE STATE";
	default :
		return "UNKNOWN ITER STATE";
	}
}

int 
iter_state_is_responsestate(enum iter_state s)
{
	switch(s) {
		case INIT_REQUEST_STATE :
		case INIT_REQUEST_2_STATE :
		case INIT_REQUEST_3_STATE :
		case QUERYTARGETS_STATE :
			return 0;
		default:
			break;
	}
	return 1;
}

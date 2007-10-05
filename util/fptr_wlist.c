/*
 * util/fptr_wlist.c - function pointer whitelists.
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
 * This file contains functions that check function pointers.
 * The functions contain a whitelist of known good callback values.
 * Any other values lead to an error. 
 *
 * Due to the listing nature, this file violates all the modularization
 * boundaries in the program.
 */
#include "config.h"
#include "util/fptr_wlist.h"
#include "util/mini_event.h"
#include "daemon/worker.h"
#include "services/outside_network.h"
#include "services/mesh.h"
#include "services/cache/infra.h"
#include "iterator/iter_donotq.h"
#include "iterator/iter_fwd.h"
#include "iterator/iter_hints.h"
#include "validator/val_anchor.h"
#include "validator/val_nsec3.h"
#include "validator/val_sigcrypt.h"
#include "validator/val_kentry.h"
#include "util/data/msgreply.h"
#include "util/data/packed_rrset.h"
#include "util/storage/slabhash.h"
#include "util/locks.h"
#include "testcode/checklocks.h"

int 
fptr_whitelist_comm_point(comm_point_callback_t *fptr)
{
	if(fptr == &worker_handle_request) return 1;
	else if(fptr == &outnet_udp_cb) return 1;
	else if(fptr == &outnet_tcp_cb) return 1;
	else if(fptr == &worker_handle_control_cmd) return 1;
	return 0;
}

int 
fptr_whitelist_comm_timer(void (*fptr)(void*))
{
	if(fptr == &pending_udp_timer_cb) return 1;
	else if(fptr == &outnet_tcptimer) return 1;
	return 0;
}

int 
fptr_whitelist_comm_signal(void (*fptr)(int, void*))
{
	if(fptr == &worker_sighandler) return 1;
	return 0;
}

int 
fptr_whitelist_event(void (*fptr)(int, short, void *))
{
	if(fptr == &comm_point_udp_callback) return 1;
	else if(fptr == &comm_point_tcp_accept_callback) return 1;
	else if(fptr == &comm_point_tcp_handle_callback) return 1;
	else if(fptr == &comm_timer_callback) return 1;
	else if(fptr == &comm_signal_callback) return 1;
	else if(fptr == &comm_point_local_handle_callback) return 1;
	return 0;
}

int 
fptr_whitelist_pending_udp(comm_point_callback_t *fptr)
{
	if(fptr == &serviced_udp_callback) return 1;
	else if(fptr == &worker_handle_reply) return 1;
	return 0;
}

int 
fptr_whitelist_pending_tcp(comm_point_callback_t *fptr)
{
	if(fptr == &serviced_tcp_callback) return 1;
	else if(fptr == &worker_handle_reply) return 1;
	return 0;
}

int 
fptr_whitelist_serviced_query(comm_point_callback_t *fptr)
{
	if(fptr == &worker_handle_service_reply) return 1;
	return 0;
}

int 
fptr_whitelist_region_allocator(void *(*fptr)(size_t))
{
	/* TODO: remove callbacks from new region type */
	if(fptr == &malloc) return 1;
	return 0;
}

int 
fptr_whitelist_region_deallocator(void (*fptr)(void*))
{
	if(fptr == &free) return 1;
	return 0;
}

int 
fptr_whitelist_rbtree_cmp(int (*fptr) (const void *, const void *))
{
	if(fptr == &mesh_state_compare) return 1;
	else if(fptr == &mesh_state_ref_compare) return 1;
	else if(fptr == &donotq_cmp) return 1;
	else if(fptr == &fwd_cmp) return 1;
	else if(fptr == &stub_cmp) return 1;
	else if(fptr == &pending_cmp) return 1;
	else if(fptr == &serviced_cmp) return 1;
	else if(fptr == &order_lock_cmp) return 1;
	else if(fptr == &codeline_cmp) return 1;
	else if(fptr == &nsec3_hash_cmp) return 1;
	else if(fptr == &mini_ev_cmp) return 1;
	else if(fptr == &anchor_cmp) return 1;
	else if(fptr == &canonical_tree_compare) return 1;
	return 0;
}

int 
fptr_whitelist_hash_sizefunc(lruhash_sizefunc_t fptr)
{
	if(fptr == &msgreply_sizefunc) return 1;
	else if(fptr == &ub_rrset_sizefunc) return 1;
	else if(fptr == &infra_host_sizefunc) return 1;
	else if(fptr == &key_entry_sizefunc) return 1;
	else if(fptr == &infra_lame_sizefunc) return 1;
	else if(fptr == &test_slabhash_sizefunc) return 1;
	return 0;
}

int 
fptr_whitelist_hash_compfunc(lruhash_compfunc_t fptr)
{
	if(fptr == &query_info_compare) return 1;
	else if(fptr == &ub_rrset_compare) return 1;
	else if(fptr == &infra_host_compfunc) return 1;
	else if(fptr == &key_entry_compfunc) return 1;
	else if(fptr == &infra_lame_compfunc) return 1;
	else if(fptr == &test_slabhash_compfunc) return 1;
	return 0;
}

int 
fptr_whitelist_hash_delkeyfunc(lruhash_delkeyfunc_t fptr)
{
	if(fptr == &query_entry_delete) return 1;
	else if(fptr == &ub_rrset_key_delete) return 1;
	else if(fptr == &infra_host_delkeyfunc) return 1;
	else if(fptr == &key_entry_delkeyfunc) return 1;
	else if(fptr == &infra_lame_delkeyfunc) return 1;
	else if(fptr == &test_slabhash_delkey) return 1;
	return 0;
}

int 
fptr_whitelist_hash_deldatafunc(lruhash_deldatafunc_t fptr)
{
	if(fptr == &reply_info_delete) return 1;
	else if(fptr == &rrset_data_delete) return 1;
	else if(fptr == &infra_host_deldatafunc) return 1;
	else if(fptr == &key_entry_deldatafunc) return 1;
	else if(fptr == &infra_lame_deldatafunc) return 1;
	else if(fptr == &test_slabhash_deldata) return 1;
	return 0;
}

/*
 * mixed_mode/mixed_mode.h - Module for querying DNSSEC not enabled NS for Insecure zones
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

#ifndef MIXED_MODE_MIXED_MODE_H
#define MIXED_MODE_MIXED_MODE_H

#include "util/module.h"
#include "services/outbound_list.h"


/**
 * This structure contains module configuration information. One instance of
 * this structure exists per instance of the module. Normally there is only one
 * instance of the module.
 */
struct mixed_mode_env {
	// TODO add more global options here
};

/**
 * The query state internal to the module
 */
enum mixed_mode_state {
	MIXED_MODE_NEW_CLIENT_QUERY,		/* Query from client */

	MIXED_MODE_WAIT_OUTBOUND_QUERY,

	MIXED_MODE_HAVE_RESPONSE,

	MIXED_MODE_FINISHED
};

/**
 * Per-query module-specific state.
 */
struct mixed_mode_qstate {
	/**
	 * The query specific module state
	 */
	enum mixed_mode_state state;

	/* response */
	struct dns_msg* response;

	/* current forwarder used */
	struct sock_list* forwarder;

	/* list of outbound queries */
	struct outbound_list outlist;
};

//------------------------------------------------------------------------------------

/**
 * Get the mixed_mode function block.
 * @return: function block with function pointers to mixed_mode methods.
 */
struct module_func_block *mixed_mode_get_funcblock(void);

/** mixed_mode init */
int mixed_mode_init(struct module_env* env, int id);

/** mixed_mode deinit */
void mixed_mode_deinit(struct module_env* env, int id);

/** mixed_mode operate on a query */
void mixed_mode_operate(struct module_qstate* qstate, enum module_ev event, int id,
		struct outbound_entry* outbound);

void mixed_mode_inform_super(struct module_qstate* qstate, int id,
    struct module_qstate* super);

/** mixed_mode cleanup query state */
void mixed_mode_clear(struct module_qstate* qstate, int id);

/** mixed_mode alloc size routine */
size_t mixed_mode_get_mem(struct module_env* env, int id);

#endif /* MIXED_MODE_MIXED_MODE_H */

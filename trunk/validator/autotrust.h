/*
 * validator/autotrust.h - RFC5011 trust anchor management for unbound.
 *
 * Copyright (c) 2009, NLnet Labs. All rights reserved.
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
 * Contains autotrust definitions.
 */

#ifndef VALIDATOR_AUTOTRUST_H
#define VALIDATOR_AUTOTRUST_H
#include "util/rbtree.h"
struct val_anchors;

/** Autotrust anchor states */
typedef enum {
	AUTR_STATE_START   = 0,
	AUTR_STATE_ADDPEND = 1,
	AUTR_STATE_VALID   = 2,
	AUTR_STATE_MISSING = 3,
	AUTR_STATE_REVOKED = 4,
	AUTR_STATE_REMOVED = 5
} autr_state_t;

/** 
 * Autotrust metadata for one trust anchor key.
 */
struct autr_ta_data {
	/** 5011 state */
	autr_state_t s;
	/** last update of key */
	time_t last_change;
	/** pending count */
	uint8_t pending_count;
	/** fresh TA was seen */
	uint8_t fetched;
	/** revoked TA was seen */
	uint8_t revoked;
};

/** 
 * Autotrust metadata for a trust point.
 */
struct autr_point_data {
	/** file to store the trust point in */
	const char* file;
	/** next probe time */
	uint32_t next_probe_time;
	/** rbtree node for probe sort */
	rbnode_t pnode;

	/** last queried DNSKEY set */
	time_t last_queried;
	/** how many times did it fail */
	uint8_t query_failed;
	/** when to query if !failed */
	uint32_t query_interval;
	/** when to retry if failed */
	uint32_t retry_time;

	/** number of valid DNSKEYs */
	uint8_t valid;
	/** number of missing DNSKEYs */
	uint8_t missing;
};

/** 
 * Autotrust global metadata.
 */
struct autr_global_data {
	/** rbtree of autotrust anchors sorted by next probe time */
	rbtree_t probetree;
};

/**
 * Create new global 5011 data structure.
 * @return new structure or NULL on malloc failure.
 */
struct autr_global_data* autr_global_create(void);

/**
 * Delete global 5011 data structure.
 * @param global: global autotrust state to delete.
 */
void autr_global_delete(struct autr_global_data* global);

/** probe tree compare function */
int probetree_cmp(const void* x, const void* y);

/**
 * Read autotrust file.
 * @param anchors: the anchors structure.
 * @param parsebuf: buffer temporary for parsing data.
 * @param nm: name of the file (copied).
 * @return false on failure.
 */
int autr_read_file(struct val_anchors* anchors, ldns_buffer* parsebuf,
	const char* nm);

#endif /* VALIDATOR_AUTOTRUST_H */

/*
 * mixed_mode/mm_fwds.h - functions for working with mixed-mode forwarders structure
 *
 * Copyright (C) 2015 Red Hat, Inc.
 *
 * Author: Tomas Hozza <thozza@redhat.com>
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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef MIXED_MODE_MM_FWDS_H
#define MIXED_MODE_MM_FWDS_H

#include "util/net_help.h"
#include "util/config_file.h"


struct mm_forwards {
	/* list of insecure forwarders, that are used
	 * by the mixed-mode module.
	 */
	struct sock_list* list;
};

/**
 * Creates the structure and returns pointer. If fails, returns NULL.
 */
struct mm_forwards* mm_forwards_create(void);

/**
 * Delete all forwarders from the list
 */
void mm_forwards_delete_all(struct mm_forwards* fwds);

/**
 * Delete all forwarders from the list and free the structure. Set it to NULL.
 */
void mm_forwards_destroy(struct mm_forwards** fwds);

/**
 * Add a forwarder to existing list of forwarders
 */
int mm_forwards_add(struct mm_forwards* fwds, struct sockaddr_storage* addr, socklen_t len);

/**
 * Replace the sock_list in the old_fwds with the list from new_fwds.
 * List in new_fwds is set to NULL. The original list in old_fwds is freed.
 */
void mm_forwards_replace(struct mm_forwards* old_fwds, struct mm_forwards* new_fwds);

/**
 * Apply the configuration from config file to the forwarders list.
 */
int mm_forwards_apply_cfg(struct mm_forwards* fwds, struct config_file* cfg);

#endif /* MIXED_MODE_MM_FWDS_H */
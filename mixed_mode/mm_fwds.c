/*
 * mixed_mode/mm_fwds.c - implementation of functions for mixed-mode forwarders
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

#include "config.h"
#include "mixed_mode/mm_fwds.h"
#include "util/module.h"
#include "util/net_help.h"


struct mm_forwards* mm_forwards_create(void)
{
	struct mm_forwards* fwds = (struct mm_forwards*)calloc(1, sizeof(struct mm_forwards));
	if (fwds)
		return fwds;
	else
		return NULL;
}

static void forwarders_list_delete(struct mm_forwards* fwds)
{
	struct sock_list** list = &fwds->list;
	struct sock_list* item = NULL;

	for (item = *list; item != NULL; ) {
		struct sock_list* tmp = item;
		item = item->next;
		free(tmp);
	}

	*list = NULL;
}

void mm_forwards_delete_all(struct mm_forwards* fwds)
{
	if (!fwds)
		return;

	forwarders_list_delete(fwds);
}

void mm_forwards_destroy(struct mm_forwards** fwds)
{
	if (!*fwds)
		return;

	mm_forwards_delete_all(*fwds);
	free(*fwds);
	*fwds = NULL;
}

int mm_forwards_add(struct mm_forwards* fwds, struct sockaddr_storage* addr, socklen_t len)
{
	struct sock_list** list = &fwds->list;
	struct sock_list* add = (struct sock_list*)calloc(1, sizeof(*add) - sizeof(add->addr) + (size_t)len);
	if (!add) {
		log_err("mixed-mode: malloc failed");
		return 0;
	}

	add->next = *list;
	add->len = len;
	if (len)
		memmove(&add->addr, addr, len);
	*list = add;

	return 1;
}

void mm_forwards_replace(struct mm_forwards* old_fwds, struct mm_forwards* new_fwds)
{
	/* remove forwarders list from the original structure */
	forwarders_list_delete(old_fwds);

	old_fwds->list = new_fwds->list;
	new_fwds->list = NULL;
}

int mm_forwards_apply_cfg(struct mm_forwards* fwds, struct config_file* cfg)
{
	mm_forwards_delete_all(fwds);

	/* go through all forwarders from the configuration */
	struct config_strlist* forwarder = NULL;
	for (forwarder = cfg->mixed_mode_fwds; forwarder != NULL; forwarder = forwarder->next) {
		verbose(VERB_ALGO, "mixed-mode-fwd: %s", forwarder->str);

		struct sockaddr_storage addr;
		socklen_t len;
		if (!extstrtoaddr(forwarder->str, &addr, &len)) {
			log_err("mixed-mode: cannot parse forwarder address: %s", forwarder->str);
			return 0;
		}

		if (!mm_forwards_add(fwds, &addr, len))
			return 0;
	}
	return 1;
}

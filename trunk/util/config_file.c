/*
 * util/config_file.c - reads and stores the config file for unbound.
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
 * This file contains functions for the config file.
 */

#include "config.h"
#include "util/log.h"

#include "util/configyyrename.h"
#include "util/config_file.h"
#include "util/configparser.h"
#include "util/net_help.h"
#include "util/data/msgparse.h"
/** global config during parsing */
struct config_parser_state* cfg_parser = 0;
/** lex in file */
extern FILE* ub_c_in;
/** lex out file */
extern FILE* ub_c_out;
/** the yacc lex generated parse function */
int ub_c_parse(void);
/** the lexer function */
int ub_c_lex(void);
/** wrap function */
int ub_c_wrap(void);
/** print error with file and line number */
void ub_c_error(const char *message);
/** remove buffers for parsing and init */
void ub_c_lex_destroy(void);

/** init ports possible for use */
static void init_outgoing_availports(int* array, int num);

struct config_file* 
config_create()
{
	struct config_file* cfg;
	cfg = (struct config_file*)calloc(1, sizeof(struct config_file));
	if(!cfg)
		return NULL;
	/* the defaults if no config is present */
	cfg->verbosity = 1;
	cfg->stat_interval = 0;
	cfg->stat_cumulative = 0;
	cfg->stat_extended = 0;
	cfg->num_threads = 1;
	cfg->port = UNBOUND_DNS_PORT;
	cfg->do_ip4 = 1;
	cfg->do_ip6 = 1;
	cfg->do_udp = 1;
	cfg->do_tcp = 1;
	cfg->use_syslog = 1;
	cfg->log_time_ascii = 0;
#ifndef USE_WINSOCK
	cfg->outgoing_num_ports = 256;
	cfg->outgoing_num_tcp = 10;
	cfg->incoming_num_tcp = 10;
#else
	cfg->outgoing_num_ports = 48; /* windows is limited in num fds */
	cfg->outgoing_num_tcp = 2; /* leaves 64-52=12 for: 4if,1stop,thread4 */
	cfg->incoming_num_tcp = 2; 
#endif
	cfg->msg_buffer_size = 65552; /* 64 k + a small margin */
	cfg->msg_cache_size = 4 * 1024 * 1024;
	cfg->msg_cache_slabs = 4;
	cfg->num_queries_per_thread = 1024;
	cfg->jostle_time = 200;
	cfg->rrset_cache_size = 4 * 1024 * 1024;
	cfg->rrset_cache_slabs = 4;
	cfg->host_ttl = 900;
	cfg->lame_ttl = 900;
	cfg->bogus_ttl = 60;
	cfg->min_ttl = 0;
	cfg->max_ttl = 3600 * 24;
	cfg->infra_cache_slabs = 4;
	cfg->infra_cache_numhosts = 10000;
	cfg->infra_cache_lame_size = 10240; /* easily 40 or more entries */
	if(!(cfg->outgoing_avail_ports = (int*)calloc(65536, sizeof(int))))
		goto error_exit;
	init_outgoing_availports(cfg->outgoing_avail_ports, 65536);
	if(!(cfg->username = strdup(UB_USERNAME))) goto error_exit;
#ifdef HAVE_CHROOT
	if(!(cfg->chrootdir = strdup(CHROOT_DIR))) goto error_exit;
#endif
	if(!(cfg->directory = strdup(RUN_DIR))) goto error_exit;
	if(!(cfg->logfile = strdup(""))) goto error_exit;
	if(!(cfg->pidfile = strdup(PIDFILE))) goto error_exit;
	if(!(cfg->target_fetch_policy = strdup("3 2 1 0 0"))) goto error_exit;
	cfg->donotqueryaddrs = NULL;
	cfg->donotquery_localhost = 1;
	cfg->root_hints = NULL;
	cfg->do_daemonize = 1;
	cfg->if_automatic = 0;
	cfg->num_ifs = 0;
	cfg->ifs = NULL;
	cfg->num_out_ifs = 0;
	cfg->out_ifs = NULL;
	cfg->stubs = NULL;
	cfg->forwards = NULL;
	cfg->acls = NULL;
	cfg->harden_short_bufsize = 0;
	cfg->harden_large_queries = 0;
	cfg->harden_glue = 1;
	cfg->harden_dnssec_stripped = 1;
	cfg->harden_referral_path = 0;
	cfg->use_caps_bits_for_id = 0;
	cfg->private_address = NULL;
	cfg->private_domain = NULL;
	cfg->unwanted_threshold = 0;
	cfg->hide_identity = 0;
	cfg->hide_version = 0;
	cfg->identity = NULL;
	cfg->version = NULL;
	cfg->auto_trust_anchor_file_list = NULL;
	cfg->trust_anchor_file_list = NULL;
	cfg->trust_anchor_list = NULL;
	cfg->trusted_keys_file_list = NULL;
	cfg->dlv_anchor_file = NULL;
	cfg->dlv_anchor_list = NULL;
	cfg->domain_insecure = NULL;
	cfg->val_date_override = 0;
	cfg->val_sig_skew_min = 3600; /* at least daylight savings trouble */
	cfg->val_sig_skew_max = 86400; /* at most timezone settings trouble */
	cfg->val_clean_additional = 1;
	cfg->val_log_level = 0;
	cfg->val_permissive_mode = 0;
	cfg->add_holddown = 30*24*3600;
	cfg->del_holddown = 30*24*3600;
	cfg->keep_missing = 366*24*3600; /* one year plus a little leeway */
	cfg->key_cache_size = 4 * 1024 * 1024;
	cfg->key_cache_slabs = 4;
	cfg->neg_cache_size = 1 * 1024 * 1024;
	cfg->local_zones = NULL;
	cfg->local_zones_nodefault = NULL;
	cfg->local_data = NULL;
	cfg->python_script = NULL;
	cfg->remote_control_enable = 0;
	cfg->control_ifs = NULL;
	cfg->control_port = 953;
	if(!(cfg->server_key_file = strdup(RUN_DIR"/unbound_server.key"))) 
		goto error_exit;
	if(!(cfg->server_cert_file = strdup(RUN_DIR"/unbound_server.pem"))) 
		goto error_exit;
	if(!(cfg->control_key_file = strdup(RUN_DIR"/unbound_control.key"))) 
		goto error_exit;
	if(!(cfg->control_cert_file = strdup(RUN_DIR"/unbound_control.pem"))) 
		goto error_exit;

	if(!(cfg->module_conf = strdup("validator iterator"))) goto error_exit;
	if(!(cfg->val_nsec3_key_iterations = 
		strdup("1024 150 2048 500 4096 2500"))) goto error_exit;
	return cfg;
error_exit:
	config_delete(cfg); 
	return NULL;
}

struct config_file* config_create_forlib()
{
	struct config_file* cfg = config_create();
	if(!cfg) return NULL;
	/* modifications for library use, less verbose, less memory */
	free(cfg->chrootdir);
	cfg->chrootdir = NULL;
	cfg->verbosity = 0;
	cfg->outgoing_num_ports = 16; /* in library use, this is 'reasonable'
		and probably within the ulimit(maxfds) of the user */
	cfg->outgoing_num_tcp = 2;
	cfg->msg_cache_size = 1024*1024;
	cfg->msg_cache_slabs = 1;
	cfg->rrset_cache_size = 1024*1024;
	cfg->rrset_cache_slabs = 1;
	cfg->infra_cache_slabs = 1;
	cfg->use_syslog = 0;
	cfg->key_cache_size = 1024*1024;
	cfg->key_cache_slabs = 1;
	cfg->neg_cache_size = 100 * 1024;
	cfg->donotquery_localhost = 0; /* allow, so that you can ask a
		forward nameserver running on localhost */
	return cfg;
}

/** check that the value passed is >= 0 */
#define IS_NUMBER_OR_ZERO \
	if(atoi(val) == 0 && strcmp(val, "0") != 0) return 0
/** check that the value passed is > 0 */
#define IS_NONZERO_NUMBER \
	if(atoi(val) == 0) return 0
/** check that the value passed is not 0 and a power of 2 */
#define IS_POW2_NUMBER \
	if(atoi(val) == 0 || !is_pow2((size_t)atoi(val))) return 0
/** check that the value passed is yes or no */
#define IS_YES_OR_NO \
	if(strcmp(val, "yes") != 0 && strcmp(val, "no") != 0) return 0

int config_set_option(struct config_file* cfg, const char* opt,
        const char* val)
{
	if(strcmp(opt, "verbosity:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->verbosity = atoi(val);
	} else if(strcmp(opt, "statistics-interval:") == 0) {
		if(strcmp(val, "0") == 0 || strcmp(val, "") == 0)
			cfg->stat_interval = 0;
		else if(atoi(val) == 0)
			return 0;
		else cfg->stat_interval = atoi(val);
	} else if(strcmp(opt, "num_threads:") == 0) {
		/* not supported, library must have 1 thread in bgworker */
		return 0;
	} else if(strcmp(opt, "extended-statistics:") == 0) {
		IS_YES_OR_NO;
		cfg->stat_extended = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "do-ip4:") == 0) {
		IS_YES_OR_NO;
		cfg->do_ip4 = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "do-ip6:") == 0) {
		IS_YES_OR_NO;
		cfg->do_ip6 = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "do-udp:") == 0) {
		IS_YES_OR_NO;
		cfg->do_udp = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "do-tcp:") == 0) {
		IS_YES_OR_NO;
		cfg->do_tcp = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "outgoing-range:") == 0) {
		IS_NONZERO_NUMBER;
		cfg->outgoing_num_ports = atoi(val);
	} else if(strcmp(opt, "outgoing-port-permit:") == 0) {
		return cfg_mark_ports(val, 1, 
			cfg->outgoing_avail_ports, 65536);
	} else if(strcmp(opt, "outgoing-port-avoid:") == 0) {
		return cfg_mark_ports(val, 0, 
			cfg->outgoing_avail_ports, 65536);
	} else if(strcmp(opt, "outgoing-num-tcp:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->outgoing_num_tcp = (size_t)atoi(val);
	} else if(strcmp(opt, "incoming-num-tcp:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->incoming_num_tcp = (size_t)atoi(val);
	} else if(strcmp(opt, "msg-buffer-size:") == 0) {
		IS_NONZERO_NUMBER;
		cfg->msg_buffer_size = (size_t)atoi(val);
	} else if(strcmp(opt, "msg-cache-size:") == 0) {
		return cfg_parse_memsize(val, &cfg->msg_cache_size);
	} else if(strcmp(opt, "msg-cache-slabs:") == 0) {
		IS_POW2_NUMBER;
		cfg->msg_cache_slabs = (size_t)atoi(val);
	} else if(strcmp(opt, "num-queries-per-thread:") == 0) {
		IS_NONZERO_NUMBER;
		cfg->num_queries_per_thread = (size_t)atoi(val);
	} else if(strcmp(opt, "jostle-timeout:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->jostle_time = (size_t)atoi(val);
	} else if(strcmp(opt, "rrset-cache-size:") == 0) {
		return cfg_parse_memsize(val, &cfg->rrset_cache_size);
	} else if(strcmp(opt, "rrset-cache-slabs:") == 0) {
		IS_POW2_NUMBER;
		cfg->rrset_cache_slabs = (size_t)atoi(val);
	} else if(strcmp(opt, "cache-max-ttl:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->max_ttl = atoi(val);
	} else if(strcmp(opt, "infra-host-ttl:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->host_ttl = atoi(val);
	} else if(strcmp(opt, "infra-lame-ttl:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->lame_ttl = atoi(val);
	} else if(strcmp(opt, "infra-cache-slabs:") == 0) {
		IS_POW2_NUMBER;
		cfg->infra_cache_slabs = (size_t)atoi(val);
	} else if(strcmp(opt, "infra-cache-numhosts:") == 0) {
		IS_NONZERO_NUMBER;
		cfg->infra_cache_numhosts = (size_t)atoi(val);
	} else if(strcmp(opt, "infra-cache-lame-size:") == 0) {
		return cfg_parse_memsize(val, &cfg->infra_cache_lame_size);
	} else if(strcmp(opt, "logfile:") == 0) {
		cfg->use_syslog = 0;
		free(cfg->logfile);
		return (cfg->logfile = strdup(val)) != NULL;
	} else if(strcmp(opt, "use-syslog:") == 0) {
		IS_YES_OR_NO;
		cfg->use_syslog = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "root-hints:") == 0) {
		return cfg_strlist_insert(&cfg->root_hints, strdup(val));
	} else if(strcmp(opt, "target-fetch-policy:") == 0) {
		free(cfg->target_fetch_policy);
		return (cfg->target_fetch_policy = strdup(val)) != NULL;
	} else if(strcmp(opt, "harden-glue:") == 0) {
		IS_YES_OR_NO;
		cfg->harden_glue = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "harden-short-bufsize:") == 0) {
		IS_YES_OR_NO;
		cfg->harden_short_bufsize = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "harden-large-queries:") == 0) {
		IS_YES_OR_NO;
		cfg->harden_large_queries = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "harden-dnssec-stripped:") == 0) {
		IS_YES_OR_NO;
		cfg->harden_dnssec_stripped = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "harden-referral-path:") == 0) {
		IS_YES_OR_NO;
		cfg->harden_referral_path = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "private-address:") == 0) {
		return cfg_strlist_insert(&cfg->private_address, strdup(val));
	} else if(strcmp(opt, "private-domain:") == 0) {
		return cfg_strlist_insert(&cfg->private_domain, strdup(val));
	} else if(strcmp(opt, "unwanted-reply-threshold:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->unwanted_threshold = (size_t)atoi(val);
	} else if(strcmp(opt, "do-not-query-localhost:") == 0) {
		IS_YES_OR_NO;
		cfg->donotquery_localhost = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "do-not-query-address:") == 0) {
		return cfg_strlist_insert(&cfg->donotqueryaddrs, strdup(val));
	} else if(strcmp(opt, "auto-trust-anchor-file:") == 0) {
		return cfg_strlist_insert(&cfg->auto_trust_anchor_file_list, 
			strdup(val));
	} else if(strcmp(opt, "trust-anchor-file:") == 0) {
		return cfg_strlist_insert(&cfg->trust_anchor_file_list, 
			strdup(val));
	} else if(strcmp(opt, "trust-anchor:") == 0) {
		return cfg_strlist_insert(&cfg->trust_anchor_list, 
			strdup(val));
	} else if(strcmp(opt, "trusted-keys-file:") == 0) {
		return cfg_strlist_insert(&cfg->trusted_keys_file_list, 
			strdup(val));
	} else if(strcmp(opt, "dlv-anchor-file:") == 0) {
		free(cfg->dlv_anchor_file);
		return (cfg->dlv_anchor_file = strdup(val)) != NULL;
	} else if(strcmp(opt, "dlv-anchor:") == 0) {
		return cfg_strlist_insert(&cfg->dlv_anchor_list, 
			strdup(val));
	} else if(strcmp(opt, "domain-insecure:") == 0) {
		return cfg_strlist_insert(&cfg->domain_insecure, strdup(val));
	} else if(strcmp(opt, "val-override-date:") == 0) {
		if(strcmp(val, "") == 0 || strcmp(val, "0") == 0) {
			cfg->val_date_override = 0;
		} else if(strlen(val) == 14) {
			cfg->val_date_override = cfg_convert_timeval(val);
			return cfg->val_date_override != 0;
		} else {
			if(atoi(val) == 0) return 0;
			cfg->val_date_override = (uint32_t)atoi(val);
		}
	} else if(strcmp(opt, "val-bogus-ttl:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->bogus_ttl = atoi(val);
	} else if(strcmp(opt, "val-clean-additional:") == 0) {
		IS_YES_OR_NO;
		cfg->val_clean_additional = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "val-log-level:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->val_log_level = atoi(val);
	} else if(strcmp(opt, "val-permissive-mode:") == 0) {
		IS_YES_OR_NO;
		cfg->val_permissive_mode = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "val-nsec3-keysize-iterations:") == 0) {
		free(cfg->val_nsec3_key_iterations);
		return (cfg->val_nsec3_key_iterations = strdup(val)) != NULL;
	} else if(strcmp(opt, "add-holddown:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->add_holddown = (unsigned)atoi(val);
	} else if(strcmp(opt, "del-holddown:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->del_holddown = (unsigned)atoi(val);
	} else if(strcmp(opt, "keep-missing:") == 0) {
		IS_NUMBER_OR_ZERO;
		cfg->keep_missing = (unsigned)atoi(val);
	} else if(strcmp(opt, "key-cache-size:") == 0) {
		return cfg_parse_memsize(val, &cfg->key_cache_size);
	} else if(strcmp(opt, "key-cache-slabs:") == 0) {
		IS_POW2_NUMBER;
		cfg->key_cache_slabs = (size_t)atoi(val);
	} else if(strcmp(opt, "neg-cache-size:") == 0) {
		return cfg_parse_memsize(val, &cfg->neg_cache_size);
	} else if(strcmp(opt, "local-data:") == 0) {
		return cfg_strlist_insert(&cfg->local_data, strdup(val));
	} else if(strcmp(opt, "local-zone:") == 0) {
		return cfg_parse_local_zone(cfg, val);
	} else if(strcmp(opt, "control-enable:") == 0) {
		IS_YES_OR_NO;
		cfg->remote_control_enable = (strcmp(val, "yes") == 0);
	} else if(strcmp(opt, "control-interface:") == 0) {
		return cfg_strlist_insert(&cfg->control_ifs, strdup(val));
	} else if(strcmp(opt, "control-port:") == 0) {
		IS_NONZERO_NUMBER;
		cfg->control_port = atoi(val);
	} else if(strcmp(opt, "server-key-file:") == 0) {
		free(cfg->server_key_file);
		return (cfg->server_key_file = strdup(val)) != NULL;
	} else if(strcmp(opt, "server-cert-file:") == 0) {
		free(cfg->server_cert_file);
		return (cfg->server_cert_file = strdup(val)) != NULL;
	} else if(strcmp(opt, "control-key-file:") == 0) {
		free(cfg->control_key_file);
		return (cfg->control_key_file = strdup(val)) != NULL;
	} else if(strcmp(opt, "control-cert-file:") == 0) {
		free(cfg->control_cert_file);
		return (cfg->control_cert_file = strdup(val)) != NULL;
	} else if(strcmp(opt, "module-config:") == 0) {
		free(cfg->module_conf);
		return (cfg->module_conf = strdup(val)) != NULL;
	} else if(strcmp(opt, "python-script:") == 0) {
		free(cfg->python_script);
		return (cfg->python_script = strdup(val)) != NULL;
	} else {
		/* unknown or unsupported (from the library interface) */
		return 0;
	}
	return 1;
}

/** initialize the global cfg_parser object */
static void
create_cfg_parser(struct config_file* cfg, char* filename, const char* chroot)
{
	static struct config_parser_state st;
	cfg_parser = &st;
	cfg_parser->filename = filename;
	cfg_parser->line = 1;
	cfg_parser->errors = 0;
	cfg_parser->cfg = cfg;
	cfg_parser->chroot = chroot;
}

int 
config_read(struct config_file* cfg, const char* filename, const char* chroot)
{
	FILE *in;
	char *fname = (char*)filename;
	if(!fname)
		return 1;
	in = fopen(fname, "r");
	if(!in) {
		log_err("Could not open %s: %s", fname, strerror(errno));
		return 0;
	}
	create_cfg_parser(cfg, fname, chroot);
	ub_c_in = in;
	ub_c_parse();
	ub_c_lex_destroy();
	fclose(in);

	if(cfg_parser->errors != 0) {
		fprintf(stderr, "read %s failed: %d errors in configuration file\n",
			cfg_parser->filename, cfg_parser->errors);
		errno=EINVAL;
		return 0;
	}
	return 1;
}

void
config_delstrlist(struct config_strlist* p)
{
	struct config_strlist *np;
	while(p) {
		np = p->next;
		free(p->str);
		free(p);
		p = np;
	}
}

void
config_deldblstrlist(struct config_str2list* p)
{
	struct config_str2list *np;
	while(p) {
		np = p->next;
		free(p->str);
		free(p->str2);
		free(p);
		p = np;
	}
}

void
config_delstubs(struct config_stub* p)
{
	struct config_stub* np;
	while(p) {
		np = p->next;
		free(p->name);
		config_delstrlist(p->hosts);
		config_delstrlist(p->addrs);
		free(p);
		p = np;
	}
}

void 
config_delete(struct config_file* cfg)
{
	if(!cfg) return;
	free(cfg->username);
	free(cfg->chrootdir);
	free(cfg->directory);
	free(cfg->logfile);
	free(cfg->pidfile);
	free(cfg->target_fetch_policy);
	if(cfg->ifs) {
		int i;
		for(i=0; i<cfg->num_ifs; i++)
			free(cfg->ifs[i]);
		free(cfg->ifs);
	}
	if(cfg->out_ifs) {
		int i;
		for(i=0; i<cfg->num_out_ifs; i++)
			free(cfg->out_ifs[i]);
		free(cfg->out_ifs);
	}
	config_delstubs(cfg->stubs);
	config_delstubs(cfg->forwards);
	config_delstrlist(cfg->donotqueryaddrs);
	config_delstrlist(cfg->root_hints);
	free(cfg->identity);
	free(cfg->version);
	free(cfg->module_conf);
	free(cfg->outgoing_avail_ports);
	config_delstrlist(cfg->private_address);
	config_delstrlist(cfg->private_domain);
	config_delstrlist(cfg->auto_trust_anchor_file_list);
	config_delstrlist(cfg->trust_anchor_file_list);
	config_delstrlist(cfg->trusted_keys_file_list);
	config_delstrlist(cfg->trust_anchor_list);
	config_delstrlist(cfg->domain_insecure);
	free(cfg->dlv_anchor_file);
	config_delstrlist(cfg->dlv_anchor_list);
	config_deldblstrlist(cfg->acls);
	free(cfg->val_nsec3_key_iterations);
	config_deldblstrlist(cfg->local_zones);
	config_delstrlist(cfg->local_zones_nodefault);
	config_delstrlist(cfg->local_data);
	config_delstrlist(cfg->control_ifs);
	free(cfg->server_key_file);
	free(cfg->server_cert_file);
	free(cfg->control_key_file);
	free(cfg->control_cert_file);
	free(cfg);
}

static void 
init_outgoing_availports(int* a, int num)
{
	/* generated with make iana_update */
	const int iana_assigned[] = {
#include "util/iana_ports.inc"
		-1 }; /* end marker to put behind trailing comma */

	int i;
	/* do not use <1024, that could be trouble with the system, privs */
	for(i=1024; i<num; i++) {
		a[i] = i;
	}
	/* create empty spot at 49152 to keep ephemeral ports available 
	 * to other programs */
	for(i=49152; i<49152+256; i++)
		a[i] = 0;
	/* pick out all the IANA assigned ports */
	for(i=0; iana_assigned[i]!=-1; i++) {
		if(iana_assigned[i] < num)
			a[iana_assigned[i]] = 0;
	}
}

int 
cfg_mark_ports(const char* str, int allow, int* avail, int num)
{
	char* mid = strchr(str, '-');
	if(!mid) {
		int port = atoi(str);
		if(port == 0 && strcmp(str, "0") != 0) {
			log_err("cannot parse port number '%s'", str);
			return 0;
		}
		if(port < num)
			avail[port] = (allow?port:0);
	} else {
		int i, low, high = atoi(mid+1);
		char buf[16];
		if(high == 0 && strcmp(mid+1, "0") != 0) {
			log_err("cannot parse port number '%s'", mid+1);
			return 0;
		}
		if( (int)(mid-str)+1 >= (int)sizeof(buf) ) {
			log_err("cannot parse port number '%s'", str);
			return 0;
		}
		if(mid > str)
			memcpy(buf, str, (size_t)(mid-str));
		buf[mid-str] = 0;
		low = atoi(buf);
		if(low == 0 && strcmp(buf, "0") != 0) {
			log_err("cannot parse port number '%s'", buf);
			return 0;
		}
		for(i=low; i<=high; i++) {
			if(i < num)
				avail[i] = (allow?i:0);
		}
		return 1;
	}
	return 1;
}

int 
cfg_scan_ports(int* avail, int num)
{
	int i;
	int count = 0;
	for(i=0; i<num; i++) {
		if(avail[i])
			count++;
	}
	return count;
}

int cfg_condense_ports(struct config_file* cfg, int** avail)
{
	int num = cfg_scan_ports(cfg->outgoing_avail_ports, 65536);
	int i, at = 0;
	*avail = NULL;
	if(num == 0)
		return 0;
	*avail = (int*)malloc(sizeof(int)*num);
	if(!*avail)
		return 0;
	for(i=0; i<65536; i++) {
		if(cfg->outgoing_avail_ports[i])
			(*avail)[at++] = cfg->outgoing_avail_ports[i];
	}
	log_assert(at == num);
	return num;
}

/** print error with file and line number */
void ub_c_error_va_list(const char *fmt, va_list args)
{
	cfg_parser->errors++;
	fprintf(stderr, "%s:%d: error: ", cfg_parser->filename,
	cfg_parser->line);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}

/** print error with file and line number */
void ub_c_error_msg(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	ub_c_error_va_list(fmt, args);
	va_end(args);
}

void ub_c_error(const char *str)
{
	cfg_parser->errors++;
	fprintf(stderr, "%s:%d: error: %s\n", cfg_parser->filename,
		cfg_parser->line, str);
}

int ub_c_wrap()
{
	return 1;
}

int 
cfg_strlist_insert(struct config_strlist** head, char* item)
{
	struct config_strlist *s;
	if(!item || !head)
		return 0;
	s = (struct config_strlist*)calloc(1, sizeof(struct config_strlist));
	if(!s)
		return 0;
	s->str = item;
	s->next = *head;
	*head = s;
	return 1;
}

int 
cfg_str2list_insert(struct config_str2list** head, char* item, char* i2)
{
	struct config_str2list *s;
	if(!item || !i2 || !head)
		return 0;
	s = (struct config_str2list*)calloc(1, sizeof(struct config_str2list));
	if(!s)
		return 0;
	s->str = item;
	s->str2 = i2;
	s->next = *head;
	*head = s;
	return 1;
}

uint32_t 
cfg_convert_timeval(const char* str)
{
	uint32_t t;
	struct tm tm;
	memset(&tm, 0, sizeof(tm));
	if(strlen(str) < 14)
		return 0;
	if(sscanf(str, "%4d%2d%2d%2d%2d%2d", &tm.tm_year, &tm.tm_mon, 
		&tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6)
		return 0;
	tm.tm_year -= 1900;
	tm.tm_mon--;
	/* Check values */
	if (tm.tm_year < 70)	return 0;
	if (tm.tm_mon < 0 || tm.tm_mon > 11)	return 0;
	if (tm.tm_mday < 1 || tm.tm_mday > 31) 	return 0;
	if (tm.tm_hour < 0 || tm.tm_hour > 23)	return 0;
	if (tm.tm_min < 0 || tm.tm_min > 59)	return 0;
	if (tm.tm_sec < 0 || tm.tm_sec > 59)	return 0;
	/* call ldns conversion function */
	t = mktime_from_utc(&tm);
	return t;
}

int 
cfg_count_numbers(const char* s)
{
        /* format ::= (sp num)+ sp      */
        /* num ::= [-](0-9)+            */
        /* sp ::= (space|tab)*          */
        int num = 0;
        while(*s) {
                while(*s && isspace((int)*s))
                        s++;
                if(!*s) /* end of string */
                        break;
                if(*s == '-')
                        s++;
                if(!*s) /* only - not allowed */
                        return 0;
                if(!isdigit((int)*s)) /* bad character */
                        return 0;
                while(*s && isdigit((int)*s))
                        s++;
                num++;
        }
        return num;
}

/** all digit number */
static int isalldigit(const char* str, size_t l)
{
	size_t i;
	for(i=0; i<l; i++)
		if(!isdigit(str[i]))
			return 0;
	return 1;
}

int 
cfg_parse_memsize(const char* str, size_t* res)
{
	size_t len = (size_t)strlen(str);
	size_t mult = 1;
	if(!str || len == 0) {
		log_err("not a size: '%s'", str);
		return 0;
	}
	if(isalldigit(str, len)) {
		*res = (size_t)atol(str);
		return 1;
	}
	/* check appended num */
	while(len>0 && str[len-1]==' ')
		len--;
	if(len > 1 && str[len-1] == 'b') 
		len--;
	else if(len > 1 && str[len-1] == 'B') 
		len--;
	
	if(len > 1 && tolower(str[len-1]) == 'g')
		mult = 1024*1024*1024;
	else if(len > 1 && tolower(str[len-1]) == 'm')
		mult = 1024*1024;
	else if(len > 1 && tolower(str[len-1]) == 'k')
		mult = 1024;
	else if(len > 0 && isdigit(str[len-1]))
		mult = 1;
	else {
		log_err("unknown size specifier: '%s'", str);
		return 0;
	}
	while(len>1 && str[len-2]==' ')
		len--;

	if(!isalldigit(str, len-1)) {
		log_err("unknown size specifier: '%s'", str);
		return 0;
	}
	*res = ((size_t)atol(str)) * mult;
	return 1;
}

void 
config_apply(struct config_file* config)
{
	MAX_TTL = (uint32_t)config->max_ttl;
	MIN_TTL = (uint32_t)config->min_ttl;
	log_set_time_asc(config->log_time_ascii);
}

/** 
 * Calculate string length of full pathname in original filesys
 * @param fname: the path name to convert.
 * 	Must not be null or empty.
 * @param cfg: config struct for chroot and chdir (if set).
 * @param use_chdir: if false, only chroot is applied.
 * @return length of string.
 *	remember to allocate one more for 0 at end in mallocs.
 */
static size_t
strlen_after_chroot(const char* fname, struct config_file* cfg, int use_chdir)
{
	size_t len = 0;
	int slashit = 0;
	if(cfg->chrootdir && cfg->chrootdir[0] && 
		strncmp(cfg->chrootdir, fname, strlen(cfg->chrootdir)) == 0) {
		/* already full pathname, return it */
		return strlen(fname);
	}
	/* chroot */
	if(cfg->chrootdir && cfg->chrootdir[0]) {
		/* start with chrootdir */
		len += strlen(cfg->chrootdir);
		slashit = 1;
	}
	/* chdir */
#ifdef UB_ON_WINDOWS
	if(fname[0] != 0 && fname[1] == ':') {
		/* full path, no chdir */
	} else
#endif
	if(fname[0] == '/' || !use_chdir) {
		/* full path, no chdir */
	} else if(cfg->directory && cfg->directory[0]) {
		/* prepend chdir */
		if(slashit && cfg->directory[0] != '/')
			len++;
		if(cfg->chrootdir && cfg->chrootdir[0] && 
			strncmp(cfg->chrootdir, cfg->directory, 
			strlen(cfg->chrootdir)) == 0)
			len += strlen(cfg->directory)-strlen(cfg->chrootdir);
		else	len += strlen(cfg->directory);
		slashit = 1;
	}
	/* fname */
	if(slashit && fname[0] != '/')
		len++;
	len += strlen(fname);
	return len;
}

char*
fname_after_chroot(const char* fname, struct config_file* cfg, int use_chdir)
{
	size_t len = strlen_after_chroot(fname, cfg, use_chdir);
	int slashit = 0;
	char* buf = (char*)malloc(len+1);
	if(!buf)
		return NULL;
	buf[0] = 0;
	/* is fname already in chroot ? */
	if(cfg->chrootdir && cfg->chrootdir[0] && 
		strncmp(cfg->chrootdir, fname, strlen(cfg->chrootdir)) == 0) {
		/* already full pathname, return it */
		strncpy(buf, fname, len);
		buf[len] = 0;
		return buf;
	}
	/* chroot */
	if(cfg->chrootdir && cfg->chrootdir[0]) {
		/* start with chrootdir */
		strncpy(buf, cfg->chrootdir, len);
		slashit = 1;
	}
#ifdef UB_ON_WINDOWS
	if(fname[0] != 0 && fname[1] == ':') {
		/* full path, no chdir */
	} else
#endif
	/* chdir */
	if(fname[0] == '/' || !use_chdir) {
		/* full path, no chdir */
	} else if(cfg->directory && cfg->directory[0]) {
		/* prepend chdir */
		if(slashit && cfg->directory[0] != '/')
			strncat(buf, "/", len-strlen(buf));
		/* is the directory already in the chroot? */
		if(cfg->chrootdir && cfg->chrootdir[0] && 
			strncmp(cfg->chrootdir, cfg->directory, 
			strlen(cfg->chrootdir)) == 0)
			strncat(buf, cfg->directory+strlen(cfg->chrootdir), 
				   len-strlen(buf));
		else strncat(buf, cfg->directory, len-strlen(buf));
		slashit = 1;
	}
	/* fname */
	if(slashit && fname[0] != '/')
		strncat(buf, "/", len-strlen(buf));
	strncat(buf, fname, len-strlen(buf));
	buf[len] = 0;
	return buf;
}

/** return next space character in string */
static char* next_space_pos(const char* str)
{
	char* sp = strchr(str, ' ');
	char* tab = strchr(str, '\t');
	if(!tab && !sp)
		return NULL;
	if(!sp) return tab;
	if(!tab) return sp;
	return (sp<tab)?sp:tab;
}

/** return last space character in string */
static char* last_space_pos(const char* str)
{
	char* sp = strrchr(str, ' ');
	char* tab = strrchr(str, '\t');
	if(!tab && !sp)
		return NULL;
	if(!sp) return tab;
	if(!tab) return sp;
	return (sp>tab)?sp:tab;
}

int 
cfg_parse_local_zone(struct config_file* cfg, const char* val)
{
	const char *type, *name_end, *name;
	char buf[256];

	/* parse it as: [zone_name] [between stuff] [zone_type] */
	name = val;
	while(*name && isspace(*name))
		name++;
	if(!*name) {
		log_err("syntax error: too short: %s", val);
		return 0;
	}
	name_end = next_space_pos(name);
	if(!name_end || !*name_end) {
		log_err("syntax error: expected zone type: %s", val);
		return 0;
	}
	if (name_end - name > 255) {
		log_err("syntax error: bad zone name: %s", val);
		return 0;
	}
	strncpy(buf, name, (size_t)(name_end-name));
	buf[name_end-name] = '\0';

	type = last_space_pos(name_end);
	while(type && *type && isspace(*type))
		type++;
	if(!type || !*type) {
		log_err("syntax error: expected zone type: %s", val);
		return 0;
	}

	if(strcmp(type, "nodefault")==0) {
		return cfg_strlist_insert(&cfg->local_zones_nodefault, 
			strdup(name));
	} else {
		return cfg_str2list_insert(&cfg->local_zones, strdup(buf),
			strdup(type));
	}
}

char* cfg_ptr_reverse(char* str)
{
	char* ip, *ip_end;
	char* name;
	char* result;
	char buf[1024];
	struct sockaddr_storage addr;
	socklen_t addrlen;

	/* parse it as: [IP] [between stuff] [name] */
	ip = str;
	while(*ip && isspace(*ip))
		ip++;
	if(!*ip) {
		log_err("syntax error: too short: %s", str);
		return NULL;
	}
	ip_end = next_space_pos(ip);
	if(!ip_end || !*ip_end) {
		log_err("syntax error: expected name: %s", str);
		return NULL;
	}

	name = last_space_pos(ip_end);
	if(!name || !*name) {
		log_err("syntax error: expected name: %s", str);
		return NULL;
	}

	sscanf(ip, "%100s", buf);
	buf[sizeof(buf)-1]=0;

	if(!ipstrtoaddr(buf, UNBOUND_DNS_PORT, &addr, &addrlen)) {
		log_err("syntax error: cannot parse address: %s", str);
		return NULL;
	}

	/* reverse IPv4:
	 * ddd.ddd.ddd.ddd.in-addr-arpa.
	 * IPv6: (h.){32}.ip6.arpa.  */

	if(addr_is_ip6(&addr, addrlen)) {
		uint8_t ad[16];
		const char* hex = "0123456789abcdef";
		char *p = buf;
		int i;
		memmove(ad, &((struct sockaddr_in6*)&addr)->sin6_addr, 
			sizeof(ad));
		for(i=15; i>=0; i--) {
			uint8_t b = ad[i];
			*p++ = hex[ (b&0x0f) ];
			*p++ = '.';
			*p++ = hex[ (b&0xf0) >> 4 ];
			*p++ = '.';
		}
		snprintf(buf+16*4, sizeof(buf)-16*4, "ip6.arpa. ");
	} else {
		uint8_t ad[4];
		memmove(ad, &((struct sockaddr_in*)&addr)->sin_addr, 
			sizeof(ad));
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u.in-addr.arpa. ",
			(unsigned)ad[3], (unsigned)ad[2],
			(unsigned)ad[1], (unsigned)ad[0]);
	}

	/* printed the reverse address, now the between goop and name on end */
	while(*ip_end && isspace(*ip_end))
		ip_end++;
	if(name>ip_end) {
		snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), "%.*s", 
			(int)(name-ip_end), ip_end);
	}
	snprintf(buf+strlen(buf), sizeof(buf)-strlen(buf), " PTR %s", name);

	result = strdup(buf);
	if(!result) {
		log_err("out of memory parsing %s", str);
		return NULL;
	}
	return result;
}
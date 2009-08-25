/*
 * testcode/replay.c - store and use a replay of events for the DNS resolver.
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
 * Store and use a replay of events for the DNS resolver.
 * Used to test known scenarios to get known outcomes.
 */

#include "config.h"
#include "util/log.h"
#include "util/net_help.h"
#include "util/config_file.h"
#include "testcode/replay.h"
#include "testcode/ldns-testpkts.h"

/** max length of lines in file */
#define MAX_LINE_LEN 10240

/** parse keyword in string. 
 * @param line: if found, the line is advanced to after the keyword.
 * @param keyword: string.
 * @return: true if found, false if not. 
 */
static int 
parse_keyword(char** line, const char* keyword)
{
	size_t len = (size_t)strlen(keyword);
	if(strncmp(*line, keyword, len) == 0) {
		*line += len;
		return 1;
	}
	return 0;
}

/** delete moment */
static void
replay_moment_delete(struct replay_moment* mom)
{
	if(!mom)
		return;
	if(mom->match) {
		delete_entry(mom->match);
	}
	free(mom->autotrust_id);
	config_delstrlist(mom->file_content);
	free(mom);
}

/** delete range */
static void
replay_range_delete(struct replay_range* rng)
{
	if(!rng)
		return;
	delete_entry(rng->match);
	free(rng);
}

/** strip whitespace from end of string */
static void
strip_end_white(char* p)
{
	size_t i;
	for(i = strlen(p); i > 0; i--) {
		if(isspace((int)p[i-1]))
			p[i-1] = 0;
		else return;
	}
}

/** 
 * Read a range from file. 
 * @param remain: Rest of line (after RANGE keyword).
 * @param in: file to read from.
 * @param name: name to print in errors.
 * @param lineno: incremented as lines are read.
 * @param line: line buffer.
 * @param ttl: for readentry
 * @param or: for readentry
 * @param prev: for readentry
 * @return: range object to add to list, or NULL on error.
 */
static struct replay_range*
replay_range_read(char* remain, FILE* in, const char* name, int* lineno, 
	char* line, uint32_t* ttl, ldns_rdf** or, ldns_rdf** prev)
{
	struct replay_range* rng = (struct replay_range*)malloc(
		sizeof(struct replay_range));
	off_t pos;
	char *parse;
	struct entry* entry, *last = NULL;
	if(!rng)
		return NULL;
	memset(rng, 0, sizeof(*rng));
	/* read time range */
	if(sscanf(remain, " %d %d", &rng->start_step, &rng->end_step)!=2) {
		log_err("Could not read time range: %s", line);
		free(rng);
		return NULL;
	}
	/* read entries */
	pos = ftello(in);
	while(fgets(line, MAX_LINE_LEN-1, in)) {
		(*lineno)++;
		parse = line;
		while(isspace((int)*parse))
			parse++;
		if(!*parse || *parse == ';') {
			pos = ftello(in);
			continue;
		}
		if(parse_keyword(&parse, "ADDRESS")) {
			while(isspace((int)*parse))
				parse++;
			strip_end_white(parse);
			if(!extstrtoaddr(parse, &rng->addr, &rng->addrlen)) {
				log_err("Line %d: could not read ADDRESS: %s", 
					*lineno, parse);
				free(rng);
				return NULL;
			}
			pos = ftello(in);
			continue;
		}
		if(parse_keyword(&parse, "RANGE_END")) {
			return rng;
		}
		/* set position before line; read entry */
		(*lineno)--;
		fseeko(in, pos, SEEK_SET);
		entry = read_entry(in, name, lineno, ttl, or, prev);
		if(!entry)
			fatal_exit("%d: bad entry", *lineno);
		entry->next = NULL;
		if(last)
			last->next = entry;
		else	rng->match = entry;
		last = entry;

		pos = ftello(in);
	}
	replay_range_delete(rng);
	return NULL;
}

/** Read FILE match content */
static void
read_file_content(FILE* in, int* lineno, struct replay_moment* mom)
{
	char line[MAX_LINE_LEN];
	char* remain = line;
	struct config_strlist** last = &mom->file_content;
	line[MAX_LINE_LEN-1]=0;
	if(!fgets(line, MAX_LINE_LEN-1, in))
		fatal_exit("FILE_BEGIN expected at line %d", *lineno);
	if(!parse_keyword(&remain, "FILE_BEGIN"))
		fatal_exit("FILE_BEGIN expected at line %d", *lineno);
	while(fgets(line, MAX_LINE_LEN-1, in)) {
		(*lineno)++;
		if(strncmp(line, "FILE_END", 8) == 0) {
			return;
		}
		if(line[0]) line[strlen(line)-1] = 0; /* remove newline */
		if(!cfg_strlist_insert(last, strdup(line)))
			fatal_exit("malloc failure");
		last = &( (*last)->next );
	}
	fatal_exit("no FILE_END in input file");
}

/** 
 * Read a replay moment 'STEP' from file. 
 * @param remain: Rest of line (after STEP keyword).
 * @param in: file to read from.
 * @param name: name to print in errors.
 * @param lineno: incremented as lines are read.
 * @param ttl: for readentry
 * @param or: for readentry
 * @param prev: for readentry
 * @return: range object to add to list, or NULL on error.
 */
static struct replay_moment*
replay_moment_read(char* remain, FILE* in, const char* name, int* lineno, 
	uint32_t* ttl, ldns_rdf** or, ldns_rdf** prev)
{
	struct replay_moment* mom = (struct replay_moment*)malloc(
		sizeof(struct replay_moment));
	int skip = 0;
	int readentry = 0;
	if(!mom)
		return NULL;
	memset(mom, 0, sizeof(*mom));
	if(sscanf(remain, " %d%n", &mom->time_step, &skip) != 1) {
		log_err("%d: cannot read number: %s", *lineno, remain);
		free(mom);
		return NULL;
	}
	remain += skip;
	while(isspace((int)*remain))
		remain++;
	if(parse_keyword(&remain, "NOTHING")) {
		mom->evt_type = repevt_nothing;
	} else if(parse_keyword(&remain, "QUERY")) {
		mom->evt_type = repevt_front_query;
		readentry = 1;
		if(!extstrtoaddr("127.0.0.1", &mom->addr, &mom->addrlen))
			fatal_exit("internal error");
	} else if(parse_keyword(&remain, "CHECK_ANSWER")) {
		mom->evt_type = repevt_front_reply;
		readentry = 1;
	} else if(parse_keyword(&remain, "CHECK_OUT_QUERY")) {
		mom->evt_type = repevt_back_query;
		readentry = 1;
	} else if(parse_keyword(&remain, "REPLY")) {
		mom->evt_type = repevt_back_reply;
		readentry = 1;
	} else if(parse_keyword(&remain, "TIMEOUT")) {
		mom->evt_type = repevt_timeout;
	} else if(parse_keyword(&remain, "TIME_PASSES")) {
		mom->evt_type = repevt_time_passes;
	} else if(parse_keyword(&remain, "CHECK_AUTOTRUST")) {
		mom->evt_type = repevt_autotrust_check;
		while(isspace((int)*remain))
			remain++;
		if(strlen(remain)>0 && remain[strlen(remain)-1]=='\n')
			remain[strlen(remain)-1] = 0;
		mom->autotrust_id = strdup(remain);
		read_file_content(in, lineno, mom);
	} else if(parse_keyword(&remain, "ERROR")) {
		mom->evt_type = repevt_error;
	} else {
		log_err("%d: unknown event type %s", *lineno, remain);
		free(mom);
		return NULL;
	}
	while(isspace((int)*remain))
		remain++;
	if(parse_keyword(&remain, "ADDRESS")) {
		while(isspace((int)*remain))
			remain++;
		if(strlen(remain) > 0) /* remove \n */
			remain[strlen(remain)-1] = 0;
		if(!extstrtoaddr(remain, &mom->addr, &mom->addrlen)) {
			log_err("line %d: could not parse ADDRESS: %s", 
				*lineno, remain);
			free(mom);
			return NULL;
		}
	} 
	if(parse_keyword(&remain, "ELAPSE")) {
		double sec;
		errno = 0;
		sec = strtod(remain, &remain);
		if(sec == 0. && errno != 0) {
			log_err("line %d: could not parse ELAPSE: %s (%s)", 
				*lineno, remain, strerror(errno));
			free(mom);
			return NULL;
		}
#ifndef S_SPLINT_S
		mom->elapse.tv_sec = (int)sec;
		mom->elapse.tv_usec = (int)((sec - (double)mom->elapse.tv_sec)
			*1000000. + 0.5);
#endif
	} 

	if(readentry) {
		mom->match = read_entry(in, name, lineno, ttl, or, prev);
		if(!mom->match) {
			free(mom);
			return NULL;
		}
	}

	return mom;
}

/** makes scenario with title on rest of line */
static struct replay_scenario*
make_scenario(char* line)
{
	struct replay_scenario* scen;
	while(isspace((int)*line))
		line++;
	if(!*line) {
		log_err("scenario: no title given");
		return NULL;
	}
	scen = (struct replay_scenario*)malloc(sizeof(struct replay_scenario));
	if(!scen)
		return NULL;
	memset(scen, 0, sizeof(*scen));
	scen->title = strdup(line);
	if(!scen->title) {
		free(scen);
		return NULL;
	}
	return scen;
}

struct replay_scenario* 
replay_scenario_read(FILE* in, const char* name, int* lineno)
{
	char line[MAX_LINE_LEN];
	char *parse;
	struct replay_scenario* scen = NULL;
	uint32_t ttl = 3600;
	ldns_rdf* or = NULL;
	ldns_rdf* prev = NULL;
	line[MAX_LINE_LEN-1]=0;

	while(fgets(line, MAX_LINE_LEN-1, in)) {
		parse=line;
		(*lineno)++;
		while(isspace((int)*parse))
			parse++;
		if(!*parse) 
			continue; /* empty line */
		if(parse_keyword(&parse, ";"))
			continue; /* comment */
		if(parse_keyword(&parse, "SCENARIO_BEGIN")) {
			scen = make_scenario(parse);
			if(!scen)
				fatal_exit("%d: could not make scen", *lineno);
			continue;
		} 
		if(!scen)
			fatal_exit("%d: expected SCENARIO", *lineno);
		if(parse_keyword(&parse, "RANGE_BEGIN")) {
			struct replay_range* newr = replay_range_read(parse, 
				in, name, lineno, line, &ttl, &or, &prev);
			if(!newr)
				fatal_exit("%d: bad range", *lineno);
			newr->next_range = scen->range_list;
			scen->range_list = newr;
		} else if(parse_keyword(&parse, "STEP")) {
			struct replay_moment* mom = replay_moment_read(parse, 
				in, name, lineno, &ttl, &or, &prev);
			if(!mom)
				fatal_exit("%d: bad moment", *lineno);
			if(scen->mom_last && 
				scen->mom_last->time_step >= mom->time_step)
				fatal_exit("%d: time goes backwards", *lineno);
			if(scen->mom_last)
				scen->mom_last->mom_next = mom;
			else	scen->mom_first = mom;
			scen->mom_last = mom;
		} else if(parse_keyword(&parse, "SCENARIO_END")) {
			struct replay_moment *p = scen->mom_first;
			int num = 0;
			while(p) {
				num++;
				p = p->mom_next;
			}
			log_info("Scenario has %d steps", num);
			ldns_rdf_deep_free(or);
			ldns_rdf_deep_free(prev);
			return scen;
		}
	}
	ldns_rdf_deep_free(or);
	ldns_rdf_deep_free(prev);
	replay_scenario_delete(scen);
	return NULL;
}

void 
replay_scenario_delete(struct replay_scenario* scen)
{
	struct replay_moment* mom, *momn;
	struct replay_range* rng, *rngn;
	if(!scen)
		return;
	if(scen->title)
		free(scen->title);
	mom = scen->mom_first;
	while(mom) {
		momn = mom->mom_next;
		replay_moment_delete(mom);
		mom = momn;
	}
	rng = scen->range_list;
	while(rng) {
		rngn = rng->next_range;
		replay_range_delete(rng);
		rng = rngn;
	}
	free(scen);
}
/*
 * validator/val_sigcrypt.h - validator signature crypto functions.
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
 * This file contains helper functions for the validator module.
 * The functions help with signature verification and checking, the
 * bridging between RR wireformat data and crypto calls.
 */

#ifndef VALIDATOR_VAL_SIGCRYPT_H
#define VALIDATOR_VAL_SIGCRYPT_H
#include "util/data/packed_rrset.h"
struct val_env;
struct module_env;
struct ub_packed_rrset_key;
struct rbtree_t;
struct regional;

/** 
 * Check if dnskey matches a DS digest 
 * Does not check dnskey-keyid footprint, just the digest.
 * @param env: module environment. Uses scratch space.
 * @param dnskey_rrset: DNSKEY rrset.
 * @param dnskey_idx: index of RR in rrset.
 * @param ds_rrset: DS rrset
 * @param ds_idx: index of RR in DS rrset.
 * @return true if it matches, false on error, not supported or no match.
 */
int ds_digest_match_dnskey(struct module_env* env,
	struct ub_packed_rrset_key* dnskey_rrset, size_t dnskey_idx,
	struct ub_packed_rrset_key* ds_rrset, size_t ds_idx);

/** 
 * Get dnskey keytag, footprint value
 * @param dnskey_rrset: DNSKEY rrset.
 * @param dnskey_idx: index of RR in rrset.
 * @return the keytag or 0 for badly formatted DNSKEYs.
 */
uint16_t dnskey_calc_keytag(struct ub_packed_rrset_key* dnskey_rrset, 
	size_t dnskey_idx);

/**
 * Get DS keytag, footprint value that matches the DNSKEY keytag it signs.
 * @param ds_rrset: DS rrset
 * @param ds_idx: index of RR in DS rrset.
 * @return the keytag or 0 for badly formatted DSs.
 */ 
uint16_t ds_get_keytag(struct ub_packed_rrset_key* ds_rrset, size_t ds_idx);

/** 
 * See if DNSKEY algorithm is supported 
 * @param dnskey_rrset: DNSKEY rrset.
 * @param dnskey_idx: index of RR in rrset.
 * @return true if supported.
 */
int dnskey_algo_is_supported(struct ub_packed_rrset_key* dnskey_rrset, 
	size_t dnskey_idx);

/** 
 * See if DS digest algorithm is supported 
 * @param ds_rrset: DS rrset
 * @param ds_idx: index of RR in DS rrset.
 * @return true if supported.
 */
int ds_digest_algo_is_supported(struct ub_packed_rrset_key* ds_rrset, 
	size_t ds_idx);

/**
 * Get DS RR digest algorithm
 * @param ds_rrset: DS rrset.
 * @param ds_idx: which DS.
 * @return algorithm or 0 if DS too short.
 */
int ds_get_digest_algo(struct ub_packed_rrset_key* ds_rrset, size_t ds_idx);

/** 
 * See if DS key algorithm is supported 
 * @param ds_rrset: DS rrset
 * @param ds_idx: index of RR in DS rrset.
 * @return true if supported.
 */
int ds_key_algo_is_supported(struct ub_packed_rrset_key* ds_rrset, 
	size_t ds_idx);

/**
 * Get DS RR key algorithm. This value should match with the DNSKEY algo.
 * @param k: DS rrset.
 * @param idx: which DS.
 * @return algorithm or 0 if DS too short.
 */
int ds_get_key_algo(struct ub_packed_rrset_key* k, size_t idx);

/**
 * Get DNSKEY RR signature algorithm
 * @param k: DNSKEY rrset.
 * @param idx: which DNSKEY RR.
 * @return algorithm or 0 if DNSKEY too short.
 */
int dnskey_get_algo(struct ub_packed_rrset_key* k, size_t idx);

/**
 * Get DNSKEY RR flags 
 * @param k: DNSKEY rrset.
 * @param idx: which DNSKEY RR.
 * @return flags or 0 if DNSKEY too short.
 */
uint16_t dnskey_get_flags(struct ub_packed_rrset_key* k, size_t idx);

/** 
 * Verify rrset against dnskey rrset. 
 * @param env: module environment, scratch space is used.
 * @param ve: validator environment, date settings.
 * @param rrset: to be validated.
 * @param dnskey: DNSKEY rrset, keyset to try.
 * @return SECURE if one key in the set verifies one rrsig.
 *	UNCHECKED on allocation errors, unsupported algorithms, malformed data,
 *	and BOGUS on verification failures (no keys match any signatures).
 */
enum sec_status dnskeyset_verify_rrset(struct module_env* env, 
	struct val_env* ve, struct ub_packed_rrset_key* rrset, 
	struct ub_packed_rrset_key* dnskey);

/** 
 * verify rrset against one specific dnskey (from rrset) 
 * @param env: module environment, scratch space is used.
 * @param ve: validator environment, date settings.
 * @param rrset: to be validated.
 * @param dnskey: DNSKEY rrset, keyset.
 * @param dnskey_idx: which key from the rrset to try.
 * @return secure if *this* key signs any of the signatures on rrset.
 *	unchecked on error or and bogus on bad signature.
 */
enum sec_status dnskey_verify_rrset(struct module_env* env, 
	struct val_env* ve, struct ub_packed_rrset_key* rrset, 
	struct ub_packed_rrset_key* dnskey, size_t dnskey_idx);

/** 
 * verify rrset, with dnskey rrset, for a specific rrsig in rrset
 * @param env: module environment, scratch space is used.
 * @param ve: validator environment, date settings.
 * @param now: current time for validation (can be overridden).
 * @param rrset: to be validated.
 * @param dnskey: DNSKEY rrset, keyset to try.
 * @param sig_idx: which signature to try to validate.
 * @param sortree: reused sorted order. Stored in region. Pass NULL at start,
 * 	and for a new rrset.
 * @return secure if any key signs *this* signature. bogus if no key signs it,
 *	or unchecked on error.
 */
enum sec_status dnskeyset_verify_rrset_sig(struct module_env* env, 
	struct val_env* ve, uint32_t now, struct ub_packed_rrset_key* rrset, 
	struct ub_packed_rrset_key* dnskey, size_t sig_idx, 
	struct rbtree_t** sortree);

/** 
 * verify rrset, with specific dnskey(from set), for a specific rrsig 
 * @param region: scratch region used for temporary allocation.
 * @param buf: scratch buffer used for canonicalized rrset data.
 * @param ve: validator environment, date settings.
 * @param now: current time for validation (can be overridden).
 * @param rrset: to be validated.
 * @param dnskey: DNSKEY rrset, keyset.
 * @param dnskey_idx: which key from the rrset to try.
 * @param sig_idx: which signature to try to validate.
 * @param sortree: pass NULL at start, the sorted rrset order is returned.
 * 	pass it again for the same rrset.
 * @param buf_canon: if true, the buffer is already canonical.
 * 	pass false at start. pass old value only for same rrset and same
 * 	signature (but perhaps different key) for reuse.
 * @return secure if this key signs this signature. unchecked on error or 
 *	bogus if it did not validate.
 */
enum sec_status dnskey_verify_rrset_sig(struct regional* region, 
	ldns_buffer* buf, struct val_env* ve, uint32_t now,
	struct ub_packed_rrset_key* rrset, struct ub_packed_rrset_key* dnskey, 
	size_t dnskey_idx, size_t sig_idx,
	struct rbtree_t** sortree, int* buf_canon);

/**
 * canonical compare for two tree entries
 */
int canonical_tree_compare(const void* k1, const void* k2);

#endif /* VALIDATOR_VAL_SIGCRYPT_H */
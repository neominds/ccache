/* 
 * mc_cache.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <mc_cache.h>
#include "assert.h"
#include <mc_cache_flash.h>

/*
   Cache structure
   Number of items in the cache is fixed by program. (#define). Currently set to 160
   Each item is of size of mCert (180 octets).
   |----0-----|----1-----|----2-----|----3-----|  ... ...  |----160-----|
   |    index |    root  |   cert   |   cert   |  ... ...  |    cert    |
   |----------|----------|----------|----------|  ... ...  |------------|
   Index structure (max 180 octets)

*/
uint8_t to_delete_list[TOTAL_MCERT_SLOTS];
uint8_t to_delete_count = 0;

static error_t cache_find_cert_no_lock(IN const CertBuffer *pCert, INOUT uint16_t *slot, IN uint16_t cmp_flags);
static error_t cache_delete_entry_no_lock(uint16_t slot_num);
static error_t mc_delete_pcert(CertBuffer *pcert, uint16_t slot_num);
static error_t mc_delete_pcert_one(uint16_t slot_num);
static enum mc_types get_mcert_type(CertBuffer *pCert);
static int is_issuer_of(CertBuffer *pcert1, CertBuffer *pcert2); 
static error_t cache_find_lock(INOUT CertBuffer *pcert, INOUT uint16_t *slot, struct compare_cert_parms *cmp);
static error_t cache_find_issuer_no_lock(IN const CertBuffer *src, OUT CertBuffer *pcert, OUT uint16_t *slot);

extern error_t CheckmCertValidity(CertBuffer *cert);
extern error_t mCertVerifySignature(CertBuffer *pcert, CertBuffer *issuer);
extern error_t mc_lock(void);
extern error_t mc_unlock(void);
extern uint8_t mc_mutex_init();

uint8_t used_list_head;
uint8_t free_list_head;
struct _mc_list used_list[TOTAL_MCERT_SLOTS];
struct _mc_list free_list[TOTAL_MCERT_SLOTS];

static uint8_t is_item_in_used_list(uint8_t item)
{
        uint8_t i;

        for (i = 0; i < TOTAL_MCERT_SLOTS; i++)
                if (used_list[i].cache_slot == item) return 1;

        return 0;
}

static uint8_t get_unused_item_in_used_list()
{
        uint8_t i;

        for (i = 0; i < TOTAL_MCERT_SLOTS; i++)
                if (used_list[i].available) return i;

        return 0xFF;
}

static uint8_t get_unused_item_in_free_list()
{
        uint8_t i;

        for (i = 0; i < TOTAL_MCERT_SLOTS; i++)
                if (free_list[i].available) return i;

        return 0xFF;
}

static error_t delete_from_used_list(uint8_t slotno)
{
	uint8_t prev, curr;

	prev = curr = used_list_head;
	while (curr != 0xFF) {
		if (used_list[curr].cache_slot == slotno) {
			used_list[prev].next = used_list[curr].next;
			used_list[curr].available = AVAILABLE;
			if (curr == used_list_head) 
				used_list_head = used_list[curr].next;
			return ERR_OK;
		}           
		prev = curr;
		curr = used_list[curr].next;
	}
	return ERR_MC_CACHE_NOTHING_TO_DELETE;            
}

static error_t add_to_used_list(uint8_t slotno)
{
	uint8_t ul_index;

	ul_index = get_unused_item_in_used_list();
	if (ul_index == 0xFF)
		return ERR_MC_CACHE_FULL;

	used_list[ul_index].cache_slot = slotno;
	used_list[ul_index].next = used_list_head;
	used_list[ul_index].available = NOT_AVAILABLE;
	used_list_head = ul_index;
	return ERR_OK;
}

static error_t get_available_cache_slot(uint8_t *slotno)
{
       if (free_list_head == 0xFF)
		return ERR_MC_CACHE_FULL;

        *slotno = free_list[free_list_head].cache_slot;
        free_list[free_list_head].available = AVAILABLE;
        free_list_head = free_list[free_list_head].next;
	return ERR_OK;
}

static void add_to_free_list(uint8_t slotno)
{
	uint8_t fl_index;

	fl_index = get_unused_item_in_free_list();
	assert(fl_index != 0xFF);

	free_list[fl_index].cache_slot = slotno;
	free_list[fl_index].next = free_list_head;
	free_list[fl_index].available = NOT_AVAILABLE;
	free_list_head = fl_index;
}

static error_t delete_lru_from_cache()
{
	uint8_t curr,prev, lru_slot;
	error_t ret;

	curr = prev = used_list_head;
	while (curr != 0xFF) {
		if (used_list[curr].cache_slot == ROOT_CERT_SLOT ){
			//LRU is in prev
			lru_slot = used_list[prev].cache_slot;
			ret = delete_from_used_list(lru_slot);
			if (ret != ERR_OK) 
				return ret;
			add_to_free_list(lru_slot);

			//delete the item from flash
			ret = cert_cache_delete_cert(lru_slot);
			return ret;
		}
		prev = curr;
		curr = used_list[curr].next;
	}
	return ERR_MC_CACHE_NOTHING_TO_DELETE;
}

/**
 * compare two mcerts
 * @param - pCert1 is pointer to first Cert
 * @param - pCert1 is pointer to second Cert
 * @param - cmp specifies fields to compare and values to compare
 * @return standard error codes
 */
static error_t compare_mcerts(INOUT CertBuffer *pCert1, IN const CertBuffer *pCert2, IN struct compare_cert_parms *cmp)
{
	if (cmp->bitmap == CERT_CMP_PARAM_ALL){
		if (!memcmp(pCert1->buffer + pCert1->dc.Certificate.idx,
                            pCert2->buffer + pCert2->dc.Certificate.idx,
                            pCert1->dc.Certificate.len))
				return ERR_OK;
	}

	//CERT_CMP_PARAM_SUBJECT
	//CERT_CMP_PARAM_EXTN_POLICIES
	//CERT_CMP_PARAM_EXTN_SKID

	if (cmp->bitmap == CERT_CMP_PARM_MACADDR_BC) {
		if (pCert2->dc.AltNames.len != ALTNAME_LEN_MACADDR || pCert1->dc.AltNames.len != ALTNAME_LEN_MACADDR) 
			return ERR_MC_CACHE_FIND_NO_MATCH;
		if (!memcmp(pCert1->buffer + pCert1->dc.AltNames.idx, pCert2->buffer + pCert2->dc.AltNames.idx, pCert1->dc.AltNames.len))
			return ERR_OK;
	}
	if (cmp->bitmap == CERT_CMP_PARM_MACADDR_DL) {
		//TODO: differentiate between BC and DL
		if (pCert2->dc.AltNames.len != ALTNAME_LEN_MACADDR || pCert1->dc.AltNames.len != ALTNAME_LEN_MACADDR) 
			return ERR_MC_CACHE_FIND_NO_MATCH;
		if (!memcmp(pCert1->buffer + pCert1->dc.AltNames.idx, pCert2->buffer + pCert2->dc.AltNames.idx, pCert1->dc.AltNames.len))
			return ERR_OK;
	}
	if (cmp->bitmap == CERT_CMP_PARAM_ISSUER_AND_SERIAL) {
		if ( cmp->serial_bytes == pCert2->dc.serialNumber.len &&
		     !memcmp(cmp->serial, pCert2->buffer + pCert2->dc.serialNumber.idx, cmp->serial_bytes) &&
		     cmp->name_bytes == pCert2->dc.issuer.len &&
		     !memcmp(cmp->name, pCert2->buffer + pCert2->dc.issuer.idx, cmp->name_bytes ) ) 
			return ERR_OK;
	}
	if (cmp->bitmap == CERT_CMP_PARAM_SUBJECT_AND_SKID) {
		if ( cmp->name_bytes == pCert2->dc.subject.len &&
		     !memcmp(cmp->name, pCert2->buffer + pCert2->dc.subject.idx, cmp->name_bytes ) && 
		     cmp->skid_bytes == pCert2->dc.SubjKeyID.len &&
		     !memcmp(cmp->skid, pCert2->buffer + pCert2->dc.SubjKeyID.idx, cmp->skid_bytes ) ) 
			return ERR_OK;
	}
	if (cmp->bitmap == CERT_CMP_PARAM_OPERATOR_CERT) {
		//issuer must be root and Policies shall be "AnyPolicy"
		if ( cmp->name_bytes == pCert2->dc.issuer.len &&
		     !memcmp(cmp->name, pCert2->buffer + pCert2->dc.issuer.idx, cmp->name_bytes ) && 
		     !memcmp(pCert2->buffer + pCert2->dc.Policies.idx, "AnyPolicy",9) )
			return ERR_OK;
	}
	return ERR_MC_CACHE_FIND_NO_MATCH;
} 

/**
 * init mcert cache
 * @return standard error codes
 */
error_t mc_cache_init()
{
	int i;
	uint8_t ret;
	
	ret = mc_mutex_init();
	
	if (ret != ERR_OK)
	{
		MC_ERR("mcert cache mutex init failed. error %d\n",ret);
		return ERR_MC_CACHE_GEN_ERROR;
	}

        //Initialize used and free lists
        used_list_head = 0xFF;
        for (i = 0; i<TOTAL_MCERT_SLOTS; i++) {
                used_list[i].available = AVAILABLE;
        }   

        //add all except index and root slots to free_list
        free_list_head = 0;
        for (i = 0; i < TOTAL_MCERT_SLOTS-2; i++) {
                free_list[i].cache_slot =  CACHE_START_SLOT + i;
                free_list[i].available = NOT_AVAILABLE;
                free_list[i].next = i+1;
        }
        free_list[i-2].next = 0xFF;

	//TODO: read entries from cache and add to used_list.

	return ERR_OK;
}


/**
 * set given slotno as MRU (first in used_list)
 * @param - slotno is cache slot to become mru
 */
static error_t set_slot_as_mru(uint8_t cache_slotno)
{
	error_t ret;

	if (cache_slotno == ROOT_CERT_SLOT)
		return ERR_OK; 
	ret = delete_from_used_list(cache_slotno);
	if (ret == ERR_OK)
		ret = add_to_used_list(cache_slotno);
	return ret;
}


/**
 * find mcert in cache
 * @param - pCert is the mcert to find
 * @param - slot is index of mcert cache to return; also slotno to start to search from
 * @return standard error codes
 */
//API error_t cache_find_cert(IN const CertBuffer *pCert, INOUT uint16_t *slot){
API error_t cache_find_cert(IN const CertBuffer *pCert, INOUT uint16_t *slot){
	error_t ret = ERR_OK;

	assert(pCert && slot);

	if (mc_lock() != ERR_OK) return ERR_MC_CACHE_LOCK_ERROR;
	ret = cache_find_cert_no_lock(pCert,slot, CERT_CMP_PARAM_ALL);
	if (ret != ERR_OK) {
		mc_unlock();
		return ret;
	}
	if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;

	return ret;
}

/**
 * find mcert in cache when mutex lock is already held
 * @param - pCert is the mcert to find
 * @param - slot is index of mcert cache to return; also slotno to start to search from
 * @param - cmp_flags indicate which fields of pCert to compare
 * @return standard error codes
 */
//static error_t cache_find_cert_no_lock(IN const CertBuffer *pCert, INOUT uint16_t *slot, IN uint16_t cmp_flags)
static error_t cache_find_cert_no_lock(IN const CertBuffer *pCert, INOUT uint16_t *slot, IN uint16_t cmp_flags)
{
	struct compare_cert_parms cmp;
	uint8_t curr;
	error_t ret;

	//CertBuffer cert_local;
	CertBuffer cert_local;

	if (used_list_head == 0xFF)
		return ERR_MC_CACHE_FIND_NO_MATCH;
	
	cmp.bitmap = cmp_flags;
	if (*slot < ROOT_CERT_SLOT) *slot = ROOT_CERT_SLOT;

	curr = used_list_head;
	while (curr != 0xFF) {	
		ret = cert_cache_read_cert(&cert_local, used_list[curr].cache_slot);
		if (ret != ERR_OK) 
			return ret;
		if (used_list[curr].cache_slot < *slot ) continue;
		if (ERR_OK == compare_mcerts((CertBuffer *)pCert, &cert_local, &cmp)){
			*slot = used_list[curr].cache_slot;
			//TODO: find flag to determine to set to MRU or not
			set_slot_as_mru(*slot);
			return ERR_OK;
		}
		curr = used_list[curr].next;
	}
	return ERR_MC_CACHE_FIND_NO_MATCH;
}

API error_t cache_find_by_issuer_and_serial(IN const uint8_t *issuer, IN unsigned issuer_bytes, IN const uint8_t *serial, IN unsigned serial_bytes,
				 INOUT struct CertBuffer *pcert, INOUT uint16_t *slot) 
{
	struct compare_cert_parms cmp;
	assert(issuer && serial && pcert);

	cmp.bitmap = CERT_CMP_PARAM_ISSUER_AND_SERIAL;

	cmp.serial_bytes = serial_bytes;
	cmp.serial = (uint8_t *)serial;
	cmp.name_bytes = issuer_bytes;
	cmp.name = (uint8_t *)issuer;
	return cache_find_lock(pcert, slot, &cmp);
}

API error_t cache_find_by_subject_and_SKID(const uint8_t *subject, unsigned subject_bytes, const uint8_t *skid, unsigned skid_bytes, CertBuffer *pcert, INOUT uint16_t *slot)
{
// SKID stands for Subject Key ID.  If skid_bytes is zero, search only by subject.
	struct compare_cert_parms cmp;
	assert(subject && skid && pcert);

	cmp.bitmap = CERT_CMP_PARAM_SUBJECT_AND_SKID;

	cmp.name_bytes = subject_bytes;
	cmp.name = (uint8_t *)subject;
	cmp.skid_bytes = skid_bytes;
	cmp.skid = (uint8_t *)skid;
	return cache_find_lock(pcert, slot, &cmp);
}

API error_t cache_find_next_operator_cert(CertBuffer *pcert, INOUT uint16_t *slot)
{

//TODO
// issuer == root and Policies == "AnyPolicy"
// An Operator cert is issued by the root and has the “AnyPolicy” value in the Policies extension.  
// Find the next one starting at MRU (if *slot is zero) or starting at *slot if not.
//
	struct compare_cert_parms cmp;
	CertBuffer cert_local;
	assert(pcert);

	cmp.bitmap = CERT_CMP_PARAM_OPERATOR_CERT;

	//TODO: get root cert and fill below two fields	
	cert_cache_read_cert(&cert_local, ROOT_CERT_SLOT);
	cmp.name_bytes = cert_local.dc.subject.len;
	cmp.name = (uint8_t *)(cert_local.buffer + cert_local.dc.subject.idx);
	return cache_find_lock(pcert, slot, &cmp);
}

/**
 * find mcert in cache by subject ID (MAC address)
 * for Birth certificates, subject ID type is 1
 * @param - MAC_addr is MAC address to search for
 * @param - pcert is the mcert to find
 * @param - slot is index of mcert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_BC_by_MAC_address(const uint8_t *MAC_addr, CertBuffer *pcert, uint16_t *slot)
{
	//MAC address is in SubjectID. In EUI64 format - assuming first 8 of 16 octets.
	//Subject ID type = 1 (NIC EUI64 identifier), Subject ID len = 8
	struct compare_cert_parms cmp;

	assert(MAC_addr && pcert && slot);	

	cmp.bitmap = CERT_CMP_PARM_MACADDR_BC;
	//Look at pcert->buffer + pcert->dc.AltNames.idx for 8 octets after making sure that pcert->buffer + pcert->dc.AltNames.len is 8.	
	memcpy(pcert->buffer + pcert->dc.AltNames.idx, MAC_addr, ALTNAME_LEN_MACADDR);
	//memcpy(pcert->mc_subject_id, MAC_addr,SUBJECTID_LEN_MACADDR);
	pcert->dc.AltNames.len = ALTNAME_LEN_MACADDR;
	//pcert->mc_subject_id_len = SUBJECTID_LEN_MACADDR;
	//pcert->mc_subject_type = MC_SUBJECT_TYPE_MACADDR_BC;

	return cache_find_lock(pcert,slot,&cmp);
}

/**
 * find mcert in cache by subject ID (MAC address)
 * for DL certificates, subject ID type is 8
 * @param - MAC_addr is MAC address to search for
 * @param - pcert is the mcert to find
 * @param - slot is index of mcert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_DL_by_MAC_address(const uint8_t *MAC_addr, CertBuffer *pcert, uint16_t *slot)
{
	//MAC address is in SubjectID. In EUI64 format - assuming first 8 of 16 octets.
	//Subject ID type = 8 (NIC EUI64 identifier), Subject ID len = 8
	struct compare_cert_parms cmp;

	assert(MAC_addr && pcert && slot);	

	cmp.bitmap = CERT_CMP_PARM_MACADDR_DL;
	//memcpy(pcert->mc_subject_id, MAC_addr, SUBJECTID_LEN_MACADDR);
	memcpy(pcert->buffer + pcert->dc.AltNames.idx, MAC_addr, ALTNAME_LEN_MACADDR);
	pcert->dc.AltNames.len = ALTNAME_LEN_MACADDR;
	//pcert->mc_subject_id_len = SUBJECTID_LEN_MACADDR;
	//pcert->mc_subject_type = MC_SUBJECT_TYPE_MACADDR_DL;

	return cache_find_lock(pcert,slot,&cmp);
}

/**
 * find mcert in cache; caller shall not hold mutex lock 
 * @param - pcert is the mcert to find
 * @param - slot is index of mcert cache to return; also slotno to start to search from
 * @param - cmp is bitmap of fields to compare
 * @return standard error codes
 */
static error_t cache_find_lock(INOUT CertBuffer *pcert, INOUT uint16_t *slot, struct compare_cert_parms *cmp)
{
	CertBuffer cert_local;
	uint8_t curr;
	error_t ret;

	if (mc_lock() != ERR_OK) return ERR_MC_CACHE_LOCK_ERROR;
	
	if (*slot != 0) {
		//skip entries in used_list until and including given slotno
		//when *slot is non-zero, caller is trying 'get next matching mru'.
		curr = used_list_head;
		while (curr != 0xFF){
			if (used_list[curr].cache_slot == *slot){
				curr = used_list[curr].next;
				break;
			}
			curr = used_list[curr].next;
		}
		if (curr == 0xFF) 	
			return ERR_MC_CACHE_FIND_NO_MATCH;
	}
	else
		curr = used_list_head;

	if (*slot < ROOT_CERT_SLOT) *slot = ROOT_CERT_SLOT;

	while (curr != 0xFF) {
		ret = cert_cache_read_cert(&cert_local, used_list[curr].cache_slot);
		if (ret != ERR_OK) 
			return ret;
 		if (ERR_OK == compare_mcerts((CertBuffer *)pcert, &cert_local, cmp)){
 			*slot = used_list[curr].cache_slot;
			ret = cert_cache_read_cert(pcert, *slot);
			if (ret != ERR_OK) 
				return ret;
 			set_slot_as_mru(*slot);
			if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
 			return ERR_OK;
 		}
	curr = used_list[curr].next;
	}	
	if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
	return ERR_MC_CACHE_FIND_NO_MATCH;

}

/**
 * find mcert in cache by slot number
 * @param - slot_num is the slot number to find
 * @param - pcert is the mcert to find
 * @param - slot is index of mcert cache to return; also slotno to start to search from
 * @return standard error codes
 */
API error_t cache_find_by_slot_number(uint16_t slot_num, CertBuffer *pcert)
{
	//verify that slot is a valid entry in used list.
	uint8_t valid = 0;
	uint8_t curr;

	assert(pcert);	

	//check if slot_num is present in used_list
	curr = used_list_head;
	while( curr != 0xFF) {
		if(slot_num == used_list[curr].cache_slot) {
			valid = 1;
			break;
		}
		curr = used_list[curr].next;
	}
	if (!valid) return ERR_MC_CACHE_INVALID_SLOT_TOFIND;

	//*slot = slot_num;
	return cert_cache_read_cert(pcert, slot_num);
}

/**
 * insert mcert to cache
 * @param - pcert is the mcert to include
 * @param - slot is index of mcert cache to return
 * @return standard error codes
 */
API error_t cache_insert_cert(IN CertBuffer *pcert, OUT uint16_t *slot) 
{
	uint16_t fslot = 0, issuer_slot;
	error_t ret;
	CertBuffer issuer;

	assert(pcert && slot);	

	/* The root cert will always be the first cert inserted into an empty cache.*/
	if (used_list_head == 0xFF && get_mcert_type(pcert) != MCERT_TYPE_ROOT)
		return ERR_MC_CACHE_NO_ROOT_MCERT;

	//verify given certificate before insert
	if (ERR_OK != CheckmCertValidity(pcert)) {
		return ERR_MC_CACHE_CERT_EXPIRED;
	}

	if (mc_lock() != ERR_OK) return ERR_MC_CACHE_LOCK_ERROR;

	if (get_mcert_type(pcert) == MCERT_TYPE_ROOT ) {
		if (used_list_head != 0xFF ) {
			mc_unlock();
			return ERR_MC_CACHE_NOT_EMPTY;
		}
		//check signature
		ret = mCertVerifySignature(pcert,pcert);
		if (ret != ERR_OK) {
			mc_unlock();
			return ERR_MC_CACHE_CERT_SIGN_INVALID;
		}

		//write_cert_to_mcert_cache(pcert, ROOT_CERT_SLOT, CERT_ENTRY_VALID);
		ret = cert_cache_write_cert(pcert, ROOT_CERT_SLOT);
		if (ret != ERR_OK) {
			//TODO: handle ERR;
			return ret;
		}
		*slot = ROOT_CERT_SLOT;
		add_to_used_list(*slot);
		if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
		return ERR_OK;
	}

	if (cache_find_cert_no_lock(pcert,&fslot,CERT_CMP_PARAM_ALL) == ERR_OK){
		if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
		//TODO: a side-effect of this is pcert getting set as MRU. use another find function ?
		return ERR_MC_CACHE_ALREADY_EXIST;
	}

	issuer_slot = 0;
	if (ERR_OK != cache_find_issuer_no_lock(pcert,&issuer,&issuer_slot)) {
		mc_unlock();
		return ERR_MC_CACHE_CERT_NO_ISSUER;
	}
	ret = mCertVerifySignature(pcert,&issuer);
	if (ret != ERR_OK) {
		mc_unlock();
		return ERR_MC_CACHE_CERT_SIGN_INVALID;
	}

	//insert as MRU
	ret = get_available_cache_slot((uint8_t *)slot); //TODO fixme
	if (ret == ERR_MC_CACHE_FULL) {
		delete_lru_from_cache();
		get_available_cache_slot((uint8_t *)slot); //TODO fixme	
	}
	add_to_used_list(*slot);
	ret = cert_cache_write_cert(pcert, *slot);
	if (ret != ERR_OK) {
		mc_unlock();
		return ret;
		//TODO
	}
	if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
	return ERR_OK;
}

/**
 * delete mcert from cache
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
API error_t cache_delete_entry(uint16_t slot_num) 
{
	error_t ret = ERR_OK;

	if (mc_lock() != ERR_OK) return ERR_MC_CACHE_LOCK_ERROR;
	ret = cache_delete_entry_no_lock(slot_num);
	if (ret != ERR_OK) {
		mc_unlock();
		return ret;
	}
	if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;

	return ret;
}

/**
 * add mcert to delete and all its children to deletelist, then invoke actual delete
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
static error_t cache_delete_entry_no_lock(uint16_t slot_num) 
{
	int i;
	error_t ret = ERR_OK;
	CertBuffer cert_local;

	if (slot_num == 0) return ERR_MC_CACHE_NOTHING_TO_DELETE;
	if (slot_num == 1) return ERR_MC_CACHE_CANT_DELETE_ROOTCERT;

	//make sure entry exists in used list
	if (!is_item_in_used_list(slot_num))
		return ERR_MC_CACHE_NOTHING_TO_DELETE;
	
	ret = cert_cache_read_cert(&cert_local, slot_num);
	if (ret != ERR_OK) {
		return ERR_MC_CACHE_NOTHING_TO_DELETE;
		//TODO: handle error?
	}
	ret = mc_delete_pcert(&cert_local,slot_num);

	//perform actual deletion, right to left
	for (i = to_delete_count; i  && ret == ERR_OK; i--)
		ret = mc_delete_pcert_one(to_delete_list[i-1]);
	to_delete_count = 0;

	return ret;
}

/**
 * add mcert to delete and all its children to deletelist
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
//static error_t mc_delete_pcert(CertBuffer *pcert, uint16_t slot_num) 
static error_t mc_delete_pcert(CertBuffer *pcert, uint16_t slot_num) 
{
	CertBuffer cert_local;
	uint8_t curr;
	error_t ret;

	//MC_DEBUG("mc_delete_pcert(%x,%03u)\n", pcert->mc_cert_id, slot_num);
	MC_DEBUG("mc_delete_pcert(%lx,%03u)\n", *((uint64_t *)(pcert->buffer + pcert->dc.serialNumber.idx)), slot_num);

	//walk through used_list to find children
	curr = used_list_head;

	while (curr != 0xFF ) {
		ret = cert_cache_read_cert(&cert_local, used_list[curr].cache_slot);
		if (ret != ERR_OK) {
			//handle error?
		}
		//skip if mcert_local is same as pcert
		//if (!memcmp(pcert->mc_public_key, cert_local.mc_public_key, sizeof(pcert->mc_public_key))) {
		//TODO: compare issuer too
		if (!memcmp(pcert->buffer + pcert->dc.serialNumber.idx, cert_local.buffer + cert_local.dc.serialNumber.idx, pcert->dc.serialNumber.len)) {
				curr = used_list[curr].next;
				continue;
		}
		if (is_issuer_of(pcert, &cert_local)){
			ret = mc_delete_pcert(&cert_local, (uint16_t)used_list[curr].cache_slot); //TODO fixme
			if (ret != ERR_OK)
				return ret;
		}
	
	curr = used_list[curr].next;
	}

	//add to to_delete list
	to_delete_list[to_delete_count++] = slot_num;
	MC_DEBUG("added %d to delete_list(%d items now)\n",slot_num,to_delete_count);
	return ERR_OK;
}

/**
 * delete one mcert from cache
 * @param - slot_num is the slot number to delete
 * @return standard error codes
 */
static error_t mc_delete_pcert_one(uint16_t slot_num)
{
	error_t ret;

	if (slot_num == 0) slot_num++; // is this required ?

	//delete from used_list and add to free list.
	ret = delete_from_used_list(slot_num);
	if (ret == ERR_OK) {
		add_to_free_list(slot_num);
	
		//delete from flash
		ret = cert_cache_delete_cert(slot_num);
		return ret;
	}
	return ERR_OK;
}

/**
 * delete all orphan nodes and their children if any 
 * @return standard error codes
 */
API error_t cache_check_sanity(void)
{
	int found = 0;
	error_t ret;
	CertBuffer mcert_i, mcert_j;
	uint8_t iter_i, iter_j;

	if (mc_lock() != ERR_OK) return ERR_MC_CACHE_LOCK_ERROR;

	restart_loop:
	iter_i = used_list_head;

	while(iter_i != 0xFF) {
		ret = cert_cache_read_cert(&mcert_i, used_list[iter_i].cache_slot);
		if (ret != ERR_OK) {
			//TODO:handle ERR
			return ret;
		}
		found = 0;
		
		iter_j = used_list_head;
		while(iter_j != 0xFF) {
			//get public key of mcert_j
			ret = cert_cache_read_cert(&mcert_j, used_list[iter_j].cache_slot);
			if (ret != ERR_OK) {
				//TODO:handle ERR
				return ret;
			}
			//if (!memcmp(mcert_j.mc_public_key, mcert_i.mc_signer_id, ISSUER_OCTETS_TO_COMPARE)) {
			if ( is_issuer_of(&mcert_j, &mcert_i)) {
				found = 1;
				break;
			}
			iter_j = used_list[iter_j].next;
		}
		if (!found) {
			//delete mcert_i
			ret = cache_delete_entry_no_lock(used_list[iter_i].cache_slot);
			if (ret != ERR_OK) {
				return ret;
			}
			goto restart_loop;
		}
		iter_i = used_list[iter_i].next;
	}
	if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
	return ERR_OK;
}

/**
 * store cache index (used and free lists) to flash
 * @return standard error codes
 */
API error_t cache_store_index(void){
	//write mc_index to flash.
	//TODO
	//return sysvar_set(CERT_CACHE_SYSVAR_ID_INDEX, (const void *)mc_index, sizeof(mc_index));
	return ERR_OK;
}

/**
 * find issuer of given mcert, does not acquire lock
 * @param - src is the mcert to find issuer of
 * @param - pcert is the issuer to return
 * @param - slot is the slot no of issuer 
 * @return standard error codes
 */
static error_t cache_find_issuer_no_lock(IN const CertBuffer *src, OUT CertBuffer *pcert, INOUT uint16_t *slot)
{
	uint8_t curr;
	error_t ret;

	if (*slot < ROOT_CERT_SLOT) *slot = ROOT_CERT_SLOT;
	curr = used_list_head;
	while (curr != 0xFF) {
		ret = cert_cache_read_cert(pcert, used_list[curr].cache_slot);
		if (ret != ERR_OK) {
			//handle error
			return ret;
		}
		//if (!memcmp(src->mc_signer_id, pcert->mc_public_key, ISSUER_OCTETS_TO_COMPARE)){
		if (is_issuer_of(pcert,(CertBuffer *)src)) {
			*slot = used_list[curr].cache_slot;
			return ERR_OK;
		}
		curr = used_list[curr].next;
	}

	return ERR_MC_CACHE_FIND_NO_MATCH;
}

/**
 * find issuer of given mcert
 * @param - src is the mcert to find issuer of
 * @param - pcert is the issuer to return
 * @param - slot is the slot no of issuer 
 * @return standard error codes
 */
API error_t cache_find_issuer(IN const CertBuffer *psubject, OUT CertBuffer *pissuer, INOUT uint16_t *slot)
{
	error_t ret;

	assert(psubject && pissuer && slot);
	*slot = 0;

	if (mc_lock() != ERR_OK) return ERR_MC_CACHE_LOCK_ERROR;
	ret = cache_find_issuer_no_lock(psubject,pissuer,slot);
	if (ret == ERR_OK) {
		if (mc_unlock() != ERR_OK) return ERR_MC_CACHE_UNLOCK_ERROR;
		return ERR_OK;
	}
	mc_unlock();
	return ret;
}

/**
 * check type of given mcert
 * @param - pCert is the mcert to be checked
 * @return - type of certificate
 */
static enum mc_types get_mcert_type(CertBuffer *pCert)
{
	//TODO - identify a root certificate, currently checking only self-signed or not
	if ( is_issuer_of(pCert,pCert)) 
		return MCERT_TYPE_ROOT;
	else
		return MCERT_TYPE_NOTROOT;
}

/**
 * check if one mcert is child of another
 * @param - pCert may be parent
 * @param - maybe_child may be child 
 * @return 1 if maybe_child is child, 0 otherwise
 */
//static int is_child_of(CertBuffer *pCert, CertBuffer *maybe_child)
static int is_issuer_of(CertBuffer *maybe_issuer, CertBuffer *given)
{
	if (given->dc.issuer.len == maybe_issuer->dc.subject.len 				&& 
		     !memcmp(maybe_issuer->buffer + maybe_issuer->dc.subject.idx,
				given->buffer + given->dc.issuer.idx, given->dc.issuer.len) 	&&
		     maybe_issuer->dc.SubjKeyID.len == given->dc.AuthKeyID.len 			&&
		     !memcmp(maybe_issuer->buffer + maybe_issuer->dc.SubjKeyID.idx,
				given->buffer + given->dc.AuthKeyID.idx, given->dc.AuthKeyID.len) ) {
			return 1;
	}
	return 0;
}

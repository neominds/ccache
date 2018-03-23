/* 
 * mc_cache_flash.c
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 * cert cache routines to read/write flash
 */

//#define UCOSII

/*
 * Flash I/O abstraction notes
 *
 * A flash abstraction layer shall have APIs that cert cache can access without requiring to care about 
 * underlying actual calls and method of flash interface. 
 *
 * Following APIs are required
 *
 * error_t cert_cache_read_cert(struct CertBuffer *cert, uint8_t slotno)
 * error_t cert_cache_write_cert(struct CertBuffer *cert, uint8_t slotno)
 * error_t cert_cache_delete_cert(uint8_t slotno)
 * error_t cert_cache_read_index(struct cert_cache_index *index)
 * error_t cert_cache_write_index(struct cert_cache_index *index)
 *
 * Flash layer shall implement these APIs for 3 scenarios.
 * Cache simulated in RAM - for Linux based tests
 * Flash operations via sysvar APIs
 * Flash operations using cert_cache_xxx APIs
 *
 *
*/

#ifdef UCOSII

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "mcert_cache.h"
#include <mc_cache.h>
#include <ucos_ii.h>
#include "os_cfg.h"
#include "assert.h"

static uint16_t get_id_from_slotno(uint8_t slotno)
{
//TODO
return (uint16_t)slotno;
}

error_t cert_cache_read_cert(struct mCert *cert, uint8_t slotno)
{
	uint16_t id,out_len;
	struct mCert_cache_entry cache_entry_local;
	error_t ret;

	id = get_id_from_slotno(slotno);
 	ret =  cert_cache_get(id, (void *)cache_entry_local, sizeof(struct mCert_cache_entry), &out_len); 
 	 //error_t cert_cache_get(uint16_t id, void *val, size_t len, uint16_t *out_len)
 	if (ret == ERR_OK) {
		assert(cache_entry_local.valid == CERT_ENTRY_VALID);
		*cert = *(cache_entry_local.mCert);
	}
	return ret;	
}

error_t cert_cache_write_cert(struct mCert *cert, uint8_t slotno)
{
	uint16_t id,out_len;
	struct mCert_cache_entry cache_entry_local;

	id = get_id_from_slotno(slotno);
	cache_entry_local.valid = CERT_ENTRY_VALID;
	*(cache_entry_local.mCert) = *cert;

	return cert_cache_add(id,(const void *)&cache_entry_local, sizeof(struct mCert_cache_entry));
}

error_t cert_cache_delete_cert(uint8_t slotno)
{
	uint16_t id;

	//mark valid field to CERT_ENTRY_INVALID ?
	id = get_id_from_slotno(slotno);
	return cert_cache_del(id);
}
#endif

#ifdef USE_SYSVAR_API

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "mcert_cache.h"
#include <mc_cache.h>
#include <ucos_ii.h>
#include "os_cfg.h"
#include <sysvar.h>
#include "assert.h"
//#include <cert_cache.h>

//sysvar ids
#define MCERT_CACHE_SYSVAR_ID_INDEX     5001            //TODO: fix sysvar ids
#define MCERT_CACHE_SYSVAR_ID_START     5002
#define MCERT_CACHE_SYSVAR_ID_END       MCERT_CACHE_SYSVAR_ID_START + TOTAL_MCERT_SLOTS

/**
 * read one field from mCert store
 * @param - dest is buffer to return value of field
 * @param - n is number of bytes to read
 * @param - index is the cert_cache index to read from
 * @param - offset is start position of field within mCert
 * @return standard error codes
 */
error_t get_field_from_cert_cache(void *dest, uint16_t n, uint8_t index, uint16_t offset)
{
error_t ret;
uint16_t len_read;
	assert(dest);
	ret = sysvar_read(MCERT_CACHE_SYSVAR_ID_START+index, dest, offset,n,&len_read,NULL);
	if (ret != ERR_OK || n != len_read) {
		return ret;
	}
return ERR_OK; 
}

/**
 * read whole mCert from mCert store
 * @param - dest is buffer to return mcert 
 * @param - index is the cert_cache index to read from
 * @return standard error codes
 */
error_t get_fullcert_from_cert_cache(struct mCert *dest, uint8_t index )
{
error_t ret;
size_t len_to_read = sizeof(struct mCert);
uint16_t len_read;
uint16_t offset = OFFSET_OF(struct mCert_cache_entry, mCert);

	ret = sysvar_read(MCERT_CACHE_SYSVAR_ID_START+index, dest, offset,len_to_read,&len_read,NULL);
	if (ret != ERR_OK || len_to_read != len_read) {
		return ret;
	}
return ERR_OK; 
}

/**
 * write mCert to store
 * @param - pcert is the mcert to store
 * @param - index is the cert_cache index to write
 * @param - valid indicate mCert valid or not
 * @return standard error codes
 */
error_t write_cert_to_mcert_cache(IN struct mCert *pcert, IN uint8_t index, IN uint8_t valid)
{
	struct mCert_cache_entry cache_entry_local;
	cache_entry_local.valid = valid;
	cache_entry_local.mCert = *pcert;
	return sysvar_set(MCERT_CACHE_SYSVAR_ID_START+index, (const void *)&cache_entry_local, sizeof(struct mCert_cache_entry));
}

error_t cert_cache_read_cert(struct mCert *cert, uint8_t slotno)
{
	return get_fullcert_from_cert_cache(cert, slotno);
}

error_t cert_cache_write_cert(struct mCert *cert, uint8_t slotno)
{
	return write_cert_to_mcert_cache(cert, slotno, CERT_ENTRY_VALID);
}

error_t cert_cache_delete_cert(uint8_t slotno)
{
	return write_cert_to_mcert_cache(NULL, slotno, CERT_ENTRY_INVALID);
}

#endif

#ifdef LINUX
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <mc_cache.h>
#include "assert.h"

CertBuffer_cache_entry cert_cache[TOTAL_MCERT_SLOTS];

static void *get_cache_base_addr()
{
        return (void *)(cert_cache+1); //first one not used
}

error_t get_field_from_cert_cache(void *dest, uint16_t n, uint8_t index, uint16_t offset)
{
        // locate entry in cache and return content of mCert field starting at offset
        // caller should allocate dest
        void *base = get_cache_base_addr();

        memcpy(dest, (void *)(base + index*sizeof(CertBuffer_cache_entry) + offset), n);
	return ERR_OK;
}

error_t get_fullcert_from_cert_cache(CertBuffer *dest, uint8_t index )
{
        // locate entry and return full mCert
        // caller should allocate dest
        void *base = get_cache_base_addr();
	CertBuffer_cache_entry *pcert_flash = (CertBuffer_cache_entry *)(base + index*sizeof(CertBuffer_cache_entry));
        memcpy((void *)dest, (void *)&(pcert_flash->cb), sizeof(CertBuffer));
	return ERR_OK;
}

error_t write_cert_to_mcert_cache(IN CertBuffer *pcert, uint8_t index, uint8_t valid)
{
        void *base = get_cache_base_addr();
	uint8_t *valid_in_cache = base + index*sizeof(CertBuffer_cache_entry) + OFFSET_OF(CertBuffer_cache_entry, valid);

	*valid_in_cache = valid;
	if (valid == CERT_ENTRY_VALID) {
		CertBuffer *pcert_in_cache = base + index*sizeof(CertBuffer_cache_entry) + OFFSET_OF(CertBuffer_cache_entry, cb);
		*pcert_in_cache = *pcert;
	}
	return ERR_OK;
}

error_t cert_cache_read_cert(CertBuffer *cert, uint8_t slotno)
{
	return get_fullcert_from_cert_cache(cert, slotno);
}

error_t cert_cache_write_cert(CertBuffer *cert, uint8_t slotno)
{
	return write_cert_to_mcert_cache(cert, slotno, CERT_ENTRY_VALID);
}

error_t cert_cache_delete_cert(uint8_t slotno)
{
	return write_cert_to_mcert_cache(NULL, slotno, CERT_ENTRY_INVALID);
}

#endif

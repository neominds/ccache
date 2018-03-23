/* 
 * mc_cache.h
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 */

#ifndef _MC_CACHE_H_
#define _MC_CACHE_H_

#define RAM_CERT_CACHE
#define STANDALONE
#define LINUX
#define UCOSII

#ifdef UCOSII
#define MC_CACHE_MUTEX_PRI	6 //TODO: fix pri to correct number
#endif
#define NUM_OF_NONROOT_MCERT_SLOTS      159
#define INDEX_SLOT                      0
#define ROOT_MCERT_SLOT                 1
#define FIRST_NON_ROOT_MCERT            2
#define TOTAL_MCERT_SLOTS               NUM_OF_NONROOT_MCERT_SLOTS + 1 + 1 //root+ index

#define IN
#define OUT
#define INOUT
#define API

#define CERT_ENTRY_VALID		1
#define CERT_ENTRY_INVALID		0
#define SUBJECTID_LEN_MACADDR		8
#define MC_SUBJECT_TYPE_MACADDR_BC	1
#define MC_SUBJECT_TYPE_MACADDR_DL	8
#define ISSUER_OCTETS_TO_COMPARE	8
#define MC_PUBLICKEY_OCTETS_LEN		65
#define MCERT_PUBLIC_KEY_XVAL_LEN	32

#define CACHE_INDEX_SLOT  0
#define ROOT_CERT_SLOT    1
#define CACHE_START_SLOT  2 //0 for index and 1 for root
#define AVAILABLE      1
#define NOT_AVAILABLE  0
#define X509_CERT_SIZE 1024


struct _mc_list
{
        uint8_t available;
        uint8_t cache_slot;
        uint8_t next;
};


#ifdef STANDALONE
struct mCert {
	uint32_t mc_magic;           /* a4 9e 01 83 = version 1 */
	uint32_t mc_sys_id;        
	uint8_t  mc_signer_id [8];
	uint32_t mc_cert_id;         /* serial number */
	uint32_t mc_valid_to;        /* minutes since 1 Jan 1970 00:00 UTC */
	uint8_t  mc_subject_id[16];
	uint8_t  mc_public_key[65];
	uint8_t  mc_subject_id_len;
	uint8_t  mc_subject_type;
	uint8_t  mc_signature_len;
	uint8_t  mc_signature [72];
} __attribute__((packed)); /* Total len: 180 bytes */
#endif

struct mCert_cache_entry {
	uint8_t valid;
	struct mCert mCert;
} __attribute__((packed));

enum mc_states {
	MC_CACHE_EMPTY,
	MC_CACHE_NORMAL,
	MC_CACHE_FULL,
};

enum mc_types {
	MCERT_TYPE_ROOT = 0,
	MCERT_TYPE_NOTROOT,
};

#ifdef LINUX
typedef enum error_t_ {
	MC_CACHE_MATCH=0,
	ERR_OK = 0,
	ERR_MC_CACHE_GEN_ERROR = -1,
	ERR_MC_CACHE_ALREADY_EXIST = -2,
	ERR_MC_CACHE_NO_ROOT_MCERT = -3,
	ERR_MC_CACHE_NOT_EMPTY = -4,
	ERR_MC_CACHE_NOTHING_TO_DELETE = -5,
	ERR_MC_CACHE_CANT_DELETE_ROOTCERT = -6,
	ERR_MC_CACHE_LOCK_ERROR = -7,
	ERR_MC_CACHE_UNLOCK_ERROR = -8,
	ERR_MC_CACHE_INVALID_SLOT_TOFIND = -9,
	ERR_MC_CACHE_FIND_NO_MATCH = -10,
	ERR_MC_CACHE_CERT_EXPIRED = -11,
	ERR_MC_CACHE_CERT_NO_ISSUER = -12,
	ERR_MC_CACHE_CERT_SIGN_INVALID = -13,
	ERR_MC_CACHE_FULL = -14,
}error_t;
#endif

struct compare_mcert_parms
{
	#define MCERT_CMP_PARM_SYS_ID		1<<0
	#define MCERT_CMP_PARM_SIGNER_ID	1<<1
	#define MCERT_CMP_PARM_CERT_ID		1<<2
	#define MCERT_CMP_PARM_VALID_TO		1<<3
	#define MCERT_CMP_PARM_SUBJECT_ID	1<<4
	#define MCERT_CMP_PARM_PUBLIC_KEY	1<<5
	#define MCERT_CMP_PARM_SUBJECT_IDLEN	1<<6
	#define MCERT_CMP_PARM_SUBJECT_TYPE	1<<7
	#define MCERT_CMP_PARM_SIGNATURE_LEN	1<<8
	#define MCERT_CMP_PARM_SIGNATURE	1<<9
	#define MCERT_CMP_PARM_SUBJECT_ID_MACADDR_BC	1<<10
	#define MCERT_CMP_PARM_SUBJECT_ID_MACADDR_DL	1<<11
	#define MCERT_CMP_PARM_FIND_ISSUER	1<<12

	#define MCERT_CMP_PARAM_ALL 		0xFFFF
	#define MCERT_CMP_PARAM_SYSID_CERTID	(MCERT_CMP_PARM_SYS_ID|MCERT_CMP_PARM_CERT_ID)
	#define MCERT_CMP_PARM_DELETE_ITEM	0xFFFE

	uint16_t bitmap;
};

/*Debug macros */
#define MCERT_CACHE_DEBUG
#ifdef LINUX
#ifdef MCERT_CACHE_DEBUG
#define MC_DEBUG(fmt, ...)    		do { fprintf(stdout, fmt, __VA_ARGS__); } while (0)
#else
#define MC_DEBUG(fmt, ...)		do { } while(0)
#endif
#define MC_ERR(fmt, ...)		do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)
#define MC_INFO(fmt, ...)		do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)
#else
#define MC_DEBUG(fmt, ...)		do { } while(0)
#define MC_ERR(fmt, ...)		do { } while(0)
#define MC_INFO(fmt, ...)		do { } while(0)
#endif

#define OFFSET_OF(type, element) ((size_t)&(((type *)0)->element))

/* API prototypes */
error_t cache_find_cert(const struct mCert *pcert, uint16_t *slot);
error_t cache_find_by_certID(uint32_t systemID, uint32_t certID, struct mCert *pcert, uint16_t *slot);
error_t cache_find_by_public_key(const uint8_t * x_value, struct mCert *pcert, uint16_t *slot);
error_t cache_find_BC_by_MAC_address(const uint8_t *MAC_addr, struct mCert *pcert, uint16_t *slot);
error_t cache_find_DL_by_MAC_address(const uint8_t *MAC_addr, struct mCert *pcert, uint16_t *slot);
error_t cache_find_by_subjectIDtype(uint8_t subjectIDtype, struct mCert *pcert, uint16_t *slot);
error_t cache_find_by_slot_number(uint16_t slot_num, struct mCert *pcert, uint16_t *slot);

error_t cache_delete_entry(uint16_t slot_num);
error_t cache_insert_cert(struct mCert *pcert, uint16_t *slot);
error_t cache_check_sanity(void);
error_t cache_find_issuer(const struct mCert *src, struct mCert *pcert, uint16_t *slot);
error_t cache_store_index(void);

//externs
extern struct mCert_cache_entry mcert_cache[TOTAL_MCERT_SLOTS];
extern uint8_t free_list_start;
extern uint8_t mc_index[TOTAL_MCERT_SLOTS];
extern uint8_t to_delete_list[TOTAL_MCERT_SLOTS];
extern uint8_t to_delete_count;

extern char *get_errstr(error_t e);
extern error_t mc_cache_init();
extern error_t mc_cache_uninit();

#endif /* _MC_CACHE_H_ */

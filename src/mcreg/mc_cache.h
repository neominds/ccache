/* 
 * mc_cache.h
 * Copyright SilverSpring Networks 2018.
 * All rights reserved.
 *
 */

#ifndef _MC_CACHE_H_
#define _MC_CACHE_H_

#ifdef LINUX
#include "asn.h"

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

#if 0
typedef uint16_t word16;
typedef uint8_t byte;
#define MAX_CERT_ROLES_LINUX	4

struct CertElement {
    uint16_t      idx;    /* offset from cert->source */
    uint16_t      len;
};

typedef struct CertElement CertElement;

struct DecodedCert {
    const uint8_t*   source;            /* byte buffer holder cert, NOT owner */
    uint16_t  srcIdx;                  /* current offset into buffer         */
    uint16_t  maxIdx;                  /* offset one past end of buffer      */
/* specific bytes values */
    uint8_t    structVersion;
    uint8_t    certVersion;
    uint8_t    flags;
    uint8_t    privateID;
    CertElement   Certificate;       /* With DER encoding                  */
/* Certificate contents */
    CertElement   tbsCertificate;    /* With DER encoding                  */
    CertElement   signatureAlgorithm;/* With DER encoding                  */
    CertElement   signatureValue;    /* decoded value of bit string        */
/* tbsCertificate contents */
    /* version stored above. */
    CertElement   serialNumber;
    CertElement   signature;         /* Alg id */
    CertElement   issuer;
    /* validity stored below CertElements. */
    CertElement   subject;
//  CertElement   subjectPublicKeyInfo;
//  CertElement   issuerUniqueID;
//  CertElement   subjectUniqueID;
    CertElement   extensions;
/* parts of subjectPublicKeyInfo */
    CertElement   algorithm;
    CertElement   subjectPublicKey;
/* Specific extensions */
//  CertElement   BasicCaConstraint;
//  CertElement   AuthInfo;
    CertElement   AltNames;
    CertElement   AuthKeyID;
    CertElement   SubjKeyID;
    CertElement   Policies;
    CertElement   Role;
    CertElement   MultiRole;
/* Specific word16 values */
    uint16_t  signatureOID;            /* sum of algorithm object id       */
    uint16_t  keyOID;                  /* sum of key algo  object id       */

    long    notBefore;          /* should be time_t */
    long    notAfter;           /* should be time_t */
    uint8_t    certHash[32];
    uint8_t    num_roles;
    uint8_t    roles[MAX_CERT_ROLES_LINUX];
};  // 136 bytes

typedef struct DecodedCert DecodedCert;

struct CertBuffer {
    struct DecodedCert  dc;     // 136 bytes
    uint8_t   buffer[1024 - sizeof(struct DecodedCert)];  // 888 bytes
};  // 1024 bytes

typedef struct CertBuffer CertBuffer;
#endif

#define MCERT_CACHE_DEBUG
#ifdef MCERT_CACHE_DEBUG
#define MC_DEBUG(fmt, ...)    		do { fprintf(stdout, fmt, __VA_ARGS__); } while (0)
#else
#define MC_DEBUG(fmt, ...)		do { } while(0)
#endif

#define MC_ERR(fmt, ...)		do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)
#define MC_INFO(fmt, ...)		do { fprintf(stderr, fmt, __VA_ARGS__); } while (0)


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

#define NUM_OF_NONROOT_MCERT_SLOTS      159
#define INDEX_SLOT                      0
#define ROOT_CERT_SLOT                 1
#define FIRST_NON_ROOT_MCERT            2
#define TOTAL_MCERT_SLOTS               NUM_OF_NONROOT_MCERT_SLOTS + 1 + 1 //root+ index

#define IN
#define OUT
#define INOUT
#define API

#define CERT_ENTRY_VALID		1
#define CERT_ENTRY_INVALID		0
#define ALTNAME_LEN_MACADDR 		8
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

/*
struct mCert_cache_entry {
	uint8_t valid;
	CertBuffer mCert;
} __attribute__((packed));
*/

struct CertBuffer_cache_entry {
	uint8_t valid;
	struct CertBuffer cb;
} __attribute__((packed));

typedef struct CertBuffer_cache_entry CertBuffer_cache_entry;

enum mc_types {
	MCERT_TYPE_ROOT = 0,
	MCERT_TYPE_NOTROOT,
};


struct compare_cert_parms
{
#define CERT_CMP_PARM_SYS_ID		1<<0
#define CERT_CMP_PARM_SIGNER_ID	1<<1
#define CERT_CMP_PARM_CERT_ID		1<<2
#define CERT_CMP_PARM_VALID_TO		1<<3
#define CERT_CMP_PARM_SUBJECT_ID	1<<4
#define CERT_CMP_PARM_PUBLIC_KEY	1<<5
#define CERT_CMP_PARM_SUBJECT_IDLEN	1<<6
#define CERT_CMP_PARM_SUBJECT_TYPE	1<<7
#define CERT_CMP_PARM_SIGNATURE_LEN	1<<8
#define CERT_CMP_PARM_SIGNATURE	1<<9
#define CERT_CMP_PARM_MACADDR_BC	1<<10
#define CERT_CMP_PARM_MACADDR_DL 	1<<11
#define CERT_CMP_PARM_FIND_ISSUER	1<<12
#define CERT_CMP_PARAM_ISSUER_SERIALNO	1<<12
#define CERT_CMP_PARAM_ISSUER_AND_SERIAL	1<<13
#define CERT_CMP_PARAM_SUBJECT_AND_SKID	1<<14
#define CERT_CMP_PARAM_OPERATOR_CERT	1<<15

#define CERT_CMP_PARAM_ALL 		0xFFFF
#define CERT_CMP_PARAM_SYSID_CERTID	(CERT_CMP_PARM_SYS_ID|CERT_CMP_PARM_CERT_ID)
#define CERT_CMP_PARM_DELETE_ITEM	0xFFFE

	uint16_t bitmap;
	uint8_t *serial;
	unsigned serial_bytes;
	uint8_t *skid;
	unsigned skid_bytes;
	uint8_t *name;
	unsigned name_bytes;

};

/*Debug macros */
/*
#define MCERT_CACHE_DEBUG
#ifdef MCERT_CACHE_DEBUG
//TODO
#define MC_DEBUG(fmt, ...)		do { } while(0)
#define MC_ERR(fmt, ...)		do { } while(0)
#define MC_INFO(fmt, ...)		do { } while(0)
#endif
*/

#define OFFSET_OF(type, element) ((size_t)&(((type *)0)->element))

/* API prototypes */
error_t cache_find_cert(const CertBuffer *pcert, OUT uint16_t *slot);
error_t cache_find_by_issuer_and_serial(const uint8_t *issuer, unsigned issuer_bytes, const uint8_t *serial, unsigned serial_bytes, CertBuffer *pcert, OUT uint16_t *slot);
error_t cache_find_by_subject_and_SKID(const uint8_t *subject, unsigned subject_bytes, const uint8_t *skid, unsigned skid_bytes, CertBuffer *pcert, INOUT uint16_t *slot);
error_t cache_find_BC_by_MAC_address(const uint8_t *MAC_addr, CertBuffer *pcert, OUT uint16_t *slot);
error_t cache_find_DL_by_MAC_address(const uint8_t *MAC_addr, CertBuffer *pcert, OUT uint16_t *slot);
error_t cache_find_next_operator_cert(CertBuffer *pcert, INOUT uint16_t *slot);
error_t cache_find_by_slot_number(uint16_t slot_num, CertBuffer *pcert);

error_t cache_delete_entry(uint16_t slot_num);

error_t cache_insert_cert(CertBuffer *pcert, OUT uint16_t *slot);

error_t cache_check_sanity(void);
error_t cache_find_issuer(const CertBuffer *psubject, CertBuffer *pissuer, INOUT uint16_t *slot);
error_t cache_store_index(void);

error_t mc_cache_init();
error_t mc_cache_uninit();

//error_t cert_cache_read_cert(CertBuffer *cert, uint8_t slotno);
//error_t cert_cache_write_cert(CertBuffer *cert, uint8_t slotno);
//error_t cert_cache_delete_cert(uint8_t slotno);

#endif /* _MC_CACHE_H_ */

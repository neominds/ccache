#ifndef _X509_READ_H_
#define _X509_READ_H_
#include "types.h"

struct DecodedCert {
    byte*   publicKey;
    word32  pubKeySize;
    int     pubKeyStored;
    word32  certBegin;               /* offset to start of cert          */
    word32  sigIndex;                /* offset to start of signature     */
    word32  sigLength;               /* length of signature              */
    word32  signatureOID;            /* sum of algorithm object id       */
    word32  keyOID;                  /* sum of key algo  object id       */
    int     version;                 /* cert version, 1 or 3             */
    DNS_entry* altNames;             /* alt names list of dns entries    */
#ifndef IGNORE_NAME_CONSTRAINTS
    DNS_entry* altEmailNames;        /* alt names list of RFC822 entries */
    Base_entry* permittedNames;      /* Permitted name bases             */
    Base_entry* excludedNames;       /* Excluded name bases              */
#endif /* IGNORE_NAME_CONSTRAINTS */
    byte    subjectHash[KEYID_SIZE]; /* hash of all Names                */
    byte    issuerHash[KEYID_SIZE];  /* hash of all Names                */
#ifdef HAVE_OCSP
    byte    issuerKeyHash[KEYID_SIZE]; /* hash of the public Key         */
#endif /* HAVE_OCSP */
    byte*   signature;               /* not owned, points into raw cert  */
    char*   subjectCN;               /* CommonName                       */
    int     subjectCNLen;            /* CommonName Length                */
    char    subjectCNEnc;            /* CommonName Encoding              */
    int     subjectCNStored;         /* have we saved a copy we own      */
    char    issuer[ASN_NAME_MAX];    /* full name including common name  */
    char    subject[ASN_NAME_MAX];   /* full name including common name  */
    int     verify;                  /* Default to yes, but could be off */
    byte*   source;                  /* byte buffer holder cert, NOT owner */
    word32  srcIdx;                  /* current offset into buffer       */
    word32  maxIdx;                  /* max offset based on init size    */
    void*   heap;                    /* for user memory overrides        */
    byte    serial[EXTERNAL_SERIAL_SIZE];  /* raw serial number          */
    int     serialSz;                /* raw serial bytes stored */
    byte*   extensions;              /* not owned, points into raw cert  */
    int     extensionsSz;            /* length of cert extensions */
    word32  extensionsIdx;           /* if want to go back and parse later */
    byte*   extAuthInfo;             /* Authority Information Access URI */
    int     extAuthInfoSz;           /* length of the URI                */
    byte*   extCrlInfo;              /* CRL Distribution Points          */
    int     extCrlInfoSz;            /* length of the URI                */
    byte    extSubjKeyId[KEYID_SIZE]; /* Subject Key ID                  */
    byte    extSubjKeyIdSet;         /* Set when the SKID was read from cert */
    byte    extAuthKeyId[KEYID_SIZE]; /* Authority Key ID                */
    byte    extAuthKeyIdSet;         /* Set when the AKID was read from cert */
#ifndef IGNORE_NAME_CONSTRAINTS
    byte    extNameConstraintSet;
#endif /* IGNORE_NAME_CONSTRAINTS */
    byte    isCA;                    /* CA basic constraint true         */
    byte    pathLengthSet;           /* CA basic const path length set   */
    byte    pathLength;              /* CA basic constraint path length  */
    byte    weOwnAltNames;           /* altNames haven't been given to copy */
    byte    extKeyUsageSet;
    word16  extKeyUsage;             /* Key usage bitfield               */
    byte    extExtKeyUsageSet;       /* Extended Key Usage               */
    byte    extExtKeyUsage;          /* Extended Key usage bitfield      */
#ifdef OPENSSL_EXTRA
    byte    extCRLdistSet;
    byte    extCRLdistCrit;
    byte    extAuthInfoSet;
    byte    extAuthInfoCrit;
    byte    extBasicConstSet;
    byte    extBasicConstCrit;
    byte    extSubjAltNameSet;
    byte    extSubjAltNameCrit;
    byte    extAuthKeyIdCrit;
#ifndef IGNORE_NAME_CONSTRAINTS
    byte    extNameConstraintCrit;
#endif /* IGNORE_NAME_CONSTRAINTS */
    byte    extSubjKeyIdCrit;
    byte    extKeyUsageCrit;
    byte    extExtKeyUsageCrit;
    byte*   extExtKeyUsageSrc;
    word32  extExtKeyUsageSz;
    word32  extExtKeyUsageCount;
    byte*   extAuthKeyIdSrc;
    word32  extAuthKeyIdSz;
    byte*   extSubjKeyIdSrc;
    word32  extSubjKeyIdSz;
#endif
#if defined(HAVE_ECC) || defined(HAVE_ED25519)
    word32  pkCurveOID;           /* Public Key's curve OID */
#endif /* HAVE_ECC */
    byte*   beforeDate;
    int     beforeDateLen;
    byte*   afterDate;
    int     afterDateLen;
#ifdef HAVE_PKCS7
    byte*   issuerRaw;               /* pointer to issuer inside source */
    int     issuerRawLen;
#endif
#ifndef IGNORE_NAME_CONSTRAINT
    byte*   subjectRaw;               /* pointer to subject inside source */
    int     subjectRawLen;
#endif
#if defined(WOLFSSL_CERT_GEN)
    /* easy access to subject info for other sign */
    char*   subjectSN;
    int     subjectSNLen;
    char    subjectSNEnc;
    char*   subjectC;
    int     subjectCLen;
    char    subjectCEnc;
    char*   subjectL;
    int     subjectLLen;
    char    subjectLEnc;
    char*   subjectST;
    int     subjectSTLen;
    char    subjectSTEnc;
    char*   subjectO;
    int     subjectOLen;
    char    subjectOEnc;
    char*   subjectOU;
    int     subjectOULen;
    char    subjectOUEnc;
    char*   subjectEmail;
    int     subjectEmailLen;
#endif /* WOLFSSL_CERT_GEN */
#ifdef OPENSSL_EXTRA
    DecodedName issuerName;
    DecodedName subjectName;
#endif /* OPENSSL_EXTRA */
#ifdef WOLFSSL_SEP
    int     deviceTypeSz;
    byte*   deviceType;
    int     hwTypeSz;
    byte*   hwType;
    int     hwSerialNumSz;
    byte*   hwSerialNum;
    #ifdef OPENSSL_EXTRA
        byte    extCertPolicySet;
        byte    extCertPolicyCrit;
    #endif /* OPENSSL_EXTRA */
#endif /* WOLFSSL_SEP */
#ifdef WOLFSSL_CERT_EXT
    char    extCertPolicies[MAX_CERTPOL_NB][MAX_CERTPOL_SZ];
    int     extCertPoliciesNb;
#endif /* WOLFSSL_CERT_EXT */

    Signer* ca;
    SignatureCtx sigCtx;
};



#endif


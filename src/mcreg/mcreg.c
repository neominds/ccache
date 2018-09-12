#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <mc_cache.h>
#include <mc_cache_flash.h>
#include <asn.h>

#define OPENSSL

#ifdef OPENSSL
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/sha.h> // for SHA256
#endif

#ifdef LINUX
#include <arpa/inet.h>
#endif

#define RESULT_PASS 0
#define RESULT_FAIL	1

//tokens
#define TOKEN_EXPECT 		1
#define TOKEN_PASS		2
#define TOKEN_FAIL		3
#define TOKEN_EDITBUF		5
#define TOKEN_INSERT		6
#define TOKEN_DELETE		9
#define TOKEN_FIND		10
#define TOKEN_BYID		11
#define TOKEN_BYSLOT		12
#define TOKEN_BYPUBKEY		13
#define TOKEN_BYSUBIDTYPE	14
#define TOKEN_BCBYMAC		15
#define TOKEN_DLBYMAC		16
#define TOKEN_PRINT_INDEX	17
#define TOKEN_PRINT_CACHE	18
#define TOKEN_PRINT_MSG		19
#define TOKEN_PROMPT		20
#define TOKEN_EXIT		21
#define TOKEN_PRINT_CERT	22
#define TOKEN_ISSUER		23
#define TOKEN_CREATE		24
#define TOKEN_SIGN		25
#define TOKEN_USING		26
#define TOKEN_SELF		27
#define TOKEN_CHECK_SANITY 	28
#define TOKEN_NEWPAIR		29
#define TOKEN_OPER		30
#define TOKEN_BYSUBJ		31
#define TOKEN_SUBJECT		32
#define TOKEN_SKID		33
#define TOKEN_SERIAL		34
#define TOKEN_PRINT_KEYSTORE	35
#define TOKEN_ADDMANY		36

#define CERT_ELEMENT_MAXLEN_SERIALNO	9//8?
#define CERT_ELEMENT_MAXLEN_SUBJECT	102
#define CERT_ELEMENT_MAXLEN_ISSUER	102
#define CERT_ELEMENT_MAXLEN_ALTNAMES	8
#define CERT_ELEMENT_MAXLEN_POLICIES	16
#define CERT_ELEMENT_MAXLEN_AUTHKEYID	20
#define CERT_ELEMENT_MAXLEN_SUBJKEYID	20
#define CERT_ELEMENT_MAXLEN_PUBKEY	65
#define CERT_ELEMENT_MAXLEN_NOTAFTER	8
#define CERT_ELEMENT_MAXLEN_SIGNATURE	72

extern void get_field_from_cert_cache(void *dest, uint16_t n, uint8_t index, uint16_t offset);
extern void get_fullcert_from_cert_cache(void *dest, uint8_t index);
void hexdump(uint8_t *p, uint32_t size);
int8_t g_strtok_current[512];
char *g_strtok_strptr;
CertBuffer ram_cert;
uint8_t der_cert[] = { 0x30,0x82,0x02,0x0c,0x30,0x82,0x01,0xb4,0xa0,0x03,0x02,0x01,0x02,0x02,0x09,0x00,0x89,0x79,0x5c,0xed,0xc9,0x18,0xc8,0x3f,0x30,0x09,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x04,0x01,0x30,0x64,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x69,0x6e,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x08,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x07,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0a,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0b,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x03,0x0c,0x02,0x6e,0x65,0x31,0x14,0x30,0x12,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01,0x16,0x05,0x6e,0x65,0x40,0x6e,0x65,0x30,0x1e,0x17,0x0d,0x31,0x38,0x30,0x33,0x30,0x37,0x31,0x32,0x31,0x37,0x31,0x39,0x5a,0x17,0x0d,0x32,0x30,0x30,0x33,0x30,0x36,0x31,0x32,0x31,0x37,0x31,0x39,0x5a,0x30,0x64,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x06,0x13,0x02,0x69,0x6e,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x08,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x07,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0a,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x0b,0x0c,0x02,0x6e,0x65,0x31,0x0b,0x30,0x09,0x06,0x03,0x55,0x04,0x03,0x0c,0x02,0x6e,0x65,0x31,0x14,0x30,0x12,0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x01,0x16,0x05,0x6e,0x65,0x40,0x6e,0x65,0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x8d,0xca,0x5d,0xf0,0xda,0xbf,0xf4,0x79,0x82,0x37,0xee,0xab,0xf0,0x4f,0xb7,0x1d,0x5e,0x96,0xb5,0x71,0xf5,0x06,0xc3,0x0b,0x07,0xce,0x79,0xbf,0x1e,0xd7,0xf2,0x03,0xb3,0x2d,0x03,0xfe,0xe0,0x93,0x2a,0x7e,0xcb,0x71,0x7e,0x62,0x44,0x24,0xcb,0x57,0xd3,0x2e,0x28,0x30,0xaa,0x01,0x0e,0x31,0x31,0x20,0x96,0xb9,0x3b,0x79,0xbe,0x22,0xa3,0x50,0x30,0x4e,0x30,0x1d,0x06,0x03,0x55,0x1d,0x0e,0x04,0x16,0x04,0x14,0x55,0x4b,0x62,0xa0,0x5d,0xfe,0xb7,0x43,0x4b,0xe5,0xbf,0xdb,0x8b,0x5e,0xe8,0xbc,0x45,0xf3,0x64,0x08,0x30,0x1f,0x06,0x03,0x55,0x1d,0x23,0x04,0x18,0x30,0x16,0x80,0x14,0x55,0x4b,0x62,0xa0,0x5d,0xfe,0xb7,0x43,0x4b,0xe5,0xbf,0xdb,0x8b,0x5e,0xe8,0xbc,0x45,0xf3,0x64,0x08,0x30,0x0c,0x06,0x03,0x55,0x1d,0x13,0x04,0x05,0x30,0x03,0x01,0x01,0xff,0x30,0x09,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x04,0x01,0x03,0x47,0x00,0x30,0x44,0x02,0x20,0x5b,0x84,0x3b,0xd1,0x6f,0x47,0x80,0xa2,0xf6,0x7a,0x9d,0xad,0x84,0xda,0x31,0x41,0x87,0x50,0xe4,0x4e,0x8d,0x65,0xb7,0x2f,0x2f,0xaf,0x99,0x7b,0x02,0xad,0x2b,0xdc,0x02,0x20,0x59,0xb9,0x40,0xfe,0x11,0xfd,0xd9,0x71,0x33,0xae,0xdb,0x45,0x30,0x45,0xec,0xa6,0x74,0x8f,0xdf,0x08,0xd7,0x98,0x43,0xb2,0xf6,0xd5,0xed,0x84,0x49,0xdc,0x2a,0x0f };

int8_t line[512];
uint8_t cdf_line[256];

#ifdef OPENSSL
EC_KEY *ram_cert_eckey;
#define KEY_STORE_SIZE 160
struct ec_key_store {
	uint8_t serialNumber[CERT_ELEMENT_MAXLEN_SERIALNO];
	uint8_t subject[CERT_ELEMENT_MAXLEN_SUBJECT];
	uint8_t issuer[CERT_ELEMENT_MAXLEN_SUBJECT];
	uint8_t subjkeyid[CERT_ELEMENT_MAXLEN_SUBJKEYID];
	uint8_t authkeyid[CERT_ELEMENT_MAXLEN_AUTHKEYID];
	uint8_t slot_no;
	EC_KEY *eckey;
	uint8_t pubkey[CERT_ELEMENT_MAXLEN_PUBKEY];
	uint8_t valid; // tells whether the slot is empty or used
} key_store[KEY_STORE_SIZE];
#define VALID 1
#define INVALID 0
#define KEY_STORE_FULL 15
#define KEY_STORE_ERROR 16
#define FOUND 1
#define NOT_FOUND 0
void print_keystore();
uint8_t find_keypair_from_store(uint8_t *serialNumber);
uint8_t delete_keypair_from_store();
uint8_t is_slot_in_used_list(uint8_t slot); 

error_t CheckmCertValidity(CertBuffer *pcert);

error_t CheckmCertValidity(CertBuffer *pcert)
{
#ifdef LINUX
	time_t curr;
	curr = time(NULL);
	if (curr) {
		//TODO: compare x.509 notAfter (pcert->notAfter) to curr.
		if (curr >= pcert->dc.notBefore && curr <= pcert->dc.notAfter)
			return ERR_OK;
	}
	printf("CheckmCertValidity: mCert expired.\n");
	return ERR_MC_CACHE_CERT_EXPIRED;
#endif
}

void clear_ec_key_store()
{
	uint8_t i;

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID)
		EC_KEY_free(key_store[i].eckey);
	}
}

error_t mCertVerifySignature(CertBuffer *pcert, CertBuffer *issuer)
{
	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	uint8_t  verify_result;
	EC_KEY *sign_key;
	uint8_t i;

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, pcert->buffer + pcert->dc.tbsCertificate.idx, pcert->dc.tbsCertificate.len);
	SHA256_Final(hash, &sha256);

	//printf("dbg==> Verify hash:");
	//hexdump(hash, SHA256_DIGEST_LENGTH);

	//find eckey in key_store corresponding to issuer
	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
		if (!memcmp(key_store[i].serialNumber, issuer->buffer + issuer->dc.serialNumber.idx, issuer->dc.serialNumber.len))
			sign_key = key_store[i].eckey;
		}
	}

	verify_result = ECDSA_verify(0,hash,SHA256_DIGEST_LENGTH,
			pcert->buffer + pcert->dc.signatureValue.idx, pcert->dc.signatureValue.len, sign_key);

	if (1 != verify_result) {
		printf("Failed to verify EC Signature\n");
		return ERR_MC_CACHE_CERT_SIGN_INVALID;
	}
	else
		return ERR_OK;

	printf("Issuer cert not found.\n");
	return ERR_MC_CACHE_CERT_SIGN_INVALID;
}

int8_t create_new_ec_key_pair(EC_KEY **eckey, uint8_t *pubkey)
{
	const EC_POINT *ecpoint;	
	EC_GROUP *ecgroup;
	uint8_t set_group_status;
	uint8_t gen_status; 

	*eckey = EC_KEY_new();
	if (*eckey == NULL) {
		printf("EC_KEY_new() failed\n");
		return 1;
	}
	ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1);
	if (ecgroup == NULL) {
		printf("EC_GROUP_new_by_curve() failed\n");
		return 1;
	}
	set_group_status = EC_KEY_set_group(*eckey,ecgroup);
	if (set_group_status != 1) {
		printf("EC_KEY_set_group() failed\n");
		return 1;
	} 
	gen_status = EC_KEY_generate_key(*eckey);
	if (gen_status != 1) {
		printf("EC_KEY_generate_key() failed\n");
		return 1;
	}
	ram_cert_eckey = *eckey;

	ecpoint = EC_KEY_get0_public_key(*eckey);
	BN_CTX *ctx= BN_CTX_new();
	uint8_t pubkey_len = EC_POINT_point2oct(ecgroup,ecpoint, POINT_CONVERSION_UNCOMPRESSED, pubkey,65,ctx);

	if (pubkey_len > ram_cert.dc.subjectPublicKey.len) {
		printf("pubkey too big.\n");
		return 1;
	}

	return 0;
}

uint8_t add_keypair_to_store(uint8_t *serialNumber, uint8_t *subject, EC_KEY *eckey,uint8_t *pubkey, uint8_t *subjkeyid )
{
	uint8_t i,found=0;

	//check if item already exit- overwrite is exit
	for(i = 0;i < KEY_STORE_SIZE;i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)){
				found = 1;
				break;	
			}
		}
	
	}
	//check for free entry
	if(!found){
		for(i = 0;i < KEY_STORE_SIZE;i++)
			if(key_store[i].valid == INVALID) break;
		if(i == KEY_STORE_SIZE) return KEY_STORE_FULL;
	}
	//add to the list
	memcpy(&(key_store[i].serialNumber), serialNumber, CERT_ELEMENT_MAXLEN_SERIALNO); 
	memcpy(&(key_store[i].subject), subject, CERT_ELEMENT_MAXLEN_SUBJECT); 
	memcpy(&(key_store[i].subjkeyid), subjkeyid, CERT_ELEMENT_MAXLEN_SUBJKEYID); 
	key_store[i].eckey = eckey;
	memcpy(key_store[i].pubkey,pubkey,sizeof(key_store[i].pubkey));
	key_store[i].valid = VALID;	

	return 0;
}

extern uint8_t used_list_head;
extern uint8_t free_list_head;
extern struct _mc_list used_list[TOTAL_MCERT_SLOTS];
extern struct _mc_list free_list[TOTAL_MCERT_SLOTS];

uint8_t delete_keypair_from_store()
{
	uint8_t i;
	for(i = 0;i < KEY_STORE_SIZE;i++){
			if(key_store[i].valid == VALID){
				if(!is_slot_in_used_list(key_store[i].slot_no))
				{
					key_store[i].valid = INVALID;
				}
			}	
	}
//	else return KEY_STORE_ERROR;
	
return 0;

}

uint8_t is_slot_in_used_list(uint8_t slot) 
{ 
	uint8_t curr = used_list_head;
	 while (curr != 0xFF) 
		{
			 if (used_list[curr].cache_slot == slot) 
			 return FOUND; 
			 curr = used_list[curr].next;
	 	}
	 return NOT_FOUND; 
}

uint8_t find_keypair_from_store(uint8_t *serialNumber)
{
	uint8_t i,found=0;
	for(i = 0;i < KEY_STORE_SIZE;i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)){
				found = 1;
				break;	
			}
		}
	
	}
	if(found) 
		printf("The serialNumber entry available in the list\n");
	else return KEY_STORE_ERROR;
	
return 0;
}
static void update_issuer_to_store(uint8_t *serialNumber, uint8_t *issuer, uint8_t *authkeyid)
{
	uint8_t i;

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)) {
				memcpy(&(key_store[i].issuer), issuer, CERT_ELEMENT_MAXLEN_ISSUER); 
				memcpy(&(key_store[i].authkeyid), authkeyid, CERT_ELEMENT_MAXLEN_AUTHKEYID); 
			}
		}
	}
}

static error_t get_subjkeyid_from_store(uint8_t *serialNumber, uint8_t **issuer_subjkeyid)
{
	uint8_t i;

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)) {
				*issuer_subjkeyid = key_store[i].subjkeyid;
				return 0;
			}
		}
	}
	return 1;
}

static void update_slotno_to_store(uint8_t *serialNumber, uint8_t slot_no)
{
	uint8_t i;

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)) {
				key_store[i].slot_no = slot_no;
			}
		}
	}
}

uint8_t get_keypair_from_store(uint8_t *serialNumber, EC_KEY **eckey, uint8_t **pubkey, uint8_t *subject)
{
	uint8_t i;

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)) {
				*eckey = key_store[i].eckey;
				*pubkey = key_store[i].pubkey;
				memcpy(subject, key_store[i].subject, CERT_ELEMENT_MAXLEN_SUBJECT);
				return 0;
			}
		}
	}

	return 1;
}

uint8_t get_issuer_from_store(uint8_t *serialNumber, uint8_t *issuer)
{
	uint8_t i;

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(key_store[i].serialNumber, serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO)) {
				memcpy(issuer, key_store[i].issuer, CERT_ELEMENT_MAXLEN_ISSUER);
				return 0;
			}
		}
	}
	return 1;
}



uint8_t sign_cert(CertBuffer *pcert, EC_KEY *eckey, uint8_t *pubkey,uint8_t *issuer, uint8_t *authkeyid)
{
	//do hash and sign
	ECDSA_SIG *signature = NULL;
	uint8_t hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	uint8_t siglen=0;
	unsigned char temp[72];
	unsigned char* psig = NULL;
	int i;

	//update issuer  & AuthKeyID before hash
	memcpy(pcert->buffer+pcert->dc.issuer.idx, issuer, CERT_ELEMENT_MAXLEN_SUBJECT);
	memcpy(pcert->buffer+pcert->dc.AuthKeyID.idx, authkeyid, CERT_ELEMENT_MAXLEN_AUTHKEYID);

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, pcert->buffer + pcert->dc.tbsCertificate.idx, pcert->dc.tbsCertificate.len);
	SHA256_Final(hash, &sha256);

	//printf("sign dbg==> hash:");
	//hexdump(hash, SHA256_DIGEST_LENGTH);

	signature = ECDSA_do_sign(hash, SHA256_DIGEST_LENGTH, eckey);
	if (signature == NULL)
	{
		printf("Error ECDSA_do_sign()\n");
		return 1;
	}

	for (i = 0; i < KEY_STORE_SIZE; i++){
		if(key_store[i].valid == VALID){
			if (!memcmp(pcert->buffer + pcert->dc.serialNumber.idx, key_store[i].serialNumber, CERT_ELEMENT_MAXLEN_SERIALNO)) {
				memcpy(key_store[i].issuer, issuer, CERT_ELEMENT_MAXLEN_SUBJECT); 
			}
		}
	}

	memset(temp, 0, sizeof(temp));
	psig = temp;
	siglen = i2d_ECDSA_SIG(signature,&psig);
	if (siglen > 0 && siglen <= CERT_ELEMENT_MAXLEN_SIGNATURE ) {
		memcpy(pcert->buffer + pcert->dc.signatureValue.idx, temp, siglen);
		pcert->dc.signatureValue.len = siglen;
		//printf("sign dbg==> siglen %d, signature:",siglen);
		//hexdump(pcert->buffer + pcert->dc.signatureValue.idx, siglen);
	}
	else{
		printf("Error coverting to DER form %d.\n",siglen);
		return 1;
	}
	return 0;
}
#endif

uint8_t get_token_id(char *string)
{
	if (!strcasecmp(string, "expect")) return TOKEN_EXPECT;
	if (!strcasecmp(string, "pass")) return TOKEN_PASS;
	if (!strcasecmp(string, "fail")) return TOKEN_FAIL;
	if (!strcasecmp(string, "editbuf")) return TOKEN_EDITBUF;
	if (!strcasecmp(string, "insert")) return TOKEN_INSERT;
	if (!strcasecmp(string, "delete")) return TOKEN_DELETE;
	if (!strcasecmp(string, "find")) return TOKEN_FIND;
	if (!strcasecmp(string, "byid")) return TOKEN_BYID;
	if (!strcasecmp(string, "byslot")) return TOKEN_BYSLOT;
	if (!strcasecmp(string, "bcbymac")) return TOKEN_BCBYMAC;
	if (!strcasecmp(string, "dlbymac")) return TOKEN_DLBYMAC;
	if (!strcasecmp(string, "issuer")) return TOKEN_ISSUER;
	if (!strcasecmp(string, "create")) return TOKEN_CREATE;
	if (!strcasecmp(string, "sign")) return TOKEN_SIGN;
	if (!strcasecmp(string, "using")) return TOKEN_USING;
	if (!strcasecmp(string, "self")) return TOKEN_SELF;
	if (!strcasecmp(string, "check_sanity")) return TOKEN_CHECK_SANITY;
	if (!strcasecmp(string, "addmany")) return TOKEN_ADDMANY;

	if (!strcasecmp(string, "oper")) return TOKEN_OPER;
	if (!strcasecmp(string, "bysubj")) return TOKEN_BYSUBJ;
	if (!strcasecmp(string, "subject")) return TOKEN_SUBJECT;
	if (!strcasecmp(string, "skid")) return TOKEN_SKID;
	if (!strcasecmp(string, "serial")) return TOKEN_SKID;

	if (!strcasecmp(string, "print_index")) return TOKEN_PRINT_INDEX;
	if (!strcasecmp(string, "print_cache")) return TOKEN_PRINT_CACHE;
	if (!strcasecmp(string, "print_cert")) return TOKEN_PRINT_CERT;
	if (!strcasecmp(string, "print")) return TOKEN_PRINT_MSG;
	if (!strcasecmp(string, "print_keystore")) return TOKEN_PRINT_KEYSTORE; //keystore print

	if (!strcasecmp(string, "prompt")) return TOKEN_PROMPT;
	if (!strcasecmp(string, "exit")) return TOKEN_EXIT;

	return 0;
}


void strip_last_newline(char *string)
{
	if (!string) return;
	uint32_t j = strlen(string);
	for (; j; j--)
		if (string[j] == '\n') string[j] = '\0';
}

char *get_first_token(char *string)
{
	char *retstr;

	memcpy(g_strtok_current, string, 512);
	g_strtok_strptr = string;
	retstr = strtok((char *)g_strtok_current," ;");
	if (retstr && strstr(retstr,"\n"))
		strip_last_newline(retstr);

	return retstr;
}

char *get_next_token(char *string)
{
	char *retstr;

	if (g_strtok_strptr != string) {
		printf("Incorrect current string.\n");
		return NULL;
	}
	retstr = strtok(NULL," ");
	if (retstr && strstr(retstr,"\n"))
		strip_last_newline(retstr);

	return retstr;
}
void hexdump(uint8_t *p, uint32_t size)
{
	while (size--) printf("%02x",*p++);
	printf("\n");
}

void sscan_octets(void *string, void *dest, uint8_t no_of_octets)
{
	uint8_t i, *cursor;

	for (i=0; i < no_of_octets; i++) {
		cursor = ((uint8_t *)(dest)) + i;
		sscanf((char *)string + i*2,"%2hhx",cursor);
	}
}

#ifdef PRINT_CERT_ELEMENTS
static inline void print_cert_element(int idx,int len)
{
	printf("offset=%03d  len=%03d\n",idx,len);
}

static void print_cert_elements(CertBuffer *cb)
{
	printf("\nCertBuffer@%p\n",cb);
	printf("CertBuff->Certificate:        ");print_cert_element(cb->dc.Certificate.idx,cb->dc.Certificate.len);
	printf("CertBuff->tbsCertificate:     ");print_cert_element(cb->dc.tbsCertificate.idx,cb->dc.tbsCertificate.len);
	printf("CertBuff->signatureAlgorithm: ");print_cert_element(cb->dc.signatureAlgorithm.idx,cb->dc.signatureAlgorithm.len);
	printf("CertBuff->signatureValue:     ");print_cert_element(cb->dc.signatureValue.idx,cb->dc.signatureValue.len);
	printf("CertBuff->serialNumber:       ");print_cert_element(cb->dc.serialNumber.idx,cb->dc.serialNumber.len);
	printf("CertBuff->signature(signAlgoID): ");print_cert_element(cb->dc.signature.idx,cb->dc.signature.len);
	printf("CertBuff->issuer:             ");print_cert_element(cb->dc.issuer.idx,cb->dc.issuer.len);
	printf("CertBuff->subject:            ");print_cert_element(cb->dc.issuer.idx,cb->dc.issuer.len);
	printf("CertBuff->algorithm(PubKeyAlgo): ");print_cert_element(cb->dc.algorithm.idx,cb->dc.algorithm.len);
	printf("CertBuff->subjectPublicKey:   ");print_cert_element(cb->dc.subjectPublicKey.idx,cb->dc.subjectPublicKey.len);
	printf("CertBuff->extensions:         ");print_cert_element(cb->dc.extensions.idx,cb->dc.extensions.len);
	printf("CertBuff->AltNames:           ");print_cert_element(cb->dc.AltNames.idx,cb->dc.AltNames.len);
	printf("CertBuff->AuthKeyID:          ");print_cert_element(cb->dc.AuthKeyID.idx,cb->dc.AuthKeyID.len);
	printf("CertBuff->SubjKeyID:          ");print_cert_element(cb->dc.SubjKeyID.idx,cb->dc.SubjKeyID.len);
	printf("CertBuff->Policies:           ");print_cert_element(cb->dc.Policies.idx,cb->dc.Policies.len);
	printf("CertBuff->Role:               ");print_cert_element(cb->dc.Role.idx,cb->dc.Role.len);
	printf("CertBuff->MultiRole:          ");print_cert_element(cb->dc.MultiRole.idx,cb->dc.MultiRole.len);
}
#endif

char *get_algoid_string(uint8_t *signalgo, uint16_t len)
{
	uint8_t oid_ecdsa_sha1[] = {42, 134, 72, 206, 61, 4, 1 };
	if (!memcmp(signalgo+4,oid_ecdsa_sha1, 7))
		return "ecdsa-with-sha1";
	return "unknown-algo";
}

void print_pcert(CertBuffer *cb)
{
	printf("\nCertBuffer@%p\n",cb);
	printf("CertBuff->certVersion: ");hexdump((uint8_t *)&(cb->dc.certVersion), 1);
	printf("CertBuff->signAlgoID: %s\n", get_algoid_string(cb->buffer + cb->dc.signatureAlgorithm.idx, cb->dc.signatureAlgorithm.len));
	printf("CertBuff->serialNumber: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.serialNumber.idx]), cb->dc.serialNumber.len);
	printf("CertBuff->subject: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.subject.idx]), cb->dc.subject.len);
	printf("CertBuff->issuer: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.issuer.idx]), cb->dc.issuer.len);
	printf("CertBuff->algorithm: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.algorithm.idx]), cb->dc.algorithm.len);
	printf("CertBuff->subjectPublicKey: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.subjectPublicKey.idx]), cb->dc.subjectPublicKey.len);
	printf("CertBuff->AltNames: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.AltNames.idx]), cb->dc.AltNames.len);
	printf("CertBuff->AuthKeyID: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.AuthKeyID.idx]), cb->dc.AuthKeyID.len);
	printf("CertBuff->SubjKeyID: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.SubjKeyID.idx]), cb->dc.SubjKeyID.len);
	printf("CertBuff->Policies: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.Policies.idx]), cb->dc.Policies.len);
	printf("CertBuff->Role: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.Role.idx]), cb->dc.Role.len);
	printf("CertBuff->MultiRole: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.MultiRole.idx]), cb->dc.MultiRole.len);
	printf("CertBuff->valid_notBefore: ");printf("%s",ctime(&(cb->dc.notBefore)));
	printf("CertBuff->valid_notAfter : ");printf("%s",ctime(&(cb->dc.notAfter)));
	printf("CertBuff->signatureOID : ");printf("%d\n",cb->dc.signatureOID);
	printf("CertBuff->signature(Alg_id): ");hexdump((uint8_t *)&(cb->buffer[cb->dc.signature.idx]), cb->dc.signature.len);
	printf("CertBuff->signatureValue: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.signatureValue.idx]), cb->dc.signatureValue.len);
	printf("\n");
}

const char help_string[] = \
			   "mcreg [<filename>|help|prompt]\n"
			   "<filename> - name of input command file\n"
			   "help - this screen\n"
			   "prompt - no input command file. start at command prompt - default option\n"
			   "\n"
			   "General instructions for input command file:\n"
			   "1. Sequence of arguments to command MUST be same as in syntax below.\n"
			   "2. extra whitespace may cause undefined behavior\n"
			   "3. line starting with '#' IN FIRST COLUMN only is comment.\n"
			   "4. blank lines will be ignored by parser.\n"
			   "\n"
			   "GENERAL commands\n"
			   "expect pass|fail <INSERTcommand|FINDcommand|DELETEcommand|SIGNATUREcommand>\n"
			   "print_index\n"
			   "print_cache\n"
			   "print_cert [index]\n"
			   "print <string>\n"
			   "prompt\n"
			   "exit\n"
			   "\n"
			   "INSERT commands\n"
			   "insert\n"
			   "\n"
			   "EDITBUF commands\n"
			   "editbuf serial <8-octets>|*<octet>\n"
			   "editbuf subject <102-octets>|*<octet>\n"
			   "editbuf issuer <102-octets>|*<octet>\n"
			   "editbuf altnames <8-octets>|*<octet>\n"
			   "editbuf policies <8-octets>|*<octet>\n"
			   "editbuf authkeyid <16-octets>|*<octet>\n"
			   "editbuf subjkeyid <16-octets>|*<octet>\n"
			   "editbuf pubkey <65-octets>|*<octet>\n"
			   "editbuf notafter <8-octets>|*<octet>\n"
			   "\n"
			   "FIND commands\n"
			   "find\n"
			   "find byid serial <8-octets>|*<octet>\n"
			   "find byslot <slot_no>\n"
			   "find bysubj subject <102-octets>|*<octet> skid <16-octets>|*<octet>\n"
			   "find oper <slot_no>\n"
			   "find bcbymac <8-octets>|*<octet>\n"
			   "find dlbymac <8-octets>|*<octet>\n"
			   "find issuer serial <8-octets>|*<octet>\n"
			   "\n"
			   "DELETE commands\n"
			   "delete byslot <slot_no>\n"
			   "delete byid serial <8-octets>|*<octet>\n"
			   "\n"
			   "SIGNATURE commands\n"
			   "create\n"
			   "\tcreate key pair for ram_cert, store in keypair_store and set pubkey of ram_cert.\n"
			   "sign [self | using serial <8-octets>|*<octet>]\n"
			   "\tsign\n"
			   "\t\tsign using keypair of root certificate\n"
			   "\tsign using serial <8-ocetes>|*<octet>\n"
			   "\t\tsign using keypair of specified certificate\n"
			   "\tsign self\n"
			   "\t\tsign using keypair of ram_cert.\n"
			   ;

void help()
{
	printf("%s\n",help_string);
}

void parse_hexstring(void *string, void *ptr, uint8_t len)
{
	uint8_t tval;
	char *token = (char *)string;

	if (token[0] == '*') {
		sscanf(token+1,"%2hhx",&tval);
		memset(ptr,tval,len);
	}
	else
		sscan_octets(token, ptr, len);
}


void report_result(char *result, int8_t *line, uint32_t lno)
{
	if (line){
		strip_last_newline((char *)line);
		printf("!Result %s. [Line %d: %s]\n",result,lno,line);
	}
	else
		printf("%s.\n",result);
}

void check_and_report_result(error_t libret, uint8_t expected_result, int8_t *line, uint32_t lc)
{
	char fail_string[10];
	if ( 	(libret == MC_CACHE_MATCH && expected_result == RESULT_PASS) ||
			(libret == ERR_MC_CACHE_FIND_NO_MATCH && expected_result == RESULT_FAIL) ||
			(libret == ERR_OK && expected_result == RESULT_PASS) ||
			(libret != ERR_OK && expected_result == RESULT_FAIL) )
		report_result("OK",NULL,lc);
	else {
		sprintf(fail_string,"FAIL (%d)",libret);
		report_result(fail_string,line,lc);
	}
}

void print_index()
{
	struct _mc_list item;
	CertBuffer cert_local;

	//traverse used_list;
	printf("Used list:\n");
	if (used_list_head == 0xFF) {
		printf("Empty.\n");
	}
	else {
		item = used_list[used_list_head];
		while (item.next != 0xFF) {
			get_fullcert_from_cert_cache(&cert_local, item.cache_slot);
			printf("[%03u(%08lx) %03u] -> ", item.cache_slot, *((long unsigned int *)(cert_local.buffer+cert_local.dc.serialNumber.idx)), item.next);
			item = used_list[item.next];
		}
		get_fullcert_from_cert_cache(&cert_local, item.cache_slot);
		printf("[%03u(%08lx) %03u]\n", item.cache_slot, *((long unsigned int *)(cert_local.buffer+cert_local.dc.serialNumber.idx)), item.next);
	}
	//traverse free list;
	printf("Free list:\n");
	if (free_list_head == 0xFF) {
		printf("Empty.\n");
	}
	else {
		item = free_list[free_list_head];
		while (item.next != 0xFF) {
			//printf("[%03u, %03u] -> ", item.cache_slot, item.next);
			printf("[%03u]->", item.cache_slot);
			item = free_list[item.next];
		}
		//printf("[%03u, %03u]\n", item.cache_slot, item.next);
		printf("[%03u]\n", item.cache_slot);
	}

}

error_t parse_der_cert(CertBuffer *ram_cert)
{
	error_t ret;
	memcpy(ram_cert->buffer, der_cert, sizeof(der_cert));
	InitDecodedCert(&ram_cert->dc, ram_cert->buffer, sizeof(der_cert), NULL); 
	ret = ParseCert(&ram_cert->dc,0);

	if (ret != ERR_OK ) {
		printf("Error parsing DER form of certificate.\n");
		return ret;
	}
	return ERR_OK;		
}

CertBuffer find_result_pcert, find_result_issuer; 

void print_keystore()
{
	uint16_t i;
	for(i=0;i<KEY_STORE_SIZE;i++)
	{
		if(key_store[i].valid == VALID){
			printf("key_store[%d].serialNumber: ",i);hexdump(key_store[i].serialNumber,CERT_ELEMENT_MAXLEN_SERIALNO);
			printf("key_store[%d].slot_no=%d ",i,key_store[i].slot_no);
			printf("\n");
		}
	}
}

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	uint32_t tc = 0, lc = 0;
	uint8_t expected_result;
	error_t libret;
	uint8_t done = 0, prompt = 0;
	uint8_t i;
	
	libret = mc_cache_init();
	if (libret != ERR_OK) {
		printf("Error initializing cert Cache. error %d\n", libret);
	}

	if (argv[1]) {
		if (!strcmp(argv[1],"help")) {
			help();
			return 0;
		}
		fp = fopen(argv[1],"r");
		if (fp == NULL) {
			printf("Cannot open input file. %s\n", argv[1]);
			return 1;
		}
	}
	else
		prompt = 1;

	libret = parse_der_cert(&ram_cert);
	if (libret != ERR_OK) {
		printf("Error initializing ram_cert. error %d\n",libret);
	}

	//initialize the variable vaid enry to INVALID in key_store
		for(i=0;i<KEY_STORE_SIZE;i++)
		key_store[i].valid = INVALID;

	while (!done){
		if (!prompt) {
			if (!fgets((char *)line,512,fp)) {
				done = 1;
				continue;
			}
		}
		else {
			printf("==> ");fflush(stdout);
			fgets((char *)line, 512,stdin);
		}
		if (line == NULL) continue;
		lc++;
		if (line[0] == '#' || line[0] == '\n') continue;

		if (!prompt) {
			if (!strstr((char *)line,"print "))
				printf("==> %s", line);
		}
	
		//process this line
		char *token;
		tc = 0;
		expected_result = RESULT_PASS; //default is to assume PASS
		token = get_first_token((char *)line);
		while (token){
			switch(get_token_id(token)){
				case TOKEN_EXPECT:
					token = get_next_token((char *)line);
					if (get_token_id(token) == TOKEN_FAIL) {
						expected_result = RESULT_FAIL;
						break;
					}
					if (get_token_id(token) == TOKEN_PASS) {
						expected_result = RESULT_PASS;
						break;
					}
					printf("Incorrect result keyword for expect command\n");
					break;
				case TOKEN_EDITBUF:
					//read param and value from next tokens and update cert buffer
					token = get_next_token((char *)line);

					if (!strcasecmp(token,"serial")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.serialNumber.idx, CERT_ELEMENT_MAXLEN_SERIALNO);
					}

					if (!strcasecmp(token,"subject")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.subject.idx, CERT_ELEMENT_MAXLEN_SUBJECT);
					}

					if (!strcasecmp(token,"issuer")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.issuer.idx, CERT_ELEMENT_MAXLEN_ISSUER);
					}

					if (!strcasecmp(token,"altnames")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.AltNames.idx, CERT_ELEMENT_MAXLEN_ALTNAMES);
						ram_cert.dc.AltNames.len = CERT_ELEMENT_MAXLEN_ALTNAMES;
					}

					if (!strcasecmp(token,"policies")){
						token = get_next_token((char *)line);
						memset(ram_cert.buffer + ram_cert.dc.Policies.idx,0, CERT_ELEMENT_MAXLEN_POLICIES);
						int len = strlen(token);
						if (len > CERT_ELEMENT_MAXLEN_POLICIES-1) len = CERT_ELEMENT_MAXLEN_POLICIES-1;
						memcpy(ram_cert.buffer + ram_cert.dc.Policies.idx,token, len);
						ram_cert.dc.Policies.len = len;
					}
					if (!strcasecmp(token,"authkeyid")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.AuthKeyID.idx, CERT_ELEMENT_MAXLEN_AUTHKEYID);
					}
					if (!strcasecmp(token,"subjkeyid")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.SubjKeyID.idx, CERT_ELEMENT_MAXLEN_SUBJKEYID);
					}
					if (!strcasecmp(token,"pubkey")){
						token = get_next_token((char *)line);
						parse_hexstring(token, ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx, CERT_ELEMENT_MAXLEN_PUBKEY);
					}
					if (!strcasecmp(token,"notafter")){
						token = get_next_token((char *)line);
						parse_hexstring(token, &ram_cert.dc.notAfter, CERT_ELEMENT_MAXLEN_NOTAFTER);
					}
					report_result("OK",NULL,lc);
					break;
				case TOKEN_INSERT:
					{
						uint16_t slot = 0;
						//int ii;
						//if ( *(ram_cert.buffer + ram_cert.dc.serialNumber.idx) == 0xf8) 
						//{ ii++; }	
						libret = cache_insert_cert(&ram_cert, &slot);
						update_slotno_to_store(ram_cert.buffer + ram_cert.dc.serialNumber.idx, slot);
						check_and_report_result(libret, expected_result, line, lc);
					}
					break;
				case TOKEN_DELETE:
					{
						uint16_t slot_to_delete;

						token = get_next_token((char *)line);
						if (!strcasecmp(token,"byslot")){
							token = get_next_token((char *)line);
							sscanf(token,"%hhu",(uint8_t *)&slot_to_delete);
							libret = cache_delete_entry(slot_to_delete);
							check_and_report_result(libret, expected_result, line, lc);
							delete_keypair_from_store();
						}
						if (!strcasecmp(token,"byid")){
							//find and delete
							CertBuffer tmpcert;
							slot_to_delete = 0;
							uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
							uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];

							token = get_next_token((char *)line);
							if (token == NULL) goto noparams_del;
							if (!strcasecmp(token,"serial")){
								token = get_next_token((char *)line);
								if (token == NULL) goto noparams_del;
								parse_hexstring(token, serial, CERT_ELEMENT_MAXLEN_SERIALNO);
							}
							//get issuer from key-store
							libret = get_issuer_from_store(serial, issuer);
							if (libret) goto check_report;

							libret = cache_find_by_issuer_and_serial(issuer,CERT_ELEMENT_MAXLEN_ISSUER, serial, CERT_ELEMENT_MAXLEN_SERIALNO,
									&tmpcert, &slot_to_delete);
							if (libret != ERR_OK) goto check_report;
							libret = cache_delete_entry(slot_to_delete);
							delete_keypair_from_store();
check_report:
							check_and_report_result(libret, expected_result, line, lc);
							break;
noparams_del:
							printf("Line %d: Not enough parameters for delete byid. [syntax: delete byid serial <val>]\n",lc);
							break;
						}
					}
					break;
				case TOKEN_FIND:
					{
						uint16_t slot = 0;

						token = get_next_token((char *)line);
						if (token == NULL){
							//no arguments to find. Try find "ram_cert" in cache
							libret = cache_find_cert(&ram_cert, &slot);
							check_and_report_result(libret, expected_result, line, lc);
							break;
						}
						switch(get_token_id(token)){
							case TOKEN_BYID:
								{
									uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
									uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];

									token = get_next_token((char *)line);
									if (token == NULL) goto noparams_find;
									if (!strcasecmp(token,"serial")){
										token = get_next_token((char *)line);
										parse_hexstring(token, &serial, CERT_ELEMENT_MAXLEN_SERIALNO);
									}
									libret = get_issuer_from_store(serial, issuer);
									if (libret) {
										//no valid entry in key store. so we test API with invalid input
										memset(issuer, 0, CERT_ELEMENT_MAXLEN_ISSUER);
									}
									libret = cache_find_by_issuer_and_serial(issuer,CERT_ELEMENT_MAXLEN_ISSUER, 
											serial, CERT_ELEMENT_MAXLEN_SERIALNO,
											&find_result_pcert, &slot);
									check_and_report_result(libret, expected_result, line, lc);
									goto out;
noparams_find:
									printf("Line %d: Not enough parameters for find byid. [syntax: find byid serial <val>]\n",lc);
								}
out:
								break;
							case TOKEN_BYSLOT:
								{
									uint8_t slotno;
									token = get_next_token((char *)line);
									sscanf(token,"%hhu",&slotno);
									libret =  cache_find_by_slot_number(slotno, &find_result_pcert);
									check_and_report_result(libret, expected_result, line, lc);
								}
								break;
							case TOKEN_BCBYMAC:
								{
									uint8_t mac_addr[8];
									token = get_next_token((char *)line);
									parse_hexstring(token, mac_addr, 8);
									libret = cache_find_BC_by_MAC_address(mac_addr,&find_result_pcert, &slot);
									check_and_report_result(libret, expected_result, line, lc);
								}
								break;
							case TOKEN_DLBYMAC:
								{
									uint8_t mac_addr[8];
									token = get_next_token((char *)line);
									parse_hexstring(token, mac_addr, 8);
									libret = cache_find_DL_by_MAC_address(mac_addr,&find_result_pcert, &slot);
									check_and_report_result(libret, expected_result, line, lc);
								}
								break;
							case TOKEN_ISSUER:
								{
									uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
									uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];

									token = get_next_token((char *)line);
									if (token == NULL) goto token_issuer_noparams;
									if (!strcasecmp(token,"serial")){
										token = get_next_token((char *)line);
										parse_hexstring(token, &serial, CERT_ELEMENT_MAXLEN_SERIALNO);
									}
									libret = get_issuer_from_store(serial, issuer);
									if (libret) goto check_report;

									libret = cache_find_by_issuer_and_serial(issuer,CERT_ELEMENT_MAXLEN_ISSUER, 
											serial, CERT_ELEMENT_MAXLEN_SERIALNO, &find_result_pcert, &slot);
									if (libret != ERR_OK) {
										printf("mcert not found.\n");
										break;
									}
									libret = cache_find_issuer(&find_result_pcert, &find_result_issuer, &slot);
									if (libret == ERR_OK) {
										print_pcert(&find_result_issuer);
									}
									check_and_report_result(libret, expected_result, line, lc);
									break;
token_issuer_noparams:
									printf("Line %d: Not enough or incorrect sequence of parameters for find issuer. [syntax: find issuer certid <val> sysid <val>]\n",lc);
								}
								break;
							case TOKEN_BYSUBJ:
								{
									uint8_t subject[CERT_ELEMENT_MAXLEN_SUBJECT];	
									uint8_t skid[CERT_ELEMENT_MAXLEN_SUBJKEYID];	

									token = get_next_token((char *)line);
									if (token == NULL) goto token_issuer_noparams;
									if (!strcasecmp(token,"subject")){
										token = get_next_token((char *)line);
										parse_hexstring(token, &subject, CERT_ELEMENT_MAXLEN_SUBJECT);
									}
									token = get_next_token((char *)line);
									if (token == NULL) goto token_issuer_noparams;
									if (!strcasecmp(token,"skid")){
										token = get_next_token((char *)line);
										parse_hexstring(token, &skid, CERT_ELEMENT_MAXLEN_SUBJKEYID);
									}
									libret = cache_find_by_subject_and_SKID(subject, CERT_ELEMENT_MAXLEN_SUBJECT,
											skid, CERT_ELEMENT_MAXLEN_SUBJKEYID,&find_result_pcert, &slot);
									check_and_report_result(libret, expected_result, line, lc);
								}
								break;
							case TOKEN_OPER:
								{
									uint16_t slotno;
									token = get_next_token((char *)line);
									sscanf(token,"%hu",&slotno);
									libret = cache_find_next_operator_cert(&find_result_pcert, &slotno);
									if (libret == ERR_OK) printf("found @ slot %d\n", slotno);
									check_and_report_result(libret, expected_result, line, lc);
								}
								break;
							default:
								printf("Unsupported specifier %s for find.\n", token);
								break;
						}
					}
					break;

				case TOKEN_CREATE:
					{
						EC_KEY *eckey = NULL;
						uint8_t pubkey[65];
						uint8_t ret_keypair;
						//create key pair, store in keypair_store and set pubkey of test_mcert
						create_new_ec_key_pair(&eckey, pubkey);
						ret_keypair = add_keypair_to_store((uint8_t *)ram_cert.buffer + ram_cert.dc.serialNumber.idx, 
								(uint8_t *)ram_cert.buffer + ram_cert.dc.subject.idx, eckey, pubkey, 
								(uint8_t *)ram_cert.buffer + ram_cert.dc.SubjKeyID.idx);
						if(ret_keypair == KEY_STORE_FULL) 
						{
							printf("KEYSTORE FULL\n");
							//return 0;
							break;
						}
						memcpy(ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx, pubkey, CERT_ELEMENT_MAXLEN_PUBKEY);
						//TODO: update AuthKeyID and subjKeyID ?
						//
						/*
						   For CA certificates, subject key identifiers SHOULD be derived from
						   the public key or a method that generates unique values.  Two common
						   methods for generating key identifiers from the public key are:

						   (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
						   value of the BIT STRING subjectPublicKey (excluding the tag,
						   length, and number of unused bits).

						   (2) The keyIdentifier is composed of a four bit type field with
						   the value 0100 followed by the least significant 60 bits of the
						   SHA-1 hash of the value of the BIT STRING subjectPublicKey
						   (excluding the tag, length, and number of unused bit string bits).

						   One common method for generating unique values is a monotonically
						   increasing sequence of integers.
						   */
						check_and_report_result(ERR_OK, expected_result, line, lc);
					}
					break;

				case TOKEN_SIGN:
					{
						EC_KEY *signer_key = NULL;
						uint8_t *signer_pubkey = NULL,*issuer_subjkeyid;
						CertBuffer cert_local;
						uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
						uint8_t subject[CERT_ELEMENT_MAXLEN_ISSUER];


						token = get_next_token((char *)line);
						if (token == NULL){
							//no arguments to sign. sign using keypair of root certificate
							libret = cert_cache_read_cert(&cert_local, ROOT_CERT_SLOT);
							if (libret != ERR_OK) {
								printf("Error reading cert from cache\n");
								break;
							}
							get_keypair_from_store(cert_local.buffer + cert_local.dc.serialNumber.idx, &signer_key, &signer_pubkey,subject);
							libret = sign_cert(&ram_cert, signer_key,signer_pubkey,subject, cert_local.buffer + cert_local.dc.SubjKeyID.idx);
							update_issuer_to_store(ram_cert.buffer + ram_cert.dc.serialNumber.idx, 
									cert_local.buffer + cert_local.dc.issuer.idx,
									cert_local.buffer + cert_local.dc.AuthKeyID.idx);
							check_and_report_result(libret, expected_result, line, lc);
							break;
						}
						switch(get_token_id(token)){
							case TOKEN_USING:
								{
									token = get_next_token((char *)line);
									if (token == NULL) goto noparams_sign_using;
									if (!strcasecmp(token,"serial")){
										token = get_next_token((char *)line);
										if (token == NULL) goto noparams_sign_using;
										parse_hexstring(token, &serial, CERT_ELEMENT_MAXLEN_SERIALNO);
									}
									get_keypair_from_store(serial,&signer_key,&signer_pubkey,subject);
									get_subjkeyid_from_store(serial, &issuer_subjkeyid);
									libret = sign_cert(&ram_cert,signer_key,signer_pubkey,subject,issuer_subjkeyid);
									if (libret != ERR_OK) {
										printf("sign_cert returned Error\n");
										break;
									}
									update_issuer_to_store(ram_cert.buffer + ram_cert.dc.serialNumber.idx, subject, issuer_subjkeyid);
									check_and_report_result(libret, expected_result, line, lc);
									break;
noparams_sign_using:
									printf("Line %d: Not enough or incorrect sequence of parameters for \"sign using\".\n",lc);
									printf("sign [self | using serial <8-octets>|*<octet>]\n");
								}
								break;
							case TOKEN_SELF:
								{
									//sign using keypair of test_mcert
									libret = sign_cert(&ram_cert, ram_cert_eckey, ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx,
											ram_cert.buffer + ram_cert.dc.subject.idx, ram_cert.buffer + ram_cert.dc.SubjKeyID.idx);
									memcpy(ram_cert.buffer + ram_cert.dc.issuer.idx, 
											ram_cert.buffer + ram_cert.dc.subject.idx, CERT_ELEMENT_MAXLEN_ISSUER);
									memcpy(ram_cert.buffer + ram_cert.dc.AuthKeyID.idx, 
											ram_cert.buffer + ram_cert.dc.SubjKeyID.idx, CERT_ELEMENT_MAXLEN_AUTHKEYID);
									check_and_report_result(libret, expected_result, line, lc);
								}
								break;
							default:
								printf("sign [self | using serial <8-octets>|*<octet>]\n");
								break;
						}
					}
					break;

				case TOKEN_CHECK_SANITY:
					libret = cache_check_sanity();	
					check_and_report_result(libret, expected_result, line, lc);

					break;
	
				case TOKEN_ADDMANY:
#if 1						
					{
						uint16_t range,auto_serial=1;
						uint16_t slot = 0;
						uint8_t serial[CERT_ELEMENT_MAXLEN_SERIALNO];
						uint8_t issuer[CERT_ELEMENT_MAXLEN_ISSUER];
						uint8_t subject[CERT_ELEMENT_MAXLEN_ISSUER];
						EC_KEY *signer_key = NULL;
						uint8_t *signer_pubkey = NULL,*issuer_subjkeyid;	
						token = get_next_token((char *)line);
						sscanf(token,"%hu",&range);
						token = get_next_token((char *)line);
						//if(token == NULL) goto token_addmany_noparams;
						if(token == NULL){
							printf("Syntax error add many command\n");
							printf("Syntax addmany <decimal_number_n at <serialoctet> serials auto|<serialoctet1 serialoctet2 .. serialoctetn>>\n");
							return 0;
						}
						if(!strcasecmp(token,"at"))
						{
							token = get_next_token((char *)line);
							parse_hexstring(token, serial, CERT_ELEMENT_MAXLEN_SERIALNO);
							//get issuer from stor by serialid
							libret = get_issuer_from_store(serial, issuer);
							if (libret) goto check_report;
							token = get_next_token((char *)line);
							if(!strcasecmp(token,"serial"))
							{

									EC_KEY *eckey = NULL;
									uint8_t pubkey[65];
									uint8_t ret_keypair;
									token = get_next_token((char *)line);
									for(i=0;i<range;i++){
									if(strcasecmp(token,"auto")){  // TODO comparation not correct
									parse_hexstring(token, ram_cert.buffer + ram_cert.dc.serialNumber.idx, CERT_ELEMENT_MAXLEN_SERIALNO);
									parse_hexstring(token, ram_cert.buffer + ram_cert.dc.subject.idx, CERT_ELEMENT_MAXLEN_SUBJECT);
									parse_hexstring(token, ram_cert.buffer + ram_cert.dc.SubjKeyID.idx, CERT_ELEMENT_MAXLEN_SUBJKEYID);
									token = get_next_token((char *)line);
									}
									else
									{
										memset(ram_cert.buffer + ram_cert.dc.serialNumber.idx,auto_serial,CERT_ELEMENT_MAXLEN_SERIALNO);
										memset(ram_cert.buffer + ram_cert.dc.subject.idx,auto_serial, CERT_ELEMENT_MAXLEN_SUBJECT);
										memset(ram_cert.buffer + ram_cert.dc.SubjKeyID.idx,auto_serial, CERT_ELEMENT_MAXLEN_SUBJKEYID);
										auto_serial++;
									}	
									create_new_ec_key_pair(&eckey, pubkey);
									ret_keypair = add_keypair_to_store((uint8_t *)ram_cert.buffer + ram_cert.dc.serialNumber.idx, 
											(uint8_t *)ram_cert.buffer + ram_cert.dc.subject.idx, eckey, pubkey, 
											(uint8_t *)ram_cert.buffer + ram_cert.dc.SubjKeyID.idx);
									if(ret_keypair == KEY_STORE_FULL) 
									{
										printf("KEYSTORE FULL\n");
										//return 0;
										break;
									}
									memcpy(ram_cert.buffer + ram_cert.dc.subjectPublicKey.idx, pubkey, CERT_ELEMENT_MAXLEN_PUBKEY);
									// sign 
									get_keypair_from_store(serial,&signer_key,&signer_pubkey,subject);
									get_subjkeyid_from_store(serial, &issuer_subjkeyid);
									libret = sign_cert(&ram_cert,signer_key,signer_pubkey,subject,issuer_subjkeyid);
									if (libret != ERR_OK) {
										printf("sign_cert returned Error\n");
										break;
									}
									update_issuer_to_store(ram_cert.buffer + ram_cert.dc.serialNumber.idx, subject, issuer_subjkeyid);
									// insert
									libret = cache_insert_cert(&ram_cert, &slot);
									update_slotno_to_store(ram_cert.buffer + ram_cert.dc.serialNumber.idx, slot);
									}
							}

					}
					check_and_report_result(libret, expected_result, line, lc);
#endif
			}
					break;

				case TOKEN_PRINT_INDEX:
					print_index();
					break;
				case TOKEN_PRINT_CACHE:
					{
						struct CertBuffer_cache_entry ce;
						uint8_t curr;

						printf("Cert_cache:\n");
						curr = used_list_head;
						while ( curr != 0xFF) {

							get_fullcert_from_cert_cache((void *)&(ce.cb), used_list[curr].cache_slot);
							printf("#%d:\n",used_list[curr].cache_slot);
							printf("SerialNumber	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.serialNumber.idx), CERT_ELEMENT_MAXLEN_SERIALNO);
							//printf("Subject				: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.subject.idx), CERT_ELEMENT_MAXLEN_SUBJECT);
							printf("Subject		: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.subject.idx), 16);
							//printf("Issuer 				: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.issuer.idx), CERT_ELEMENT_MAXLEN_ISSUER);
							printf("Issuer 		: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.issuer.idx), 16);
							//printf("Public key		)	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.subjectPublicKey.idx), CERT_ELEMENT_MAXLEN_PUBKEY);
							printf("Public key	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.subjectPublicKey.idx), 16);
							printf("AltNames   	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.AltNames.idx), 16);
							printf("SubjKeyID   	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.SubjKeyID.idx), 16);
							printf("AuthKeyID	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.AuthKeyID.idx), 16);
							printf("Policies   	: ");hexdump((uint8_t *)(ce.cb.buffer + ce.cb.dc.Policies.idx), ce.cb.dc.Policies.len);

							curr = used_list[curr].next;
						}
					}
					break;
				case TOKEN_PRINT_CERT:
					{
						uint16_t index;
						struct CertBuffer_cache_entry ce;
						token = get_next_token((char *)line);
						if (token) {
							sscanf(token,"%hhu",(uint8_t *)&index);
							get_fullcert_from_cert_cache((void *)&(ce.cb), index);
							print_pcert(&(ce.cb));
						}
						else
							print_pcert(&ram_cert);
					}
					break;
				case TOKEN_PRINT_KEYSTORE:
					print_keystore();
					break;
				
				case TOKEN_PRINT_MSG:
					//print everything except "print "
					printf("%s\n",line+6);
					token = NULL;
					continue;

				case TOKEN_PROMPT:
					prompt = 1;
					break;

				case TOKEN_EXIT:
					done = 1;
					token = NULL;
					continue;
					//return 0;

				default:
					printf("Unrecognized keyword %s\n", token);
					break;
			}
			token = get_next_token((char *)line);
		}
	}
	clear_ec_key_store();
	mc_cache_uninit();
	printf("All done.\n");
	if (fp) fclose(fp);
	return 0;
}

#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<time.h>
#include<string.h>
//#include "x509_read.h"
#include "asn.h"
#undef OPENSSL
//openssl headers
#ifdef OPENSSL
#include<openssl/bio.h>
#include<openssl/err.h>
#include<openssl/pem.h>
#include<openssl/x509.h>
void print_x509_cert(X509 *cert);
#endif
#define BUFF_SIZE 2048

#define ne_certp(a,b) printf("idx=%d, len=%d\n",(int)a,(int)b)
void print_x509_cyassl(CertBuffer *cb);
void hexdump(uint8_t *p, uint32_t size);
void print_x509_idx_len(int idx,int len);
void print_idx_len(CertBuffer *cb);
void signAlgo_verify(CertBuffer *cb);
//void InitDecodedCert(DecodedCert* cert, byte* source, word32 inSz, void* heap);	

int main(int argc, char *argv)
{
	CertBuffer cb;
	uint32_t ret;
	memset(&cb, 0, sizeof(cb));
	//char *x509_fname = "t2.der";
	//char *x509_fname = "cacert1.der";
	char *x509_fname = "cacert9.der";
	FILE *x509_der_fp = NULL;
	word16 fp_size;
	int i;
	x509_der_fp=fopen(x509_fname,"rb");
	
	if(x509_der_fp == NULL)
	{
		printf("Failed to open %s file\n",x509_fname);
		return 1;
	}

	fp_size = fread(cb.buffer,sizeof(byte),sizeof(cb.buffer),x509_der_fp);
	//printf("fp_size %d\n",fp_size); 
	

#if 1

	//printf("cb.dc.srcIdx= %x\n,",cb.dc.srcIdx);
	//InitDecodedCert(&cb.dc, der_buf, (word16)fp_size, NULL); 
	InitDecodedCert(&cb.dc, cb.buffer, (word16)fp_size, NULL); 
	//printf("cb.dc.srcIdx= %x\n,",cb.dc.srcIdx);
	ret = ParseCert(&cb.dc,0);
	//printf("cb.dc.srcIdx= %x\n,",cb.dc.srcIdx);
	printf("ret = %d\n",ret);
	//printf("max-id = %d\n",cb.dc.maxIdx);

	print_idx_len(&cb);	
	print_x509_cyassl(&cb);
#ifdef OPENSSL
	X509 *cert = d2i_X509_fp(x509_der_fp,NULL);
	if(cert == NULL)
	{
		printf("Failed to decode %s cert file\n", x509_fname);
		return 1;
	}
	print_x509_cert(cert);
	fclose(x509_der_fp);
	X509_free(cert);
	#endif
#endif
return 0;
}

void print_x509_cyassl(CertBuffer *cb)
{
	int i=0,index;
	uint32_t size;
	byte *buff;
//	printf("cert_version= %d\n",cb->dc.certVersion);
	buff = cb->buffer;
//	printf("sizeof(cb->buffer) %d\n",sizeof(cb->buffer));
		
	printf("\nCertBuffer@%p\n",cb);
        printf("CertBuff->certVersion: ");hexdump((uint8_t *)&(cb->dc.certVersion), 1);
      //  printf("CertBuff->Certificate: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.Certificate.idx]), cb->dc.Certificate.len);
      //  printf("CertBuff->tbsCertificate: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.tbsCertificate.idx]), cb->dc.tbsCertificate.len);
        printf("CertBuff->signatureAlgorithm: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.signatureAlgorithm.idx]), cb->dc.signatureAlgorithm.len);
	signAlgo_verify(cb);
        printf("CertBuff->signatureValue: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.signatureValue.idx]), cb->dc.signatureValue.len);
        printf("CertBuff->serialNumber: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.serialNumber.idx]), cb->dc.serialNumber.len);
        printf("CertBuff->signature(Alg_id): ");hexdump((uint8_t *)&(cb->buffer[cb->dc.signature.idx]), cb->dc.signature.len);
        printf("CertBuff->issuer: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.issuer.idx]), cb->dc.issuer.len);
        printf("CertBuff->subject: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.subject.idx]), cb->dc.subject.len);
        printf("CertBuff->extensions: ");hexdump((uint8_t *)&(cb->buffer[cb->dc.extensions.idx]), cb->dc.extensions.len);
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
        printf("CertBuff->signatureOID : ");printf("%d",cb->dc.signatureOID);
	printf("\n");

	
	

}

void print_idx_len(CertBuffer *cb)
{
	printf("\nCertBuffer_idx_len\n");
        printf("CertBuff->Certificate:        ");print_x509_idx_len(cb->dc.Certificate.idx,cb->dc.Certificate.len);
        printf("CertBuff->tbsCertificate:     ");print_x509_idx_len(cb->dc.tbsCertificate.idx,cb->dc.tbsCertificate.len);
        printf("CertBuff->signatureAlgorithm: ");print_x509_idx_len(cb->dc.signatureAlgorithm.idx,cb->dc.signatureAlgorithm.len);
        printf("CertBuff->signatureValue:     ");print_x509_idx_len(cb->dc.signatureValue.idx,cb->dc.signatureValue.len);
        printf("CertBuff->serialNumber:       ");print_x509_idx_len(cb->dc.serialNumber.idx,cb->dc.serialNumber.len);
        printf("CertBuff->signature(signAlgoID): ");print_x509_idx_len(cb->dc.signature.idx,cb->dc.signature.len);
        printf("CertBuff->issuer:             ");print_x509_idx_len(cb->dc.issuer.idx,cb->dc.issuer.len);
        printf("CertBuff->subject:            ");print_x509_idx_len(cb->dc.issuer.idx,cb->dc.issuer.len);
        printf("CertBuff->algorithm(PubKeyAlgo): ");print_x509_idx_len(cb->dc.algorithm.idx,cb->dc.algorithm.len);
        printf("CertBuff->subjectPublicKey:   ");print_x509_idx_len(cb->dc.subjectPublicKey.idx,cb->dc.subjectPublicKey.len);
        printf("CertBuff->extensions:         ");print_x509_idx_len(cb->dc.extensions.idx,cb->dc.extensions.len);
        printf("CertBuff->AltNames:           ");print_x509_idx_len(cb->dc.AltNames.idx,cb->dc.AltNames.len);
        printf("CertBuff->AuthKeyID:          ");print_x509_idx_len(cb->dc.AuthKeyID.idx,cb->dc.AuthKeyID.len);
        printf("CertBuff->SubjKeyID:          ");print_x509_idx_len(cb->dc.SubjKeyID.idx,cb->dc.SubjKeyID.len);
        printf("CertBuff->Policies:           ");print_x509_idx_len(cb->dc.Policies.idx,cb->dc.Policies.len);
        printf("CertBuff->Role:               ");print_x509_idx_len(cb->dc.Role.idx,cb->dc.Role.len);
        printf("CertBuff->MultiRole:          ");print_x509_idx_len(cb->dc.MultiRole.idx,cb->dc.MultiRole.len);

}

void print_x509_idx_len(int idx,int len)
{
        printf("idx=%03d  len=%03d\n",idx,len);

}

void hexdump(uint8_t *p, uint32_t size)
{
        while (size--) printf("%02x",*p++);
        printf("\n");
}

void signAlgo_verify(CertBuffer *cb)
{
uint16_t idx=cb->dc.signatureAlgorithm.idx;
uint16_t len=cb->dc.signatureAlgorithm.len;
uint16_t i=idx+4,j=0,k=0;
uint16_t ret;
uint8_t tmp_buf[7]={42,134,72,206,61,04,01};
while(i != ((idx+4) + strlen(tmp_buf)))
{
if(cb->buffer[i] == tmp_buf[k])
{
	j++;
}
	k++;
	i++;
}
if (j == strlen(tmp_buf))
{
	printf("CertBuff->signatureAlgorithm: ecdsa-with-SHA1\n");
}
else
{
	printf("CertBuff->signatureAlgorithm is not ecdsa-with-SHA1\n");
}
//ret = memcmp(tmp_buf,cb->buffer+i,strlen(tmp_buf));

}
#ifdef OPENSSL
void print_x509_cert(X509 *cert)
{
	uint8_t cert_version;
	//cert_version = ((uint8_t)X509_get_version(cert)) + 1; // the version is one less than the cert version so added one
	//printf("Cert_version %d\n",cert_version);
	//printf("%d\n",cert->cert_info.version);
	#ifdef OPENSSL
	BIO *outbio;
	outbio = BIO_new_fp(stdout,BIO_NOCLOSE);
	X509_print(outbio,cert);
	#endif
	//PEM_write_bio_X509(outbio,cert);
	
}
#endif

#ifndef _X509_CACHE_FLASH_H_
#define _X509_CACHE_FLASH_H_

error_t cert_cache_read_cert(CertBuffer *cert, uint8_t slotno);
error_t cert_cache_write_cert(CertBuffer *cert, uint8_t slotno);
error_t cert_cache_delete_cert(uint8_t slotno);


#endif

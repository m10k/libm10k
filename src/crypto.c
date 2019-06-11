/*
 * crypto.c - This file is part of libm10k
 * Copyright (C) 2019 Matthias Kruk
 *
 * libm10k is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 3, or (at your
 * option) any later version.
 *
 * libm10k is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libxhome; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#define _LIBM10K_SOURCE
#include <m10k/crypto.h>
#include <m10k/mem.h>
#include <m10k/log.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <pthread.h>

#define CONFIG_KEYLENGTH_DEFAULT  4096
#define CONFIG_EXPIRATION_DEFAULT 365

#define RSA_EXP 65537
#define HASHFUNC EVP_sha512()

static pthread_once_t init_once = PTHREAD_ONCE_INIT;

struct _m10k_key {
	EVP_PKEY *key;
};

struct _m10k_cert {
	X509 *cert;
	int next_serial;
	int expiration;
};

struct _m10k_cert_req {
	X509_REQ *req;
};

static void __init__(void);

#define INIT() pthread_once(&init_once, __init__)

/* generate an RSA key with a specified keylength */
static int _gen_rsa(EVP_PKEY **dst, int keylength)
{
	unsigned int exp;
	EVP_PKEY *pkey;
	RSA *key;
	BIGNUM *e;
	int ret_val;

	ret_val = -EFAULT;
	exp = htonl(RSA_EXP);
	pkey = EVP_PKEY_new();
	key = NULL;
	e = NULL;

	if(pkey) {
		key = RSA_new();

		if(key) {
			e = BN_bin2bn((const unsigned char*)&exp, sizeof(exp), NULL);

			if(e) {
				if(RSA_generate_key_ex(key, keylength, e, NULL)) {
					EVP_PKEY_set1_RSA(pkey, key);
					ret_val = 0;
				}
			}
		}
	}

	if(e) {
		BN_free(e);
	}

	if(ret_val) {
		if(key) {
			RSA_free(key);
		}

		if(pkey) {
			EVP_PKEY_free(pkey);
		}
	} else {
		*dst = pkey;
	}

	return(ret_val);
}

/**
 * m10k_key_new - Generate a new RSA key and allocate a m10k_key structure for it
 * @param dst A pointer to the pointer that will point to the newly allocated structure
 * @param len The length of the RSA key to be generated, in bits
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_key_new(m10k_key **dst, int len)
{
	int ret_val;
	m10k_key *k;

	INIT();

	ret_val = m10k_salloc(k);

	if(!ret_val) {
		ret_val = _gen_rsa(&(k->key), len ? len : CONFIG_KEYLENGTH_DEFAULT);

		if(ret_val < 0) {
			m10k_unref(k);
		} else {
			*dst = k;
		}
	}

	return(ret_val);
}

/**
 * m10k_key_new_from_file - Read a m10k_key structure from a file
 * @param dst A pointer to the pointer that will point to the newly allocated structure
 * @param path The file system path to read the key material from
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_key_new_from_file(m10k_key **dst, const char *path)
{
	int ret_val;
	m10k_key *key;
	FILE *fd;

	INIT();

	fd = NULL;
	ret_val = m10k_salloc(key);

	if(ret_val) {
		goto gtfo;
	}

	fd = fopen(path, "r");

	if(!fd) {
		ret_val = -errno;
		m10k_P("fopen", ret_val);
		goto gtfo;
	}

	key->key = PEM_read_PrivateKey(fd, NULL, NULL, NULL);

	if(!key->key) {
		ret_val = -EIO;
	}

	fclose(fd);

gtfo:

	if(ret_val) {
		if(key) {
			if(key->key) {
				EVP_PKEY_free(key->key);
			}
			m10k_unref(key);
		}
	} else {
		*dst = key;
	}

	return(ret_val);
}

/**
 * m10k_key_to_file - Save a m10k_key structure to a file
 * @param key The key to be written to a file
 * @param path The file to write the key to
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_key_to_file(m10k_key *key, const char *path)
{
	int ret_val;
	FILE *fd;

	INIT();

	fd = fopen(path, "w+");

	if(!fd) {
		ret_val = -errno;
		m10k_P("fopen", ret_val);
	} else {
		ret_val = PEM_write_PrivateKey(fd, key->key, NULL, NULL, 0, 0, NULL);

		fclose(fd);

		if(!ret_val) {
			ret_val = -EIO;
			goto skip;
		}

		ret_val = 0;
	}

skip:
	return(ret_val);
}

/**
 * m10k_key_sign - Sign data with a m10k_key
 * @param key The key to be used to create the signature
 * @param src A pointer to the data to be signed
 * @param slen The length of the data to be signed
 * @param dst A pointer to the buffer where the signature shall be stored
 * @param dsize The maximum number of bytes to be written to dst
 * @return On success, the number of bytes written; on error, a negative error code (man 3 errno)
 */
int m10k_key_sign(m10k_key *key, const void *src, const size_t slen, void *dst, const size_t dsize)
{
	EVP_MD_CTX ctx;
	int ret_val;
	unsigned char md[2048];
	size_t mdlen;

	mdlen = sizeof(md);

	EVP_MD_CTX_init(&ctx);
	EVP_DigestSignInit(&ctx, NULL, HASHFUNC, NULL, key->key);

	if(!EVP_DigestSignUpdate(&ctx, src, slen)) {
		ret_val = -EINVAL;
	} else if(!EVP_DigestSignFinal(&ctx, md, &mdlen)) {
		ret_val = -EKEYREJECTED;
	} else {
		if(dsize < mdlen) {
			mdlen = dsize;
		}
		ret_val = (int)mdlen;
		memcpy(dst, md, mdlen);
	}

	EVP_MD_CTX_cleanup(&ctx);

	return(ret_val);
}

/**
 * m10k_key_verify - Validate a signature with a m10k_key
 * @param key The public key to use for the signature verification
 * @param data A pointer to the signed data
 * @param dlen The length of the signed data
 * @param sig A pointer to the signature to be verified
 * @param slen The length of the signature
 * @return Zero if the signature is valid; otherwise, a negative error code (man 3 errno)
 */
int m10k_key_verify(m10k_key *key, const void *data, const size_t dlen, const void *sig, const size_t slen)
{
	int ret_val;
	EVP_MD_CTX ctx;

	EVP_MD_CTX_init(&ctx);

	EVP_DigestVerifyInit(&ctx, NULL, HASHFUNC, NULL, key->key);

	if(!EVP_DigestVerifyUpdate(&ctx, data, dlen)) {
		ret_val = -EINVAL;
	} else if(!EVP_DigestVerifyFinal(&ctx, (unsigned char*)sig, slen)) {
		ret_val = -EBADMSG;
	} else {
		ret_val = 0;
	}

	EVP_MD_CTX_cleanup(&ctx);

	return(ret_val);
}

/**
 * m10k_key_free - Free the memory that is occupied by a m10k_key instance
 * @param key The key to be freed
 */
void m10k_key_free(m10k_key **key)
{
	INIT();

	if((*key)->key) {
		EVP_PKEY_free((*key)->key);
	}
	m10k_mem_unref((void**)key);

	return;
}

static int _cert_add_ext(X509 *cert, int nid, char *value)
{
	X509_EXTENSION *ext;
	X509V3_CTX ctx;
	int ret_val;

	X509V3_set_ctx_nodb(&ctx);
	X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

	ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);

	if(ext) {
		X509_add_ext(cert, ext, -1);
		X509_EXTENSION_free(ext);
		ret_val = 0;
	} else {
		ret_val = 1;
	}

	return(ret_val);
}

/**
 * m10k_cert_new - Create a new CA certificate
 * @param dst A pointer to the pointer that will point to the newly allocated certificate
 * @param key The key to use with the certificate
 * @param days The number of days that the certificate shall be valid for
 * @param c The country code for the certificate
 * @param o The organization for the certificate
 * @param cn The certificate subject
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_new(m10k_cert **dst, m10k_key *key, int days, const char *c, const char *o, const char *cn)
{
	int ret_val;
	m10k_cert *cert;
	X509_NAME *name;

	INIT();

	ret_val = m10k_salloc(cert);

	if(ret_val) {
		goto err;
	}

	cert->expiration = CONFIG_EXPIRATION_DEFAULT;

	cert->cert = X509_new();

	if(!cert->cert) {
		ret_val = -ENOMEM;
		goto err;
	}

	if(!X509_set_pubkey(cert->cert, key->key)) {
		ret_val = -EKEYREJECTED;
		goto err;
	}

	if(!X509_set_version(cert->cert, 1)) {
		ret_val = -EFAULT;
		goto err;
	}

	name = X509_get_subject_name(cert->cert);

	if(!name) {
		ret_val = -ENOMEM;
		goto err;
	}

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)c, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)o, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);
	X509_set_issuer_name(cert->cert, name);

	ASN1_INTEGER_set(X509_get_serialNumber(cert->cert), 1);
	X509_gmtime_adj(X509_get_notBefore(cert->cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert->cert), (long)(24 * 60 * 60 * days));

	ret_val = _cert_add_ext(cert->cert, NID_basic_constraints, "critical,CA:TRUE");

	if(ret_val < 0) {
		goto err;
	}

	ret_val = _cert_add_ext(cert->cert, NID_key_usage, "critical,keyCertSign,cRLSign");

	if(ret_val < 0) {
		goto err;
	}

	ret_val = _cert_add_ext(cert->cert, NID_subject_key_identifier, "hash");

	if(ret_val < 0) {
		goto err;
	}

	if(!X509_sign(cert->cert, key->key, HASHFUNC)) {
		ret_val = -EIO;
	} else {
		ret_val = 0;
	}

err:
	if(ret_val) {
		if(cert) {
			m10k_cert_free(&cert);
		}
	} else {
		*dst = cert;
	}

	return(ret_val);
}

/**
 * m10k_cert_new_from_file - Read a m10k_cert structure from a file
 * @param dst A pointer to a pointer that will point to the newly allocated m10k_cert instance
 * @param path The path to read the certificate from
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_new_from_file(m10k_cert **dst, const char *path)
{
	int ret_val;
	m10k_cert *cert;
	FILE *fd;

	INIT();

	ret_val = m10k_salloc(cert);

	if(ret_val) {
		goto gtfo;
	}

	fd = fopen(path, "r");

	if(!fd) {
		ret_val = -errno;
		m10k_P("fopen", ret_val);
		goto gtfo;
	}

	cert->cert = PEM_read_X509(fd, NULL, NULL, NULL);

	if(!cert->cert) {
		ret_val = -EIO;
	} else {
		ret_val = 0;
	}

	fclose(fd);

gtfo:
	if(ret_val) {
		if(cert) {
			if(cert->cert) {
				X509_free(cert->cert);
			}

			m10k_unref(cert);
		}
	} else {
		*dst = cert;
	}

	return(ret_val);
}

/**
 * m10k_cert_new_from_der - Read a m10k_cert from DER-encoded memory
 * @param dst A pointer to a pointer that will point to the newly allocated m10k_cert instance
 * @param src A pointer to the memory where the DER-encoded certificate is stored
 * @param len The length of the buffer pointed to by src
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_new_from_der(m10k_cert **dst, const void *src, const size_t len)
{
	int ret_val;
	m10k_cert *cert;

	INIT();

	ret_val = m10k_salloc(cert);

	if(ret_val) {
		goto gtfo;
	}

	cert->cert = d2i_X509(NULL, (const unsigned char**)&src, (long)len);

	if(!cert->cert) {
		ret_val = -EIO;
	} else {
		ret_val = 0;
	}

gtfo:
	if(ret_val) {
		if(cert) {
			if(cert->cert) {
				X509_free(cert->cert);
			}

			m10k_unref(cert);
		}
	} else {
		*dst = cert;
	}

	return(ret_val);
}

/**
 * m10k_cert_set_expiration - Set the expiration date of certificates that are signed with this certificate
 * @param cert The certificate of which the signature expiration is to be modified
 * @param exp The new expiration time for signatures created with the certificate
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_set_expiration(m10k_cert *cert, int exp)
{
	INIT();

	if(exp < 0 || exp > 20 * 365) {
		return(-ERANGE);
	}

	cert->expiration = exp;
	return(0);
}

/**
 * m10k_cert_get_name - Return the common name stored in a certificate
 * @param cert The certificate to retrieve the common name from
 * @param dst The buffer where the common name shall be stored
 * @param dsize The size of the destination buffer, in bytes
 * @return The length of the common name, or a negative error code (man 3 errno)
 */
int m10k_cert_get_name(m10k_cert *cert, char *dst, const size_t dsize)
{
	int ret_val;
	X509_NAME *name;

	name = X509_get_subject_name(cert->cert);

	if(!name) {
		ret_val = -EBADFD;
	} else {
		int pos;

		ret_val = -EINVAL;
		pos = X509_NAME_get_index_by_NID(name, NID_commonName, -1);

		if(pos != -1) {
			X509_NAME_ENTRY *ne;

			ne = X509_NAME_get_entry(name, pos);

			if(ne) {
				ASN1_STRING *str;

				str = X509_NAME_ENTRY_get_data(ne);

				if(str) {
					unsigned char *utf8;
					int len;

					len = ASN1_STRING_to_UTF8(&utf8, str);

					if(len > 0) {
						ret_val = dsize < (size_t)len ? (int)dsize : len;
						strncpy(dst, (char*)utf8, (size_t)ret_val);
						dst[ret_val] = 0;
						free(utf8);
					}
				}
			}
		}
	}

	return(ret_val);
}

/**
 * m10k_cert_get_public_key - Get the public key from a certificate
 * @param cert The certificate of which the public key is to be retrieved
 * @param dst A pointer to a pointer that will be made to point to the key
 * @return Zero upon success, or a negative error number (man 3 errno)
 */
int m10k_cert_get_public_key(m10k_cert *cert, m10k_key **dst)
{
	int ret_val;
	m10k_key *key;

	key = NULL;
	ret_val = m10k_salloc(key);

	if(!ret_val) {
		key->key = X509_get_pubkey(cert->cert);

		if(!key->key) {
			ret_val = -ENOENT;
		} else if(!EVP_PKEY_up_ref(key->key)) {
			ret_val = -EBUSY;
		} else {
			ret_val = 0;
		}
	}

	if(ret_val < 0) {
		if(key) {
			m10k_unref(key);
		}
	} else {
		*dst = key;
	}

	return(ret_val);
}

/**
 * m10k_cert_to_file - Write a certificate to a file
 * @param cert The certificate to write to a file
 * @param path The path to write the certificate to
 * @return Zero upon success, or a negative error number (man 3 errno)
 */
int m10k_cert_to_file(m10k_cert *cert, const char *path)
{
	int ret_val;
	FILE *fd;

	INIT();

	fd = fopen(path, "w+");

	if(!fd) {
		ret_val = -errno;
		m10k_P("fopen", ret_val);
	} else {
		if(!PEM_write_X509(fd, cert->cert)) {
			ret_val = -EIO;
		} else {
			ret_val = 0;
		}

		fclose(fd);
	}

	return(ret_val);
}

/**
 * m10k_cert_to_der - DER-encode a m10k_cert
 * @param cert The certificate to encode
 * @param dst The buffer to write the DER-encoded certificate to
 * @param dsize The size of the buffer pointed to by dst
 * @return The number of bytes written, or a negative error code (man 3 errno)
 */
int m10k_cert_to_der(m10k_cert *cert, void *dst, const size_t dsize)
{
	int ret_val;
	m10k_u8 buf[8192];
	unsigned char *d;

	INIT();

	d = buf;
	ret_val = i2d_X509(cert->cert, &d);

	if(ret_val < 0) {
		ret_val = -EINVAL;
	} else {
		size_t size;

		size = (size_t)ret_val;

		if(dsize < size) {
			size = dsize;
		}

		memcpy(dst, buf, size);
		memset(buf, 0, size);
	}

	return(ret_val);
}

/**
 * m10k_cert_free - Free the memory occupied by a m10k_cert instance
 * @param cert The m10k_cert to be freed
 */
void m10k_cert_free(m10k_cert **cert)
{
	INIT();

	if((*cert)->cert) {
		X509_free((*cert)->cert);
	}
	m10k_mem_unref((void**)cert);

	return;
}

/**
 * m10k_cert_req_new - Generate a new X509 certificate request
 * @param dst A pointer to the pointer that will point to the newly allocated certificate request
 * @param key The key to be used to with the certificate request
 * @param c The country code of the certificate request
 * @param o The organization of the certificate request
 * @param cn The certificate subject
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_req_new(m10k_cert_req **dst, m10k_key *key, const char *c, const char *o, const char *cn)
{
	int ret_val;
	m10k_cert_req *req;
	X509_NAME *name;

	INIT();

	ret_val = m10k_salloc(req);

	if(ret_val) {
		goto gtfo;
	}

	req->req = X509_REQ_new();

	if(!req->req) {
		ret_val = -ENOMEM;
		goto gtfo;
	}

	name = X509_REQ_get_subject_name(req->req);

	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)c, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)o, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0);

	if(!X509_REQ_set_version(req->req, 1)) {
		ret_val = -ERANGE;
		goto gtfo;
	}

	if(!X509_REQ_set_pubkey(req->req, key->key)) {
		ret_val = -EKEYREJECTED;
		goto gtfo;
	}

	if(X509_REQ_sign(req->req, key->key, HASHFUNC) < 0) {
		ret_val = -EIO;
	} else {
		ret_val = 0;
	}

gtfo:
	if(ret_val) {
		if(req) {
			m10k_cert_req_free(&req);
		}
	} else {
		*dst = req;
	}

	return(ret_val);
}

/**
 * m10k_cert_req_new_from_der - Read a certificate signing request from memory
 * @param dst A pointer to the pointer that will point to the newly allocated m10k_cert_req structure
 * @param src A pointer to the DER-encoded certification request
 * @param len The length of the memory pointed to by src
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_req_new_from_der(m10k_cert_req **dst, const void *src, const size_t len)
{
	int ret_val;
	m10k_cert_req *req;

	INIT();

	req = NULL;
	ret_val = m10k_salloc(req);

	if(!ret_val) {
		req->req = d2i_X509_REQ(NULL, (const unsigned char**)&src, (long)len);

		if(!req->req) {
			ret_val = -EINVAL;
		} else {
			ret_val = 0;
		}
	}

	if(ret_val < 0) {
		if(req) {
			m10k_cert_req_free(&req);
		}
	} else {
		*dst = req;
	}

	req = NULL;

	return(ret_val);
}

/**
 * m10k_cert_req_new_from_file - Read a m10k_cert_req structure from a file
 * @param dst A pointer to the pointer that will point to the new m10k_cert_req structure
 * @param path The path to the file to read the signing request from
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_req_new_from_file(m10k_cert_req **dst, const char *path)
{
	int ret_val;
	m10k_cert_req *req;
	FILE *fd;

	INIT();

	ret_val = m10k_salloc(req);

	if(ret_val) {
		goto gtfo;
	}

	fd = fopen(path, "r");

	if(!fd) {
		ret_val = -errno;
		m10k_P("fopen", ret_val);
		goto gtfo;
	}

	req->req = PEM_read_X509_REQ(fd, NULL, NULL, NULL);

	if(!req->req) {
		ret_val = -EIO;
	} else {
		ret_val = 0;
	}

	fclose(fd);

gtfo:
	if(ret_val < 0) {
		if(req) {
			m10k_cert_req_free(&req);
		}
	} else {
		*dst = req;
	}

	req = NULL;

	return(ret_val);
}

/**
 * m10k_cert_req_to_file - Write a certificate signing request to a file
 * @param req The request to be written to a file
 * @param path The path of the file to write to
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_req_to_file(m10k_cert_req *req, const char *path)
{
	int ret_val;
	FILE *fd;

	INIT();

	fd = fopen(path, "w+");

	if(!fd) {
		ret_val = -errno;
		m10k_P("fopen", ret_val);
	} else {
		if(!PEM_write_X509_REQ(fd, req->req)) {
			ret_val = -EIO;
		} else {
			ret_val = 0;
		}

		fclose(fd);
	}

	return(ret_val);
}

/**
 * m10k_cert_req_to_der - DER-encode a certificate signing request
 * @param req The certificate signing request to be encoded
 * @param dst The memory where the DER-encoded request shall be stored
 * @param dsize The size of the memory pointed to by dst
 * @return The number of bytes written, or a negative error code (man 3 errno)
 */
int m10k_cert_req_to_der(m10k_cert_req *req, void *dst, const size_t dsize)
{
	int ret_val;
	m10k_u8 buf[8192];
	unsigned char *d;

	INIT();

	d = buf;

	ret_val = i2d_X509_REQ(req->req, &d);

	if(ret_val < 0) {
		ret_val = -EINVAL;
	} else {
		size_t size;

		size = (size_t)ret_val;

		if(dsize < size) {
			size = dsize;
		}

		memcpy(dst, buf, size);
		memset(buf, 0, size);
	}

	return(ret_val);
}

/**
 * m10k_cert_req_sign - Sign a certificate signing request
 * @param req The signing request to be signed
 * @param signer The certificate of the signer
 * @param key The private key that belongs to the certificate of the signer
 * @param dst A pointer to the pointer that will point to the certificate created
 * @return Zero upon success, or a negative error code (man 3 errno)
 */
int m10k_cert_req_sign(m10k_cert_req *req, m10k_cert *signer, m10k_key *key, m10k_cert **dst)
{
	m10k_cert *cert;
	EVP_PKEY *pkey;
	int ret_val;

	INIT();

	cert = NULL;
	pkey = X509_REQ_get_pubkey(req->req);

	if(!pkey) {
		ret_val = -EINVAL;
		goto err;
	}

	ret_val = X509_REQ_verify(req->req, pkey);

	if(ret_val != 1) {
		if(ret_val < 0) {
			ret_val = -EBADMSG;
		} else {
			ret_val = -EKEYREJECTED;
		}
		goto err;
	}

	ret_val = m10k_salloc(cert);

	if(ret_val < 0) {
		goto err;
	}

	cert->cert = X509_new();

	if(!cert->cert) {
		ret_val = -ENOMEM;
		goto err;
	}

	if(!X509_set_pubkey(cert->cert, X509_REQ_get_pubkey(req->req))) {
		ret_val = -EKEYREVOKED;
		goto err;
	}

	if(!X509_set_subject_name(cert->cert, X509_REQ_get_subject_name(req->req)) ||
	   !X509_set_issuer_name(cert->cert, X509_get_subject_name(signer->cert))) {
		ret_val = -ENOMEM;
		goto err;
	}

	ASN1_INTEGER_set(X509_get_serialNumber(cert->cert), signer->next_serial++);
	X509_gmtime_adj(X509_get_notBefore(cert->cert), 0);
	X509_gmtime_adj(X509_get_notAfter(cert->cert), 24 * 60 * 60 * signer->expiration);

	if(!X509_sign(cert->cert, key->key, HASHFUNC)) {
		ret_val = -EIO;
	} else {
		ret_val = 0;
	}

err:
	if(ret_val) {
		if(cert) {
			m10k_cert_free(&cert);
		}
	} else {
		*dst = cert;
	}

	pkey = NULL;
	cert = NULL;

	return(ret_val);
}

/**
 * m10k_cert_req_free - Free the memory occupied by a certificate signing request
 * @param req The certificate signing request to be freed
 */
void m10k_cert_req_free(m10k_cert_req **req)
{
	INIT();

	if((*req)->req) {
		X509_REQ_free((*req)->req);
	}
	m10k_mem_unref((void**)req);

	return;
}

static void __init__(void)
{
	OpenSSL_add_all_algorithms();
	return;
}

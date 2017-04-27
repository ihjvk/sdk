#include "openssl/hmac.h"
#include "openssl/md5.h"
#include "openssl/pem.h"
#include "event2/event.h"
#include "openssl/evp.h"
#include "openssl/ossl_typ.h"
#include "openssl/rsa.h"
#include <openssl/bn.h>  
#include "openssl/err.h"
#include <string>
using namespace std;
class EncryptHelper 
{
public:
	static bool Char2String(unsigned char* data, int data_len, string& s, bool bRaw)
	{
		if (NULL == data || data_len <= 0 )
		{
			return false;
		}
		s.clear();
		if (bRaw)
		{
			s.resize(data_len);
			for(int i = 0; i < data_len; i++) 
			{
				s[i] = data[i];
			}
			
		}
		else
		{
			s.resize(data_len * 2);
			for(int i = 0, k = 0; i < data_len; i++) 
			{  
				sprintf(&s.at(k), "%02x", data[i]);
				k += 2;
			}  
		}
		return true;
	}
	static string HmacSHA1(const char* data, const char* key, bool bHex = true)
	{
		string s;
		if (NULL == data || NULL == key)
		{
			return s;
		}
		
 		unsigned char mac[EVP_MAX_MD_SIZE]; 
		unsigned int mac_length = 0;  
		
		HMAC(EVP_sha1(), key, strlen(key), (unsigned char *)data, strlen(data), (unsigned char *)mac, &mac_length);
	
		Char2String(mac, mac_length, s, !bHex);
		return s;
	}

	static string Sha256(const char* data, bool bHex = true)
	{
		string s;
		if (NULL == data )
		{
			return s;
		}
		unsigned char md[SHA256_DIGEST_LENGTH] = {0};
		SHA256((const unsigned char *)data, strlen(data), md);  
		Char2String(md, SHA256_DIGEST_LENGTH, s, !bHex);
		return s;
	}
	
	static string Sha1(const char* data, bool bHex = true)
	{
		string s;
		if (NULL == data )
		{
			return s;
		}
		unsigned char md[SHA_DIGEST_LENGTH] = {0};
		SHA1((const unsigned char *)data, strlen(data), md);  
		Char2String(md, SHA_DIGEST_LENGTH, s, !bHex);
		return s;
	}

	static string Md5(const char* data, bool bHex = true)
	{
		unsigned char md[MD5_DIGEST_LENGTH] = {0}; 
		string s;

		if (NULL == data)
		{
			return s;
		}

		MD5((unsigned char *)data, strlen(data), md);
		Char2String(md, MD5_DIGEST_LENGTH, s, !bHex);

		return s;
	}
	static string Base64Decode(char * input, int length)  
	{  
		string result;
		static char decode[1024] = {0};
		if (NULL == input || length <= 0 || length >= 1024)
		{
			return result;
		}		
		int len = EVP_DecodeBlock((unsigned char*)decode, (const unsigned char*)input, length);  
		if (len >= 1024 || len <= 0)
		{
			unsigned long ulErr = ERR_get_error(); 
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg); 
			cout << szErrMsg;
			
			return result;
		}
		decode[len] = '\0';
	
		result.resize(len);
		for(int i = 0; i < len; i++) 
		{
			result[i] = decode[i];
		}
		return result;
	}  
	static string Base64Encode(char * input, int length)
	{
		static char encoded[1024] = {0};
		string result;
		if (NULL == input || length <= 0 || length >= 1024)
		{
			return result;
		}
		
		int len = EVP_EncodeBlock((unsigned char*)encoded, (const unsigned char*)input, length);  	
		if (len >= 1024 || len <= 0)
		{
			return result;
		}
		encoded[len] = '\0';
		result.resize(len);
		for(int i = 0; i < len; i++) 
		{
			result[i] = encoded[i];
		}
		return result;
	}

	static string UrlEncode(const char* data)
	{
		string s; 
		if (NULL == data)
		{
			return s;
		}
		char* p = evhttp_encode_uri(data);

		if (NULL == p)
		{
			return s;
		}
		s = string(p); 
		return s;
	}

	static string UrlDecode(const char* data, bool decode_plus = true)
	{
		string s; 
		if (NULL == data)
		{
			return s;
		}
		size_t len = 0;
		char *p = NULL;
		if (decode_plus)
		{
			p = evhttp_uridecode(data, 1, &len);
		}
		else
		{
			p = evhttp_decode_uri(data);
		}
		
		if (NULL == p)
		{
			return s;
		}
		s = string(p); 
		return s;
	}


	static string RSASignWithMd5(string& strBase, RSA* pPrivateRSA)
	{
		if (NULL == pPrivateRSA)
		{
			return "";
		}
		
		static unsigned char encrypted[1024] = {0};
		int iSignlen = sizeof(encrypted);
		
		string hash = EncryptHelper::Md5(strBase.c_str(),false); 
		int iDatalen = MD5_DIGEST_LENGTH;
		int res = RSA_sign(NID_md5, (const unsigned char*)hash.c_str(), iDatalen,encrypted,(unsigned int *)&iSignlen, pPrivateRSA);
		if (res != 1)
		{
			unsigned long ulErr = ERR_get_error();
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg);
			
			return "";
		}
		string sign = EncryptHelper::Base64Encode((char *)encrypted, iSignlen);
		
		return sign;
	}

	static string RSASign(string& strBase, RSA* pPrivateRSA)
	{
		if (NULL == pPrivateRSA)
		{
			return "";
		}
		
		static unsigned char encrypted[1024] = {0};
		int iSignlen = sizeof(encrypted);
		
		string hash = EncryptHelper::Sha1(strBase.c_str(),false); 
		int iDatalen = SHA_DIGEST_LENGTH;
		int res = RSA_sign(NID_sha1, (const unsigned char*)hash.c_str(), iDatalen,encrypted,(unsigned int *)&iSignlen, pPrivateRSA);
		if (res != 1)
		{
			unsigned long ulErr = ERR_get_error(); 
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg); 
			
			return "";
		}
		string sign = EncryptHelper::Base64Encode((char *)encrypted, iSignlen);
		
		return sign;
	}
	static bool RSAVerifyWithSHA256(string& strBase, string& strSign, RSA* pPubilcKey)
	{
		if (NULL == pPubilcKey)
		{
			return false;
		}
		string hash = EncryptHelper::Sha256(strBase.c_str(),false); 
		string sign = EncryptHelper::Base64Decode((char *)strSign.c_str(), strlen(strSign.c_str()));
		int sign_len = 256; 
		int hash_len = SHA256_DIGEST_LENGTH;
		int res = RSA_verify(NID_sha256, (const unsigned char*)hash.c_str(), hash_len/*strlen(hash.c_str())*/, (unsigned char*)sign.c_str(),sign_len, pPubilcKey);  
		if (res == 1)
		{
			return true;
		}
		else
		{
			unsigned long ulErr = ERR_get_error(); 
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg); 
			return false;
		}
	}
	static bool	RSAVerifyWithSHA1(string& strBase, string& strSign, RSA* pPubilcKey)
	{
		if (NULL == pPubilcKey)
		{
			return false;
		}
		string sign = EncryptHelper::Base64Decode((char *)strSign.c_str(), strlen(strSign.c_str()));
		string hash = EncryptHelper::Sha1(strBase.c_str(),false); 
		int hash_len  = SHA_DIGEST_LENGTH;
		int sign_len = sign.length();
		if (sign_len < 128)
		{
			sign_len = 64;
		}
		else if ( sign_len < 256)
		{
			sign_len = 128;
		}
		else
		{
			sign_len = 256;
		}

		int res = RSA_verify(NID_sha1, (const unsigned char*)hash.c_str(), hash_len/*strlen(hash.c_str())*/, (unsigned char*)sign.c_str(),sign_len, pPubilcKey);  
		if (res != 1)
		{
			unsigned long ulErr = ERR_get_error();
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg);

			return false;
		}
		return true;
	}
	static RSA* GetPublicKeyRSA(string strPublicKey)
	{
		int nPublicKeyLen = strPublicKey.size();     
		for(int i = 64; i < nPublicKeyLen; i+=64)
		{
			if(strPublicKey[i] != '\n')
			{
				strPublicKey.insert(i, "\n");
			}
			i++;
		}
		strPublicKey.insert(0, "-----BEGIN PUBLIC KEY-----\n");
		strPublicKey.append("\n-----END PUBLIC KEY-----\n");

		BIO *bio = NULL; 
		RSA *rsa = NULL; 
		char *chPublicKey = const_cast<char *>(strPublicKey.c_str());
		if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)      
		{     
			cout<<"BIO_new_mem_buf failed!"<<endl;      
		}       
		rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);  
		if (NULL == rsa)
		{
			BIO_free_all(bio);
			unsigned long ulErr = ERR_get_error();
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg);
			
		}
		return rsa;	
	}

	static RSA* GetPrivateKeyRSA(string strPrivateKey)
	{
		int nKeyLen = strPrivateKey.size();  
		for(int i = 64; i < nKeyLen; i+=64)
		{
			if(strPrivateKey[i] != '\n')
			{
				strPrivateKey.insert(i, "\n");
			}
			i++;
		}
		strPrivateKey.insert(0, "-----BEGIN PRIVATE KEY-----\n");
		strPrivateKey.append("\n-----END PRIVATE KEY-----\n");
	
		BIO *bio = NULL; 
		RSA *rsa = NULL; 
		char *chPublicKey = const_cast<char *>(strPrivateKey.c_str());
		if ((bio = BIO_new_mem_buf(chPublicKey, -1)) == NULL)    
		{     
			cout<<"BIO_new_mem_buf failed!"<<endl;      
		}   
		rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
		if (NULL == rsa)
		{
			BIO_free_all(bio);
			unsigned long ulErr = ERR_get_error();
			static char szErrMsg[1024] = {0};
			char *pTmp = NULL;
			pTmp = ERR_error_string(ulErr,szErrMsg); 
			
		}	
		return rsa;	
	}

};

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

extern "C" {
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/ossl_typ.h>
}

#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>

#include "bank.h"

static BIO *dout;
static BIO *mout;

const char _NL[]="\n";

void SetDumper(BIO *out)
    {
    dout=out;
    if(!mout)
	mout=out;
    }

void SetDumper(FILE *f)
    {
    BIO *out=BIO_new(BIO_s_file());
    assert(out);
    BIO_set_fp(out,f,BIO_NOCLOSE);
    SetDumper(out);
    }

void SetMonitor(BIO *out)
    { mout=out; }

void SetMonitor(FILE *f)
    {
    BIO *out=BIO_new(BIO_s_file());
    assert(out);
    BIO_set_fp(out,f,BIO_NOCLOSE);
    SetMonitor(out);
    }

BIGNUM *ReadNumber(BIO *in,const char *szTitle)
    {
    // Preserve the former 1024-byte numeric limit without writing past it.
    // In particular, old broken mints containing "(null)" must never become
    // small private keys through unchecked sscanf conversions.
    char line[4096];
    const int count=BIO_gets(in,line,sizeof line);
    if(count <= 0)
        throw std::runtime_error("Missing Lucre number");
    std::string text(line,static_cast<std::size_t>(count));
    const std::size_t titleLength=strlen(szTitle);
    if(text.compare(0,titleLength,szTitle) != 0)
        throw std::runtime_error("Unexpected Lucre number label");
    text.erase(0,titleLength);
    if(!text.empty() && text.back() == '\n') text.pop_back();
    if(!text.empty() && text.back() == '\r') text.pop_back();
    if(text.empty() || text.size() > 2048 ||
       text.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
        throw std::runtime_error("Invalid Lucre hexadecimal number");
    BIGNUM *number=NULL;
    if(BN_hex2bn(&number,text.c_str()) != static_cast<int>(text.size()))
        {
        BN_free(number);
        throw std::runtime_error("Unable to parse Lucre number");
        }
    return number;
    }

void DumpNumber(BIO *out,const char *szTitle,const BIGNUM *bn,
		const char *szTrailer)
    {
    if(!out)
	return;
    BIO_puts(out,szTitle);
    if(!bn)
	BIO_puts(out,"(null)");
    else
	BN_print(out,bn);
    BIO_puts(out,szTrailer);
    }

void DumpNumber(const char *szTitle,const BIGNUM *bn,const char *szTrailer)
    { DumpNumber(dout,szTitle,bn,szTrailer); }

void HexDump(BIO *out,const char *szTitle,const unsigned char *acBuf,
	     int nLength)
    {
    if(!out)
	return;
    BIO_puts(out,szTitle);
    for(int n=0 ; n < nLength ; ++n)
	{
	char buf[3];
	sprintf(buf,"%02X",acBuf[n]);
	BIO_puts(out,buf);
	}
    BIO_puts(out,"\n");
    }

void HexDump(const char *szTitle,const unsigned char *acBuf,int nLength)
    { HexDump(dout,szTitle,acBuf,nLength); }

PublicBank::PublicBank(Bank &bank)
    {
    std::unique_ptr<DH, decltype(&DH_free)> dh(DH_new(), DH_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> prime(BN_dup(bank.p()), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> generator(BN_dup(bank.g()), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> publicKey(BN_dup(bank.pub_key()), BN_free);
    if(!dh || !prime || !generator || !publicKey ||
       !DH_set0_pqg(dh.get(), prime.get(), NULL, generator.get()))
        throw std::runtime_error("Unable to copy mint parameters");
    prime.release();
    generator.release();
    if(!DH_set0_key(dh.get(), publicKey.get(), NULL))
        throw std::runtime_error("Unable to copy mint public key");
    publicKey.release();
    m_pDH=dh.release();
    }

void Bank::cb(int n, int, void * /*arg*/)
    {
    if(!mout)
	return;

    char c='*';

    if (n == 0) c='.';
    if (n == 1) c='+';
    if (n == 2) c='*';
    if (n == 3) c='\n';
    BIO_write(mout,&c,1);
    BIO_flush(mout);
    }

/*const*/ BIGNUM *Bank::SignRequest(PublicCoinRequest &req)
    {
    InitCTX();

    BIGNUM *BtoA=BN_new();
    BN_mod_exp(BtoA,req.Request(),priv_key(),p(),m_ctx);
    DumpNumber("B->A=     ",BtoA);

    return BtoA;
    }

boolean Bank::Verify(Coin &coin)
    {
    InitCTX();

    BIGNUM *t=BN_new();
    if(!coin.GenerateCoinNumber(t,*this))
	return false;
    BN_mod_exp(t,t,priv_key(),p(),m_ctx);
    DumpNumber("y^k=      ",t);

    BN_sub(t,t,coin.Signature());
    boolean bRet=BN_is_zero(t);

    BN_free(t);

    return bRet;
    }

void Bank::WriteBIO(BIO *bio)
    {
    PublicBank::WriteBIO(bio);
    DumpNumber(bio,"private=",priv_key());
    }

void Bank::ReadBIO(BIO *bio)
    {
    PublicBank::ReadBIO(bio);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> privateKey(ReadNumber(bio,"private="), BN_free);
    if(!privateKey || !DH_set0_key(m_pDH, NULL, privateKey.get()))
        throw std::runtime_error("Unable to load mint private key");
    privateKey.release();
    }

void PublicBank::WriteBIO(BIO *bio)
    {
    DumpNumber(bio,"g=",g());
    DumpNumber(bio,"p=",p());
    DumpNumber(bio,"public=",pub_key());
    }

void PublicBank::ReadBIO(BIO *bio)
    {
    std::unique_ptr<DH, decltype(&DH_free)> dh(DH_new(), DH_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> generator(ReadNumber(bio,"g="), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> prime(ReadNumber(bio,"p="), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> publicKey(ReadNumber(bio,"public="), BN_free);
    if(!dh || !prime || !generator || !publicKey ||
       !DH_set0_pqg(dh.get(), prime.get(), NULL, generator.get()))
        throw std::runtime_error("Unable to load mint parameters");
    prime.release();
    generator.release();
    if(!DH_set0_key(dh.get(), publicKey.get(), NULL))
        throw std::runtime_error("Unable to load mint public key");
    publicKey.release();
    DH_free(m_pDH);
    m_pDH=dh.release();

    Dump();
    }

void UnsignedCoin::WriteBIO(BIO *bio)
    {
    DumpNumber(bio,"id=",m_bnCoinID);
    }

void UnsignedCoin::ReadBIO(BIO *bio)
    {
    m_bnCoinID=ReadNumber(bio,"id=");
    }

void Coin::WriteBIO(BIO *bio)
    {
    UnsignedCoin::WriteBIO(bio);
    DumpNumber(bio,"signature=",m_bnCoinSignature);
    }

void Coin::ReadBIO(BIO *bio)
    {
    UnsignedCoin::ReadBIO(bio);
    m_bnCoinSignature=ReadNumber(bio,"signature=");
    Dump();
    }

void PublicCoinRequest::WriteBIO(BIO *bio)
    {
    DumpNumber(bio,"request=",m_bnCoinRequest);
    }

void PublicCoinRequest::ReadBIO(BIO *bio)
    {
    m_bnCoinRequest=ReadNumber(bio,"request=");
    }

void CoinRequest::WriteBIO(BIO *bio)
    {
    PublicCoinRequest::WriteBIO(bio);
    m_coin.WriteBIO(bio);
    DumpNumber(bio,"blinding=",m_bnBlindingFactor);
    }

void CoinRequest::ReadBIO(BIO *bio)
    {
    PublicCoinRequest::ReadBIO(bio);
    m_coin.ReadBIO(bio);
    m_bnBlindingFactor=ReadNumber(bio,"blinding=");

    Dump();
    }


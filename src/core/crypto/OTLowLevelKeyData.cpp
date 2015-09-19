/************************************************************
 *
 *                 OPEN TRANSACTIONS
 *
 *       Financial Cryptography and Digital Cash
 *       Library, Protocol, API, Server, CLI, GUI
 *
 *       -- Anonymous Numbered Accounts.
 *       -- Untraceable Digital Cash.
 *       -- Triple-Signed Receipts.
 *       -- Cheques, Vouchers, Transfers, Inboxes.
 *       -- Basket Currencies, Markets, Payment Plans.
 *       -- Signed, XML, Ricardian-style Contracts.
 *       -- Scripted smart contracts.
 *
 *  EMAIL:
 *  fellowtraveler@opentransactions.org
 *
 *  WEBSITE:
 *  http://www.opentransactions.org/
 *
 *  -----------------------------------------------------
 *
 *   LICENSE:
 *   This Source Code Form is subject to the terms of the
 *   Mozilla Public License, v. 2.0. If a copy of the MPL
 *   was not distributed with this file, You can obtain one
 *   at http://mozilla.org/MPL/2.0/.
 *
 *   DISCLAIMER:
 *   This program is distributed in the hope that it will
 *   be useful, but WITHOUT ANY WARRANTY; without even the
 *   implied warranty of MERCHANTABILITY or FITNESS FOR A
 *   PARTICULAR PURPOSE.  See the Mozilla Public License
 *   for more details.
 *
 ************************************************************/

#include <opentxs/core/stdafx.hpp>

#include <opentxs/core/crypto/mkcert.hpp>
#include <opentxs/core/crypto/OTLowLevelKeyData.hpp>

#include <opentxs/core/crypto/OTKeypair.hpp>
#include <opentxs/core/Log.hpp>

#if defined(OT_CRYPTO_USING_OPENSSL)

#include <opentxs/core/crypto/OTAsymmetricKey_OpenSSLPrivdp.hpp>

#ifdef __APPLE__
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif

namespace opentxs
{

class OTLowLevelKeyData::OTLowLevelKeyDataOpenSSLdp
{
public:
    X509* m_pX509=nullptr;
    EVP_PKEY* m_pKey=nullptr; // Instantiated form of key. (For private keys especially,
                      // we don't want it instantiated for any longer than
                      // absolutely necessary.)
};

} // namespace opentxs

#endif

namespace opentxs
{

OTLowLevelKeyData::~OTLowLevelKeyData()
{
    if (m_bCleanup) Cleanup();
    if (nullptr != dp) delete (dp);
}

#if defined(OT_CRYPTO_USING_OPENSSL)

OTLowLevelKeyData::OTLowLevelKeyData()
    : m_bCleanup(true)
{
    dp = new OTLowLevelKeyDataOpenSSLdp();
    dp->m_pX509 = nullptr;
    dp->m_pKey = nullptr;
}

// Don't force things by explicitly calling this function, unless you are SURE
// there's no one else cleaning up the same objects. Notice the if (m_bCleanup)
// just above in the destructor, for that very reason.
//
void OTLowLevelKeyData::Cleanup()
{
    if (nullptr != dp->m_pKey) EVP_PKEY_free(dp->m_pKey);
    dp->m_pKey = nullptr;
    if (nullptr != dp->m_pX509) X509_free(dp->m_pX509);
    dp->m_pX509 = nullptr;
}

bool OTLowLevelKeyData::MakeNewKeypair(int32_t nBits)
{

    //    OpenSSL_BIO        bio_err    =    nullptr;
    X509* x509 = nullptr;
    EVP_PKEY* pNewKey = nullptr;

    //    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON); // memory leak detection.
    // Leaving this for now.
    //    bio_err    =    BIO_new_fp(stderr, BIO_NOCLOSE);

    // actually generate the things. // TODO THESE PARAMETERS...(mkcert)
    mkcert(&x509, &pNewKey, nBits, 0, 3650); // 3650=10 years. Todo hardcoded.
    // Note: 512 bit key CRASHES
    // 1024 is apparently a minimum requirement, if not an only requirement.
    // Will need to go over just what sorts of keys are involved here... todo.

    if (nullptr == x509) {
        otErr << __FUNCTION__
              << ": Failed attempting to generate new x509 cert.\n";

        if (nullptr != pNewKey) EVP_PKEY_free(pNewKey);
        pNewKey = nullptr;

        return false;
    }

    if (nullptr == pNewKey) {
        otErr << __FUNCTION__
              << ": Failed attempting to generate new private key.\n";

        if (nullptr != x509) X509_free(x509);
        x509 = nullptr;

        return false;
    }

    // Below this point, x509 and pNewKey will need to be cleaned up properly.

    if (m_bCleanup) Cleanup();

    m_bCleanup = true;
    dp->m_pKey = pNewKey;
    dp->m_pX509 = x509;

    // --------COMMENT THIS OUT FOR PRODUCTION --------  TODO security
    //                  (Debug only.)
    //    RSA_print_fp(stdout, pNewKey->pkey.rsa, 0); // human readable
    //    X509_print_fp(stdout, x509); // human readable

    // --------COMMENT THIS OUT FOR PRODUCTION --------  TODO security
    //                  (Debug only.)
    // write the private key, then the x509, to stdout.

    //    OTPasswordData thePWData2("OTPseudonym::GenerateNym is calling
    // PEM_write_PrivateKey...");
    //
    //    PEM_write_PrivateKey(stdout, pNewKey, EVP_des_ede3_cbc(), nullptr, 0,
    // OTAsymmetricKey::GetPasswordCallback(), &thePWData2);
    //    PEM_write_X509(stdout, x509);

    return true;
}

bool OTLowLevelKeyData::SetOntoKeypair(OTKeypair& theKeypair)
{
    OT_ASSERT(nullptr != dp->m_pKey);
    OT_ASSERT(nullptr != dp->m_pX509);

    OT_ASSERT(nullptr != theKeypair.m_pkeyPublic);
    OT_ASSERT(nullptr != theKeypair.m_pkeyPrivate);

    // Since we are in OpenSSL-specific code, we have to make sure these are
    // OpenSSL-specific keys.
    //
    OTAsymmetricKey_OpenSSL* pPublicKey =
        dynamic_cast<OTAsymmetricKey_OpenSSL*>(theKeypair.m_pkeyPublic);
    OTAsymmetricKey_OpenSSL* pPrivateKey =
        dynamic_cast<OTAsymmetricKey_OpenSSL*>(theKeypair.m_pkeyPrivate);

    if (nullptr == pPublicKey) {
        otErr << __FUNCTION__ << ": dynamic_cast to OTAsymmetricKey_OpenSSL "
                                 "failed. (theKeypair.m_pkeyPublic)\n";
        return false;
    }
    if (nullptr == pPrivateKey) {
        otErr << __FUNCTION__ << ": dynamic_cast to OTAsymmetricKey_OpenSSL "
                                 "failed. (theKeypair.m_pkeyPrivate)\n";
        return false;
    }

    // Now we can call OpenSSL-specific methods on these keys...
    //
    pPublicKey->SetAsPublic();
    //  EVP_PKEY * pEVP_PubKey = X509_get_pubkey(m_pX509);
    //  OT_ASSERT(nullptr != pEVP_PubKey);
    //  pPublicKey-> SetKeyAsCopyOf(*pEVP_PubKey); // bool bIsPrivateKey=false
    // by default.
    pPublicKey->dp->SetKeyAsCopyOf(
        *dp->m_pKey); // bool bIsPrivateKey=false by default.
                      //  EVP_PKEY_free(pEVP_PubKey);
                      //  pEVP_PubKey = nullptr;

    pPublicKey->dp->SetX509(dp->m_pX509); // m_pX509 is now owned by pPublicKey.
                                          // (No need to free it in our own
                                          // destructor anymore.)
    dp->m_pX509 =
        nullptr; // pPublicKey took ownership, so we don't want to ALSO
                 // clean it up, since pPublicKey already will do so.

    pPrivateKey->SetAsPrivate();
    pPrivateKey->dp->SetKeyAsCopyOf(
        *dp->m_pKey, true); // bool bIsPrivateKey=true; (Default is false)
    // Since pPrivateKey only takes a COPY of m_pKey, we are still responsible
    // to clean up m_pKey in our own destructor.
    // (Assuming m_bCleanup is set to true, which is the default.) That's why
    // I'm NOT setting it to nullptr, as I did above
    // with m_pX509.

    EVP_PKEY_free(dp->m_pKey);
    dp->m_pKey = nullptr;

    // Success! At this point, theKeypair's public and private keys have been
    // set.
    // Keep in mind though, they still won't be "quite right" until saved and
    // loaded
    // again, at least according to existing logic. That saving/reloading is
    // currently
    // performed in OTPseudonym::GenerateNym().
    //
    return true;
}

#elif defined(OT_CRYPTO_USING_GPG)

#else

#endif

} // namespace opentxs

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

#include <opentxs/cash/Purse.hpp>
#include <opentxs/cash/Token.hpp>

#include <opentxs/core/crypto/OTSymmetricKey.hpp>
#include <opentxs/core/crypto/OTCachedKey.hpp>
#include <opentxs/core/crypto/OTEnvelope.hpp>
#include <opentxs/core/crypto/OTNymOrSymmetricKey.hpp>
#include <opentxs/core/crypto/OTPassword.hpp>
#include <opentxs/core/util/OTFolders.hpp>
#include <opentxs/core/util/Tag.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/OTStorage.hpp>

#include <irrxml/irrXML.hpp>

namespace opentxs
{

typedef std::map<std::string, Token*> mapOfTokenPointers;

bool Purse::GetNymID(Identifier& theOutput) const
{
    bool bSuccess = false;
    theOutput.Release();

    if (IsPasswordProtected()) {
        bSuccess = false; // optimizer will remove automatically anyway, I
                          // assume. Might as well have it here for clarity.
    }
    else if (IsNymIDIncluded() && !m_NymID.IsEmpty()) {
        bSuccess = true;
        theOutput = m_NymID;
    }
    else if (!m_NymID.IsEmpty()) {
        bSuccess = true;
        theOutput = m_NymID;
    }

    return bSuccess;
}

// Retrieves the passphrase for this purse (which is cached by its master key.)
// Prompts the user to enter his actual passphrase, if necessary to unlock it.
// (May not need unlocking yet -- there is a timeout.)
//
bool Purse::GetPassphrase(OTPassword& theOutput, const char* szDisplay)
{
    const char* szFunc = "Purse::GetPassphrase";

    if (!IsPasswordProtected()) {
        otOut << szFunc
              << ": Failed: this purse isn't even password-protected.\n";
        return false;
    }

    std::shared_ptr<OTCachedKey> pCachedKey(GetInternalMaster());
    if (!pCachedKey) OT_FAIL;

    const String strReason((nullptr == szDisplay) ? szFunc : szDisplay);

    const bool bGotMasterPassword = pCachedKey->GetMasterPassword(
        pCachedKey, theOutput, strReason.Get()); // bVerifyTwice=false
    return bGotMasterPassword;
}

// Don't ever deal with m_pCachedKey directly (except before it's been created /
// loaded.)
// When you actually USE m_pCachedKey, you want to use this function instead.
// (It will save the user from having the type the password, for example, 50
// times in 1 minute,
// by using the cached one.)

// stores the passphrase for the symmetric key.
std::shared_ptr<OTCachedKey> Purse::GetInternalMaster()
{

    if (!IsPasswordProtected() ||
        (!m_pCachedKey)) // this second half of the logic should never happen.
    {
        otOut << __FUNCTION__
              << ": Failed: no internal master key exists, in this purse.\n";
        return std::shared_ptr<OTCachedKey>();
    }

    if (!m_pCachedKey->IsGenerated()) // should never happen, since the purse IS
                                      // password-protected... then where's the
                                      // master key?
    {
        otOut << __FUNCTION__
              << ": Error: internal master key has not yet been generated.\n";
        return std::shared_ptr<OTCachedKey>();
    }

    // By this point we know the purse is password protected, the internal
    // master key
    // exists (not nullptr) and it's been properly generated, so we won't be
    // inadvertantly sticking
    // a copy of it on the CachedKey map indexed to some nonexistent ID for an
    // ungenerated key.
    // The caller will be forced to make sure the master key is real and
    // generated, before passing
    // it in here where it could get copied.
    //
    // Why is that important? BECAUSE THE COPY is all the caller will ever
    // actually use! So if it's
    // not ENTIRELY loaded up properly BEFORE it's copied, the caller will never
    // see the properly
    // loaded version of that master key.
    //
    return OTCachedKey::It(*m_pCachedKey); // here we return a cached copy of
                                           // the master key (so it's available
                                           // between instances of this purse.)
}

// INTERNAL KEY: For adding a PASSPHRASE to a PURSE.
//
// What if you DON'T want to encrypt the purse to your Nym??
// What if you just want to use a passphrase instead?
// That's what these functions are for. OT just generates
// a symmetric key and stores it INSIDE THE PURSE. You set the
// passphrase for the symmetric key, and thereafter your
// experience is one of a password-protected purse.
//
bool Purse::GenerateInternalKey()
{
    if (IsPasswordProtected() ||
        (nullptr != m_pSymmetricKey) || // GetInternalKey())
        (m_pCachedKey)) {
        otOut << __FUNCTION__
              << ": Failed: internal Key  or master key already exists. "
                 "Or IsPasswordProtected was true.\n";
        return false;
    }

    if (!IsEmpty()) {
        otOut << __FUNCTION__
              << ": Failed: The purse must be EMPTY before you create a "
                 "new symmetric key, internal to that purse. (For the purposes "
                 "of "
                 "adding a passphrase to the purse, normally.) Otherwise I "
                 "would have "
                 "to loop through all the tokens and re-assign ownership of "
                 "each one. "
                 "Instead, I'm just going to return false. That's easier.\n";
        return false;
    }

    //  OTSymmetricKey *   m_pSymmetricKey;    // If this purse contains its own
    // symmetric key (instead of using an owner Nym)...
    //  OTCachedKey    *   m_pCachedKey;       // ...then it will have a master
    // key as well, for unlocking that symmetric key, and managing timeouts.

    // m_pSymmetricKey and m_pCachedKey are both explicitly checked for nullptr
    // (above.)
    // Therefore we have to instantiate them both now.
    //
    // We'll do the Master key first, since we need the passphrase from that, in
    // order to
    // create the symmetric key.
    //
    OTPassword thePassphrase;
    const String strDisplay(
        "Enter the new passphrase for this new password-protected "
        "purse."); // todo internationalization / hardcoding.

    // thePassphrase and m_pCachedKey are BOTH output from the below function.
    //
    m_pCachedKey = OTCachedKey::CreateMasterPassword(
        thePassphrase,
        strDisplay.Get()); // int32_t nTimeoutSeconds=OT_MASTER_KEY_TIMEOUT)

    if ((!m_pCachedKey) || !m_pCachedKey->IsGenerated()) // This one is
                                                         // unnecessary because
                                                         // CreateMasterPassword
                                                         // already checks it.
                                                         // todo optimize.
    {
        otOut << __FUNCTION__
              << ": Failed: While calling OTCachedKey::CreateMasterPassword.\n";
        return false;
    }

    m_pSymmetricKey =
        new OTSymmetricKey(thePassphrase); // Creates the symmetric key here
                                           // based on the passphrase from
                                           // purse's master key.
    OT_ASSERT(nullptr != m_pSymmetricKey);

    if (!m_pSymmetricKey->IsGenerated()) {
        otOut << __FUNCTION__ << ": Failed: generating m_pSymmetricKey.\n";
        delete m_pSymmetricKey;
        m_pSymmetricKey = nullptr;
        m_pCachedKey.reset();
        return false;
    }

    m_NymID.Release();
    m_bIsNymIDIncluded = false;

    otWarn << __FUNCTION__
           << ": Successfully created a purse's internal key.\n";

    m_bPasswordProtected = true;

    std::shared_ptr<OTCachedKey> pCachedMaster(Purse::GetInternalMaster());
    if (!pCachedMaster)
        otErr << __FUNCTION__
              << ": Failed trying to cache the master key for this purse.\n";

    return true;
}

// Take all the tokens from a purse and add them to this purse.
// Don't allow duplicates.
//
bool Purse::Merge(const Nym& theSigner,
                  OTNym_or_SymmetricKey theOldNym, // must be private, if a nym.
                  OTNym_or_SymmetricKey theNewNym, // must be private, if a nym.
                  Purse& theNewPurse)
{
    const char* szFunc = "Purse::Merge";

    mapOfTokenPointers theMap;

    while (Count() > 0) {
        Token* pToken = Pop(theOldNym); // must be private, if a Nym.
        OT_ASSERT_MSG(nullptr != pToken,
                      "Purse::Merge: Assert: nullptr != Pop(theOldNym) \n");

        const OTASCIIArmor& ascTokenID = pToken->GetSpendable();

        std::list<mapOfTokenPointers::iterator> listOfTokenMapIterators;

        // I just popped a Token off of *this. Let's see if it's in my temporary
        // map...
        // If it's already there, then just delete it (duplicate).
        //
        for (auto it(theMap.begin()); it != theMap.end(); ++it) {
            Token* pTempToken = it->second;
            OT_ASSERT(nullptr != pTempToken);

            const OTASCIIArmor& ascTempTokenID = pTempToken->GetSpendable();

            // It's already there. Delete the one that's already there.
            // (That way we can add it after, whether it was there originally or
            // not.)
            if (ascTempTokenID == ascTokenID) {
                listOfTokenMapIterators.push_back(it);
                //                theMap.erase(it);
                //                delete pTempToken;
                //              pTempToken = nullptr;
                // break; // In case there are multiple duplicates, not just
                // one.
            }
        }
        while (!listOfTokenMapIterators.empty()) {
            Token* pTempToken = (listOfTokenMapIterators.back())->second;
            theMap.erase(listOfTokenMapIterators.back());
            delete pTempToken;
            pTempToken = nullptr;
            listOfTokenMapIterators.pop_back();
        }

        // Now we know there aren't any duplicates on the temporary map, let's
        // add the token to it.
        std::string theKey = ascTokenID.Get();
        theMap.insert(std::pair<std::string, Token*>(theKey, pToken));
    }
    // At this point, all of the tokens on *this have been popped, and added
    // to the temporary map as token pointers, with any duplicates removed.

    // Basically now I just want to do the exact same thing with the other
    // purse...
    //
    while (theNewPurse.Count() > 0) {
        Token* pToken = theNewPurse.Pop(theNewNym);
        OT_ASSERT_MSG(
            nullptr != pToken,
            "Purse::Merge: Assert: nullptr != theNewPurse.Pop(theNewNym) \n");

        const OTASCIIArmor& ascTokenID = pToken->GetSpendable();

        std::list<mapOfTokenPointers::iterator> listOfTokenMapIterators;

        // I just popped a Token off of theNewPurse. Let's see if it's in my
        // temporary map...
        // If it's already there, then just delete it (it's a duplicate.)
        for (auto it(theMap.begin()); it != theMap.end(); ++it) {
            Token* pTempToken = it->second;
            OT_ASSERT(nullptr != pTempToken);

            const OTASCIIArmor& ascTempTokenID = pTempToken->GetSpendable();

            // It's already there. Delete the one that's already there.
            // (That way we can add it after, whether it was there originally or
            // not.)
            if (ascTempTokenID == ascTokenID) {
                listOfTokenMapIterators.push_back(it);
                //                theMap.erase(it);
                //                delete pTempToken;
                //              pTempToken = nullptr;
                // break; // In case there are multiple duplicates, not just
                // one.
            }
        }
        while (!listOfTokenMapIterators.empty()) {
            Token* pTempToken = (listOfTokenMapIterators.back())->second;
            theMap.erase(listOfTokenMapIterators.back());
            delete pTempToken;
            pTempToken = nullptr;
            listOfTokenMapIterators.pop_back();
        }
        // Now we KNOW there aren't any duplicates on the temporary map, so
        // let's
        // add the token to it...
        //
        std::string theKey = ascTokenID.Get();
        theMap.insert(std::pair<std::string, Token*>(theKey, pToken));

        //
        // SINCE THE new purse is being MERGED into the old purse, we don't have
        // to re-assign ownership
        // of any of the old tokens. But we DO need to re-assign ownership of
        // the NEW tokens that are being
        // merged in. We reassign them from New ==> TO OLD. (And we only bother
        // if they aren't the same Nym.)
        //
        //      if (!theNewNym.CompareID(theOldNym)) // Not the same
        // Nym!!
        //
        // UPDATE: the above line was moved INSIDE OTToken::ReassignOwnership,
        // FYI.
        //
        if (false ==
            pToken->ReassignOwnership(theNewNym,  // must be private, if a Nym.
                                      theOldNym)) // can be public, if a Nym.
        {
            otErr << szFunc << ": Error: Failed while attempting to re-assign "
                               "ownership of token during purse merge.\n";
        }
        else {
            otWarn << szFunc << ": FYI: Success re-assigning ownership of "
                                "token during purse merge.\n";

            pToken->ReleaseSignatures();
            pToken->SignContract(theSigner);
            pToken->SaveContract();
        }
    }

    // At this point, all of the tokens on *this (old purse) AND theNewPurse
    // have been popped, and added
    // to the temporary map as token pointers, with any duplicates removed.
    // Also, the tokens on the New Purse have been reassigned (from theNewNym as
    // owner, to theOldNym as
    // owner) and each has been signed and saved properly, using the old Nym.

    // Next, we loop through theMap, and Push ALL of those tokens back onto
    // *this. (The old purse.)

    bool bSuccess = true;

    for (auto& it : theMap) {
        Token* pToken = it.second;
        OT_ASSERT(nullptr != pToken);

        bool bPush = Push(theOldNym, // can be public, if a Nym.
                          *pToken);  // The purse makes it's own copy of
                                     // the token, into string form.

        if (!bPush) {
            otErr << szFunc << ": Error: Failure pushing token into purse.\n";
            bSuccess = false;
        }
        // Notice we don't break here if 1 token fails -- we loop through them
        // all.
        // Maybe shouldn't? Seems right somehow.
    }

    // Next I clean up all the tokens out of the temporary map, since they will
    // leak otherwise.
    //
    while (!theMap.empty()) {
        Token* pToken = theMap.begin()->second;
        OT_ASSERT(nullptr != pToken);

        delete pToken;
        pToken = nullptr;

        theMap.erase(theMap.begin());
    }

    // Note: Caller needs to re-sign and re-save this purse, since we aren't
    // doing it
    // internally here.

    return bSuccess;
}

// static -- class factory.
//
Purse* Purse::LowLevelInstantiate(const String& strFirstLine,
                                  const Identifier& NOTARY_ID,
                                  const Identifier& INSTRUMENT_DEFINITION_ID)
{
    Purse* pPurse = nullptr;
    if (strFirstLine.Contains("-----BEGIN SIGNED PURSE-----")) // this string is
                                                               // 28 chars long.
                                                               // todo
                                                               // hardcoding.
    {
        pPurse = new Purse(NOTARY_ID, INSTRUMENT_DEFINITION_ID);
        OT_ASSERT(nullptr != pPurse);
    }
    return pPurse;
}

Purse* Purse::LowLevelInstantiate(const String& strFirstLine,
                                  const Identifier& NOTARY_ID)
{
    Purse* pPurse = nullptr;
    if (strFirstLine.Contains("-----BEGIN SIGNED PURSE-----")) // this string is
                                                               // 28 chars long.
                                                               // todo
                                                               // hardcoding.
    {
        pPurse = new Purse(NOTARY_ID);
        OT_ASSERT(nullptr != pPurse);
    }
    return pPurse;
}

Purse* Purse::LowLevelInstantiate(const String& strFirstLine)
{
    Purse* pPurse = nullptr;
    if (strFirstLine.Contains("-----BEGIN SIGNED PURSE-----")) // this string is
                                                               // 28 chars long.
                                                               // todo
                                                               // hardcoding.
    {
        pPurse = new Purse();
        OT_ASSERT(nullptr != pPurse);
    }
    return pPurse;
}

// static -- class factory.
//
// Checks the notaryID / InstrumentDefinitionID, so you don't have to.
//
Purse* Purse::PurseFactory(String strInput, const Identifier& NOTARY_ID,
                           const Identifier& INSTRUMENT_DEFINITION_ID)
{
    String strContract, strFirstLine; // output for the below function.
    const bool bProcessed =
        Contract::DearmorAndTrim(strInput, strContract, strFirstLine);

    if (bProcessed) {
        Purse* pPurse = Purse::LowLevelInstantiate(strFirstLine, NOTARY_ID,
                                                   INSTRUMENT_DEFINITION_ID);

        // The string didn't match any of the options in the factory.
        if (nullptr == pPurse) return nullptr;

        // Does the contract successfully load from the string passed in?
        if (pPurse->LoadContractFromString(strContract)) {
            const char* szFunc = "Purse::PurseFactory";
            if (NOTARY_ID != pPurse->GetNotaryID()) {
                const String strNotaryID(NOTARY_ID),
                    strPurseNotaryID(pPurse->GetNotaryID());
                otErr << szFunc << ": Failure: NotaryID on purse ("
                      << strPurseNotaryID << ") doesn't match expected "
                                             "server ID (" << strNotaryID
                      << ").\n";
                delete pPurse;
                pPurse = nullptr;
            }
            else if (INSTRUMENT_DEFINITION_ID !=
                       pPurse->GetInstrumentDefinitionID()) {
                const String strInstrumentDefinitionID(
                    INSTRUMENT_DEFINITION_ID),
                    strPurseInstrumentDefinitionID(
                        pPurse->GetInstrumentDefinitionID());
                otErr << szFunc
                      << ": Failure: InstrumentDefinitionID on purse ("
                      << strPurseInstrumentDefinitionID
                      << ") doesn't match expected "
                         "instrument definition id ("
                      << strInstrumentDefinitionID << ").\n";
                delete pPurse;
                pPurse = nullptr;
            }
            else
                return pPurse;
        }
        else {
            delete pPurse;
            pPurse = nullptr;
        }
    }

    return nullptr;
}

// Checks the notaryID, so you don't have to.
//
Purse* Purse::PurseFactory(String strInput, const Identifier& NOTARY_ID)
{
    String strContract, strFirstLine; // output for the below function.
    const bool bProcessed =
        Contract::DearmorAndTrim(strInput, strContract, strFirstLine);

    if (bProcessed) {
        Purse* pPurse = Purse::LowLevelInstantiate(strFirstLine, NOTARY_ID);

        // The string didn't match any of the options in the factory.
        if (nullptr == pPurse) return nullptr;

        // Does the contract successfully load from the string passed in?
        if (pPurse->LoadContractFromString(strContract)) {
            if (NOTARY_ID != pPurse->GetNotaryID()) {
                const String strNotaryID(NOTARY_ID),
                    strPurseNotaryID(pPurse->GetNotaryID());
                otErr << "Purse::PurseFactory"
                      << ": Failure: NotaryID on purse (" << strPurseNotaryID
                      << ") doesn't match expected server ID (" << strNotaryID
                      << ").\n";
                delete pPurse;
                pPurse = nullptr;
            }
            else
                return pPurse;
        }
        else {
            delete pPurse;
            pPurse = nullptr;
        }
    }

    return nullptr;
}

Purse* Purse::PurseFactory(String strInput)
{
    //  const char * szFunc = "Purse::PurseFactory";

    String strContract, strFirstLine; // output for the below function.
    const bool bProcessed =
        Contract::DearmorAndTrim(strInput, strContract, strFirstLine);

    if (bProcessed) {
        Purse* pPurse = Purse::LowLevelInstantiate(strFirstLine);

        // The string didn't match any of the options in the factory.
        if (nullptr == pPurse) return nullptr;

        // Does the contract successfully load from the string passed in?
        if (pPurse->LoadContractFromString(strContract))
            return pPurse;
        else
            delete pPurse;
    }

    return nullptr;
}

// private, used by factory.
Purse::Purse()
    : Contract()
    ,
    //    m_NotaryID(),
    //    m_InstrumentDefinitionID(),
    m_lTotalValue(0)
    , m_bPasswordProtected(false)
    , m_bIsNymIDIncluded(false)
    , m_pSymmetricKey(nullptr)
    , m_tLatestValidFrom(OT_TIME_ZERO)
    , m_tEarliestValidTo(OT_TIME_ZERO)
{
    InitPurse();
}

Purse::Purse(const Purse& thePurse)
    : Contract()
    , m_NymID()
    , m_NotaryID(thePurse.GetNotaryID())
    , m_InstrumentDefinitionID(thePurse.GetInstrumentDefinitionID())
    , m_lTotalValue(0)
    , m_bPasswordProtected(false)
    , m_bIsNymIDIncluded(false)
    , m_pSymmetricKey(nullptr)
    , m_tLatestValidFrom(OT_TIME_ZERO)
    , m_tEarliestValidTo(OT_TIME_ZERO)
{
    InitPurse();
}

// Don't use this unless you really don't have the instrument definition handy.
// Perhaps you know you're about to read this purse from a string and you
// know the instrument definition is in there anyway. So you use this
// constructor.
Purse::Purse(const Identifier& NOTARY_ID)
    : Contract()
    , m_NotaryID(NOTARY_ID)
    , m_lTotalValue(0)
    , m_bPasswordProtected(false)
    , m_bIsNymIDIncluded(false)
    , m_pSymmetricKey(nullptr)
    , m_tLatestValidFrom(OT_TIME_ZERO)
    , m_tEarliestValidTo(OT_TIME_ZERO)
{
    InitPurse();
}

Purse::Purse(const Identifier& NOTARY_ID,
             const Identifier& INSTRUMENT_DEFINITION_ID)
    : Contract()
    , m_NotaryID(NOTARY_ID)
    , m_InstrumentDefinitionID(INSTRUMENT_DEFINITION_ID)
    , m_lTotalValue(0)
    , m_bPasswordProtected(false)
    , m_bIsNymIDIncluded(false)
    , m_pSymmetricKey(nullptr)
    , m_tLatestValidFrom(OT_TIME_ZERO)
    , m_tEarliestValidTo(OT_TIME_ZERO)
{
    InitPurse();
}

Purse::Purse(const Identifier& NOTARY_ID,
             const Identifier& INSTRUMENT_DEFINITION_ID,
             const Identifier& NYM_ID)
    : Contract()
    , m_NymID(NYM_ID)
    , m_NotaryID(NOTARY_ID)
    , m_InstrumentDefinitionID(INSTRUMENT_DEFINITION_ID)
    , m_lTotalValue(0)
    , m_bPasswordProtected(false)
    , m_bIsNymIDIncluded(false)
    , m_pSymmetricKey(nullptr)
    , m_tLatestValidFrom(OT_TIME_ZERO)
    , m_tEarliestValidTo(OT_TIME_ZERO)
{
    InitPurse();
}

void Purse::InitPurse()
{
    m_strContractType.Set("PURSE");

    m_lTotalValue = 0;

    m_bPasswordProtected = false;
    m_bIsNymIDIncluded = false;
}

Purse::~Purse()
{
    Release_Purse();
}

void Purse::Release_Purse()
{
    // This sets m_lTotalValue to 0 already.
    ReleaseTokens();
//  m_lTotalValue = 0;

    m_bPasswordProtected = false;
    m_bIsNymIDIncluded = false;

    // the Temp Nym is when a purse contains its own Nym, created just
    // for that purse, so that it can be password protected instead of using
    // one of the real Nyms in your wallet.
    //
    if (nullptr != m_pSymmetricKey) {
        delete m_pSymmetricKey;
        m_pSymmetricKey = nullptr;
    }

//  if (m_pCachedKey)
//  {
//      delete m_pCachedKey;
//      m_pCachedKey = nullptr;
//  }
}

void Purse::Release()
{
    Release_Purse();

    Contract::Release();

    InitPurse();
}

/*
 OTIdentifier    m_NymID;    // Optional
 OTIdentifier    m_NotaryID;    // Mandatory
 OTIdentifier    m_InstrumentDefinitionID;    // Mandatory
 */

bool Purse::LoadContract()
{
    return LoadPurse();
}

bool Purse::LoadPurse(const char* szNotaryID, const char* szNymID,
                      const char* szInstrumentDefinitionID)
{
    OT_ASSERT(!IsPasswordProtected());

    if (!m_strFoldername.Exists())
        m_strFoldername.Set(OTFolders::Purse().Get());

    String strNotaryID(m_NotaryID), strNymID(m_NymID),
        strInstrumentDefinitionID(m_InstrumentDefinitionID);

    if (nullptr != szNotaryID) strNotaryID = szNotaryID;
    if (nullptr != szNymID) strNymID = szNymID;
    if (nullptr != szInstrumentDefinitionID)
        strInstrumentDefinitionID = szInstrumentDefinitionID;

    if (!m_strFilename.Exists()) {
        m_strFilename.Format("%s%s%s%s%s", strNotaryID.Get(),
                             Log::PathSeparator(), strNymID.Get(),
                             Log::PathSeparator(),
                             strInstrumentDefinitionID.Get());
    }

    const char* szFolder1name = OTFolders::Purse().Get(); // purse
    const char* szFolder2name = strNotaryID.Get();        // purse/NOTARY_ID
    const char* szFolder3name = strNymID.Get(); // purse/NOTARY_ID/NYM_ID
    const char* szFilename =
        strInstrumentDefinitionID
            .Get(); // purse/NOTARY_ID/NYM_ID/INSTRUMENT_DEFINITION_ID

    if (false ==
        OTDB::Exists(szFolder1name, szFolder2name, szFolder3name, szFilename)) {
        otInfo << "Purse::LoadPurse: File does not exist: " << szFolder1name
               << Log::PathSeparator() << szFolder2name << Log::PathSeparator()
               << szFolder3name << Log::PathSeparator() << szFilename << "\n";
        return false;
    }

    std::string strFileContents(
        OTDB::QueryPlainString(szFolder1name, szFolder2name, szFolder3name,
                               szFilename)); // <=== LOADING FROM DATA STORE.

    if (strFileContents.length() < 2) {
        otErr << "Purse::LoadPurse: Error reading file: " << szFolder1name
              << Log::PathSeparator() << szFolder2name << Log::PathSeparator()
              << szFolder3name << Log::PathSeparator() << szFilename << "\n";
        return false;
    }

    // NOTE: No need here to deal with OT ARMORED file format, since
    // LoadContractFromString
    // already handles it internally.

    String strRawFile(strFileContents.c_str());

    return LoadContractFromString(strRawFile);
}

bool Purse::SavePurse(const char* szNotaryID, const char* szNymID,
                      const char* szInstrumentDefinitionID)
{
    OT_ASSERT(!IsPasswordProtected());

    if (!m_strFoldername.Exists())
        m_strFoldername.Set(OTFolders::Purse().Get());

    String strNotaryID(m_NotaryID), strNymID(m_NymID),
        strInstrumentDefinitionID(m_InstrumentDefinitionID);

    if (nullptr != szNotaryID) strNotaryID = szNotaryID;
    if (nullptr != szNymID) strNymID = szNymID;
    if (nullptr != szInstrumentDefinitionID)
        strInstrumentDefinitionID = szInstrumentDefinitionID;

    if (!m_strFilename.Exists()) {
        m_strFilename.Format("%s%s%s%s%s", strNotaryID.Get(),
                             Log::PathSeparator(), strNymID.Get(),
                             Log::PathSeparator(),
                             strInstrumentDefinitionID.Get());
    }

    const char* szFolder1name = OTFolders::Purse().Get(); // purse
    const char* szFolder2name = strNotaryID.Get();        // purse/NOTARY_ID
    const char* szFolder3name = strNymID.Get(); // purse/NOTARY_ID/NYM_ID
    const char* szFilename =
        strInstrumentDefinitionID
            .Get(); // purse/NOTARY_ID/NYM_ID/INSTRUMENT_DEFINITION_ID

    String strRawFile;

    if (!SaveContractRaw(strRawFile)) {
        otErr << "Purse::SavePurse: Error saving Pursefile (to string):\n"
              << szFolder1name << Log::PathSeparator() << szFolder2name
              << Log::PathSeparator() << szFolder3name << Log::PathSeparator()
              << szFilename << "\n";
        return false;
    }

    String strFinal;
    OTASCIIArmor ascTemp(strRawFile);

    if (false ==
        ascTemp.WriteArmoredString(strFinal, m_strContractType.Get())) {
        otErr << "Purse::SavePurse: Error saving Pursefile (failed writing "
                 "armored string):\n" << szFolder1name << Log::PathSeparator()
              << szFolder2name << Log::PathSeparator() << szFolder3name
              << Log::PathSeparator() << szFilename << "\n";
        return false;
    }

    bool bSaved = OTDB::StorePlainString(
        strFinal.Get(), szFolder1name, szFolder2name, szFolder3name,
        szFilename); // <=== SAVING TO DATA STORE.
    if (!bSaved) {
        otErr << "Purse::SavePurse: Error writing to file: " << szFolder1name
              << Log::PathSeparator() << szFolder2name << Log::PathSeparator()
              << szFolder3name << Log::PathSeparator() << szFilename << "\n";
        return false;
    }

    return true;
}

void Purse::UpdateContents() // Before transmission or serialization, this is
                             // where the Purse saves its contents
{
    const String NOTARY_ID(m_NotaryID), NYM_ID(m_NymID),
        INSTRUMENT_DEFINITION_ID(m_InstrumentDefinitionID);

    // I release this because I'm about to repopulate it.
    m_xmlUnsigned.Release();

    Tag tag("purse");

    tag.add_attribute("version", m_strVersion.Get());
    tag.add_attribute("totalValue", formatLong(m_lTotalValue));
    tag.add_attribute("validFrom", formatTimestamp(m_tLatestValidFrom));
    tag.add_attribute("validTo", formatTimestamp(m_tEarliestValidTo));
    tag.add_attribute("isPasswordProtected", formatBool(m_bPasswordProtected));
    tag.add_attribute("isNymIDIncluded", formatBool(m_bIsNymIDIncluded));
    tag.add_attribute(
        "nymID",
        (m_bIsNymIDIncluded &&
         !m_NymID.IsEmpty()) // (Provided that the ID even exists, of course.)
            ? NYM_ID.Get()
            : ""); // Then print the ID (otherwise print an empty string.)
    tag.add_attribute("instrumentDefinitionID", INSTRUMENT_DEFINITION_ID.Get());
    tag.add_attribute("notaryID", NOTARY_ID.Get());

    // Save the Internal Symmetric Key here (if there IS one.)
    // (Some Purses own their own internal Symmetric Key, in order to "password
    // protect" the purse.)
    //
    if (m_bPasswordProtected) {
        if (!m_pCachedKey)
            otErr
                << __FUNCTION__
                << ": Error: m_pCachedKey is unexpectedly nullptr, even though "
                   "m_bPasswordProtected is true!\n";
        else if (nullptr == m_pSymmetricKey)
            otErr << __FUNCTION__ << ": Error: m_pSymmetricKey is unexpectedly "
                                     "nullptr, even though "
                                     "m_bPasswordProtected is true!\n";
        else // m_pCachedKey and m_pSymmetricKey are good pointers. (Or at
             // least, not-null.)
        {
            if (!m_pCachedKey->IsGenerated())
                otErr << __FUNCTION__ << ": Error: m_pCachedKey wasn't a "
                                         "generated key! Even though "
                                         "m_bPasswordProtected is true.\n";
            else if (!m_pSymmetricKey->IsGenerated())
                otErr << __FUNCTION__ << ": Error: m_pSymmetricKey wasn't a "
                                         "generated key! Even though "
                                         "m_bPasswordProtected is true.\n";
            else {
                OTASCIIArmor ascCachedKey, ascSymmetricKey;

                if (!m_pCachedKey->SerializeTo(ascCachedKey) ||
                    !ascCachedKey.Exists() ||
                    !m_pSymmetricKey->SerializeTo(ascSymmetricKey) ||
                    !ascSymmetricKey.Exists())
                    otErr << __FUNCTION__
                          << ": Error: m_pCachedKey or m_pSymmetricKey failed "
                             "trying to serialize to OTASCIIArmor.\n";
                else {
                    // ascInternalKey is good by this point.
                    // Therefore, let's serialize it...

                    // By this point, ascInternalKey contains the Key itself.
                    //

                    // The "password" for the internal symmetric key.
                    tag.add_tag("cachedKey", ascCachedKey.Get());

                    // The internal symmetric key, owned by the purse.
                    tag.add_tag("internalKey", ascSymmetricKey.Get());
                }
            }
        }
    }

    for (int32_t i = 0; i < Count(); i++) {
        tag.add_tag("token", m_dequeTokens[i]->Get());
    }

    std::string str_result;
    tag.output(str_result);

    m_xmlUnsigned.Concatenate("%s", str_result.c_str());
}

int32_t Purse::ProcessXMLNode(irr::io::IrrXMLReader*& xml)
{
    const char* szFunc = "Purse::ProcessXMLNode";

    const String strNodeName(xml->getNodeName());

    if (strNodeName.Compare("purse")) {
        m_strVersion = xml->getAttributeValue("version");

        const String strTotalValue = xml->getAttributeValue("totalValue");

        if (strTotalValue.Exists() && (strTotalValue.ToLong() > 0))
            m_lTotalValue = strTotalValue.ToLong();
        else
            m_lTotalValue = 0;

        const String str_valid_from = xml->getAttributeValue("validFrom");
        const String str_valid_to = xml->getAttributeValue("validTo");

        if (str_valid_from.Exists()) {
            int64_t lValidFrom = parseTimestamp(str_valid_from.Get());

            m_tLatestValidFrom = OTTimeGetTimeFromSeconds(lValidFrom);
        }
        if (str_valid_to.Exists()) {
            int64_t lValidTo = parseTimestamp(str_valid_to.Get());

            m_tEarliestValidTo = OTTimeGetTimeFromSeconds(lValidTo);
        }

        const String strPasswdProtected =
            xml->getAttributeValue("isPasswordProtected");
        m_bPasswordProtected = strPasswdProtected.Compare("true");

        const String strNymIDIncluded =
            xml->getAttributeValue("isNymIDIncluded");
        m_bIsNymIDIncluded = strNymIDIncluded.Compare("true");

        // TODO security: Might want to verify the server ID here, if it's
        // already set.
        // Just to make sure it's the one we were expecting.
        const String strNotaryID = xml->getAttributeValue("notaryID");
        if (strNotaryID.Exists())
            m_NotaryID.SetString(strNotaryID);
        else {
            m_NotaryID.Release();
            otErr << szFunc
                  << ": Failed loading notaryID, when one was expected.\n";
            return (-1);
        }

        // TODO security: Might want to verify the instrument definition id
        // here, if it's
        // already set.
        // Just to make sure it's the one we were expecting.
        const String strInstrumentDefinitionID =
            xml->getAttributeValue("instrumentDefinitionID");
        if (strInstrumentDefinitionID.Exists())
            m_InstrumentDefinitionID.SetString(strInstrumentDefinitionID);
        else {
            m_InstrumentDefinitionID.Release();
            otErr << szFunc << ": Failed loading instrumentDefinitionID, when "
                               "one was expected.\n";
            return (-1);
        }

        const String strNymID =
            xml->getAttributeValue("nymID"); // (May not exist.)
        if (m_bIsNymIDIncluded) // Nym ID **is** included.  (It's optional. Even
                                // if you use one, you don't have to list it.)
        {
            if (strNymID.Exists())
                m_NymID.SetString(strNymID);
            else {
                otErr << szFunc
                      << ": Failed loading nymID, when one was expected. "
                         "(isNymIDIncluded was true.)\n";
                m_NymID.Release();
                return (-1);
            }
        }
        else // NymID SUPPOSED to be blank here. (Thus the Release.) Maybe
               // later,
            // we might consider trying to read it, in order to validate this.
            //
            m_NymID.Release(); // For now, just assume it's not there to be
                               // read, and Release my own value to match it.

        otLog4 << szFunc << ": Loaded purse... ("
               << (m_bPasswordProtected ? "Password-protected"
                                        : "NOT password-protected")
               << ")\n NotaryID: " << strNotaryID
               << "\n NymID: " << (m_bIsNymIDIncluded ? strNymID.Get() : "")
               << "\n Instrument Definition Id: " << strInstrumentDefinitionID
               << "\n----------\n";

        return 1;
    }

    // Sometimes you want the purse to have a passphrase on it, without being
    // attached to
    // one of your actual Nyms in your wallet. To accommodate this, OT creates a
    // symmetric key
    // and stashes it INSIDE the purse. This symmetric key can have whatever
    // passphrase you want.
    // There is also a master key attached, which allows for passphrase timeouts
    // on the symmetric key.
    // Therefore internalKey and cachedKey will both be attached to the purse
    // (or neither will be.)
    //
    else if (strNodeName.Compare("internalKey")) {
        if (!m_bPasswordProtected) // If we're NOT using the internal key, then
                                   // why am I in the middle of loading one
                                   // here?
        {
            otErr << szFunc << ": Error: Unexpected 'internalKey' data, "
                               "since m_bPasswordProtected is set to false!\n";
            return (-1); // error condition
        }

        if (!m_NymID.IsEmpty()) // If the NymID isn't empty, then why am I in
                                // the middle of loading an internal Key?
        {
            otErr << szFunc << ": Error: Unexpected 'internalKey' data, since "
                               "m_NymID is not blank! "
                               "(The NymID should have loaded before THIS "
                               "node ever popped up...)\n";
            return (-1); // error condition
        }

        OTASCIIArmor ascValue;

        if (!Contract::LoadEncodedTextField(xml, ascValue) ||
            !ascValue.Exists()) {
            otErr << szFunc << ": Error: Expected "
                  << "internalKey"
                  << " element to have text field.\n";
            return (-1); // error condition
        }

        // Let's see if the internal key is already loaded somehow... (Shouldn't
        // be...)
        //
        if (nullptr != m_pSymmetricKey) {
            otErr << szFunc
                  << ": WARNING: While loading internal Key for a purse, "
                     "noticed the pointer was ALREADY set! (I'm deleting old "
                     "one to make room, "
                     "and then allowing this one to load instead...)\n";
            //          return (-1); // error condition

            delete m_pSymmetricKey;
            m_pSymmetricKey = nullptr;
        }

        // By this point, I've loaded up the string containing the encrypted
        // symmetric key.
        // I also know that m_bPasswordProtected is set to true, and I know that
        // m_pSymmetricKey is nullptr.
        //
        // (It's only now that I bother instantiating.)
        //
        OTSymmetricKey* pSymmetricKey = new OTSymmetricKey();
        OT_ASSERT_MSG(nullptr != pSymmetricKey, "Purse::ProcessXMLNode: "
                                                "Assert: nullptr != new "
                                                "OTSymmetricKey \n");

        // NOTE: In the event of any error, need to delete pSymmetricKey before
        // returning.
        // (Or it will leak.)
        //
        if (!pSymmetricKey->SerializeFrom(ascValue)) {
            otErr
                << szFunc
                << ": Error: While loading internal Key for a purse, failed "
                   "serializing from stored string! (Failed loading purse.)\n";
            delete pSymmetricKey;
            pSymmetricKey = nullptr;
            return (-1);
        }

        // By this point, the symmetric key has loaded successfully from
        // storage.

        otWarn << szFunc << ": Successfully loaded a purse's internal key.\n";

        // No more worry about pSymmetricKey cleanup, now that this pointer is
        // set.

        m_pSymmetricKey = pSymmetricKey;

        return 1;
    }
    else if (strNodeName.Compare("cachedKey")) {
        if (!m_bPasswordProtected) // If we're NOT using the internal and master
                                   // keys, then why am I in the middle of
                                   // loading one here?
        {
            otErr << szFunc << ": Error: Unexpected 'cachedKey' data, "
                               "since m_bPasswordProtected is set to false!\n";
            return (-1); // error condition
        }

        if (!m_NymID.IsEmpty()) // If the NymID isn't empty, then why am I in
                                // the middle of loading an internal Key?
        {
            otErr << szFunc << ": Error: Unexpected 'cachedKey' data, since "
                               "m_NymID is not blank!\n";
            return (-1); // error condition
        }

        OTASCIIArmor ascValue;

        if (!Contract::LoadEncodedTextField(xml, ascValue) ||
            !ascValue.Exists()) {
            otErr << szFunc << ": Error: Expected "
                  << "cachedKey"
                  << " element to have text field.\n";
            return (-1); // error condition
        }

        // Let's see if the master key is already loaded somehow... (Shouldn't
        // be...)
        //
        if (m_pCachedKey) {
            otErr << szFunc
                  << ": WARNING: While loading master Key for a purse, "
                     "noticed the pointer was ALREADY set! (I'm deleting old "
                     "one to make room, "
                     "and then allowing this one to load instead...)\n";
//          return (-1); // error condition

            m_pCachedKey.reset();
        }

        // By this point, I've loaded up the string containing the encrypted
        // symmetric key.
        // I also know that m_bPasswordProtected is set to true, and I know that
        // m_pSymmetricKey is nullptr.
        //
        // (It's only now that I bother instantiating.)
        //
        std::shared_ptr<OTCachedKey> pCachedKey(new OTCachedKey(ascValue));
        //        OT_ASSERT_MSG(nullptr != pCachedKey, "Purse::ProcessXMLNode:
        // Assert: nullptr != new OTCachedKey \n");

        // NOTE: In the event of any error, need to delete pCachedKey before
        // returning.
        // (Or it will leak.)
        //
        if (!pCachedKey->SerializeFrom(ascValue)) {
            otErr
                << szFunc
                << ": Error: While loading master Key for a purse, failed "
                   "serializing from stored string! (Failed loading purse.)\n";
            //            delete pCachedKey; pCachedKey = nullptr;
            return (-1);
        }

        // By this point, the symmetric key has loaded successfully from
        // storage.

        otWarn << szFunc << ": Successfully loaded a purse's master key.\n";

        // No more worry about pSymmetricKey cleanup, now that this pointer is
        // set.

        m_pCachedKey = pCachedKey;

        // NOTE: Hereafter, do NOT use m_pCachedKey directly.
        // Instead, use OTCachedKey::It(*m_pCachedKey) (So you deal with the
        // cached
        // version, and avoid forcing the user to re-type his passphrase more
        // than
        // necessary according to timeouts designed in OTCachedKey class.)
        //
        // In fact, don't even use that. Instead, I'll add an
        // Purse::GetPassphrase
        // method, which handles that for you.

        return 1;
    }
    else if (strNodeName.Compare("token")) {
        OTASCIIArmor* pArmor = new OTASCIIArmor;
        OT_ASSERT(nullptr != pArmor);

        if (!Contract::LoadEncodedTextField(xml, *pArmor) ||
            !pArmor->Exists()) {
            otErr << szFunc << ": Error: token field without value.\n";

            delete pArmor;
            pArmor = nullptr;

            return (-1); // error condition
        }
        else {
            m_dequeTokens.push_front(pArmor);
        }

        return 1;
    }

    return 0;
}

time64_t Purse::GetLatestValidFrom() const
{
    return m_tLatestValidFrom;
}

time64_t Purse::GetEarliestValidTo() const
{
    return m_tEarliestValidTo;
}

// Verify whether the CURRENT date is AFTER the the VALID TO date.
// Notice, this will return false, if the instrument is NOT YET VALID.
// You have to use VerifyCurrentDate() to make sure you're within the
// valid date range to use this instrument. But sometimes you only want
// to know if it's expired, regardless of whether it's valid yet. So this
// function answers that for you.
//
bool Purse::IsExpired()
{
    const time64_t CURRENT_TIME = OTTimeGetCurrentTime();

    // If the current time is AFTER the valid-TO date,
    // AND the valid_to is a nonzero number (0 means "doesn't expire")
    // THEN return true (it's expired.)
    //
    if ((CURRENT_TIME >= m_tEarliestValidTo) &&
        (m_tEarliestValidTo > OT_TIME_ZERO))
        return true;
    else
        return false;
}

// Verify whether the CURRENT date is WITHIN the VALID FROM / TO dates.
//
bool Purse::VerifyCurrentDate()
{
    const time64_t CURRENT_TIME = OTTimeGetCurrentTime();

    if ((CURRENT_TIME >= m_tLatestValidFrom) &&
        ((CURRENT_TIME <= m_tEarliestValidTo) ||
         (OT_TIME_ZERO == m_tEarliestValidTo)))
        return true;
    else
        return false;
}

// Caller IS responsible to delete. (Peek returns an instance of the
// actual token, which is stored in encrypted form inside the purse.)
//
Token* Purse::Peek(OTNym_or_SymmetricKey theOwner) const
{
    if (m_dequeTokens.empty()) return nullptr;

    // Grab a pointer to the first armored token on the deque.
    //
    const OTASCIIArmor* pArmor = m_dequeTokens.front();
    // ---------------
    // Copy the token contents into an Envelope.
    OTEnvelope theEnvelope(*pArmor);

    // Open the envelope into a string.
    //
    String strToken;
    const String strDisplay(__FUNCTION__); // this is the passphrase string
                                           // that will display if theOwner
                                           // doesn't have one already.

    const bool bSuccess =
        theOwner.Open_or_Decrypt(theEnvelope, strToken, &strDisplay);

    if (bSuccess) {
        // Create a new token with the same server and instrument definition ids
        // as this purse.
        Token* pToken = Token::TokenFactory(strToken, *this);
        OT_ASSERT(nullptr != pToken);

        if (pToken->GetInstrumentDefinitionID() != m_InstrumentDefinitionID ||
            pToken->GetNotaryID() != m_NotaryID) {
            delete pToken;
            pToken = nullptr;

            otErr << __FUNCTION__ << ": ERROR: Cash token with wrong server or "
                                     "instrument definition.\n";
        }
        else {
            // CALLER is responsible to delete this token.
            return pToken;
        }
    }
    else
        otErr << __FUNCTION__ << ": Failure: theOwner.Open_or_Decrypt.\n";

    return nullptr;
}

// Hypocritically (compared to Push) in the case of Pop(), we DO
// allocate a OTToken and return the pointer. The caller IS
// responsible to delete it when he's done with it.
//
// The apparent discrepancy is due to the fact that internally,
// we aren't storing the token object but an encrypted string of it.
// But this is hidden from the user of the purse, who perceives only
// that he is passing tokens in and getting them back out again.
//
Token* Purse::Pop(OTNym_or_SymmetricKey theOwner)
{
    if (m_dequeTokens.empty()) return nullptr;

    Token* pToken = Peek(theOwner);

    if (nullptr == pToken) {
        otErr << __FUNCTION__ << ": Failure: Peek(theOwner) "
                                 "(And m_dequeTokens isn't empty, either.)\n";
        return nullptr;
    }

    // Grab a pointer to the ascii-armored token, and remove it from the deque.
    // (And delete it.)
    //
    OTASCIIArmor* pArmor = m_dequeTokens.front();
    m_dequeTokens.pop_front();
    delete pArmor;
    pArmor = nullptr;

    // We keep track of the purse's total value.
    m_lTotalValue -= pToken->GetDenomination();

    // We keep track of the purse's expiration dates, based on the tokens
    // within.
    //
    //    OT_ASSERT(pToken->GetValidFrom() <= m_tLatestValidFrom); // If the
    // token's was larger, then the purse's should match it already.
    //    OT_ASSERT(pToken->GetValidTo()   >= m_tEarliestValidTo); // If the
    // token's was smaller, then the purse's should match it already.

    // NOTE: the above asserts were commented out because the below call to
    // RecalculateExpirationDates
    // was commented out (because without recalculating those dates when tokens
    // are removed, these asserts
    // would get triggered.)

    if ((pToken->GetValidFrom() == m_tLatestValidFrom) ||
        (pToken->GetValidTo() == m_tEarliestValidTo)) {
        //      RecalculateExpirationDates(theOwner);
    }

    // CALLER is responsible to delete this token.
    return pToken;
}

void Purse::RecalculateExpirationDates(OTNym_or_SymmetricKey& theOwner)
{
    m_tLatestValidFrom = OT_TIME_ZERO;
    m_tEarliestValidTo = OT_TIME_ZERO;

    for (auto& it : m_dequeTokens) {
        OTASCIIArmor* pArmor = it;
        OT_ASSERT(nullptr != pArmor);

        OTEnvelope theEnvelope(*pArmor);

        // Open the envelope into a string.
        //
        String strToken;
        const String strDisplay(__FUNCTION__); // this is the passphrase
                                               // string that will display if
                                               // theOwner doesn't have one
                                               // already.

        const bool bSuccess =
            theOwner.Open_or_Decrypt(theEnvelope, strToken, &strDisplay);

        if (bSuccess) {
            // Create a new token with the same server and instrument definition
            // ids as this
            // purse.
            Token* pToken = Token::TokenFactory(strToken, *this);
            OT_ASSERT(nullptr != pToken);

            if (m_tLatestValidFrom < pToken->GetValidFrom()) {
                m_tLatestValidFrom = pToken->GetValidFrom();
            }

            if ((OT_TIME_ZERO == m_tEarliestValidTo) ||
                (m_tEarliestValidTo > pToken->GetValidTo())) {
                m_tEarliestValidTo = pToken->GetValidTo();
            }

            if (m_tLatestValidFrom > m_tEarliestValidTo)
                otErr << __FUNCTION__
                      << ": WARNING: This purse has a 'valid from' date LATER "
                         "than the 'valid to' date. "
                         "(due to different tokens with different date "
                         "ranges...)\n";

        }
        else
            otErr << __FUNCTION__
                  << ": Failure while trying to decrypt a token.\n";
    }
}

// Use a local variable for theToken, do NOT allocate it on the heap
// unless you are going to delete it yourself.
// Repeat: Purse is NOT responsible to delete it. We create our OWN internal
// variable here, new that, and add it to the stack. We do not add the one
// passed in.
bool Purse::Push(OTNym_or_SymmetricKey theOwner, const Token& theToken)
{
    if (theToken.GetInstrumentDefinitionID() == m_InstrumentDefinitionID) {
        const String strDisplay(__FUNCTION__); // this is the passphrase
                                               // string that will display if
                                               // theOwner doesn't have one
                                               // already.

        String strToken(theToken);
        OTEnvelope theEnvelope;
        const bool bSuccess =
            theOwner.Seal_or_Encrypt(theEnvelope, strToken, &strDisplay);

        if (bSuccess) {
            OTASCIIArmor* pArmor = new OTASCIIArmor(theEnvelope);

            m_dequeTokens.push_front(pArmor);

            // We keep track of the purse's total value.
            m_lTotalValue += theToken.GetDenomination();

            // We keep track of the expiration dates for the purse, based on the
            // tokens within.
            //
            if (m_tLatestValidFrom < theToken.GetValidFrom()) {
                m_tLatestValidFrom = theToken.GetValidFrom();
            }

            if ((OT_TIME_ZERO == m_tEarliestValidTo) ||
                (m_tEarliestValidTo > theToken.GetValidTo())) {
                m_tEarliestValidTo = theToken.GetValidTo();
            }

            if (m_tLatestValidFrom > m_tEarliestValidTo)
                otErr << __FUNCTION__
                      << ": WARNING: This purse has a 'valid from' date LATER "
                         "than the 'valid to' date. "
                         "(due to different tokens with different date "
                         "ranges...)\n";

            return true;
        }
        else {
            String strPurseAssetType(m_InstrumentDefinitionID),
                strTokenAssetType(theToken.GetInstrumentDefinitionID());
            otErr << __FUNCTION__ << ": Failed while calling: "
                                     "theOwner.Seal_or_Encrypt(theEnvelope, "
                                     "strToken)\nPurse Asset Type:\n"
                  << strPurseAssetType << "\n"
                                          "Token Asset Type:\n"
                  << strTokenAssetType << "\n";
        }
    }
    else {
        String strPurseAssetType(m_InstrumentDefinitionID),
            strTokenAssetType(theToken.GetInstrumentDefinitionID());
        otErr << __FUNCTION__ << ": ERROR: Tried to push token with wrong "
                                 "instrument definition.\nPurse Asset Type:\n"
              << strPurseAssetType << "\n"
                                      "Token Asset Type:\n" << strTokenAssetType
              << "\n";
    }

    return false;
}

int32_t Purse::Count() const
{
    return static_cast<int32_t>(m_dequeTokens.size());
}

bool Purse::IsEmpty() const
{
    return m_dequeTokens.empty();
}

void Purse::ReleaseTokens()
{
    while (!m_dequeTokens.empty()) {
        OTASCIIArmor* pArmor = m_dequeTokens.front();
        m_dequeTokens.pop_front();
        delete pArmor;
    }

    m_lTotalValue = 0;
}

} // namespace opentxs

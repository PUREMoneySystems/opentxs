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

#include <opentxs/core/AssetContract.hpp>
#include <opentxs/core/Account.hpp>
#include <opentxs/core/AccountVisitor.hpp>
#include <opentxs/core/util/OTFolders.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/OTStorage.hpp>
#include <opentxs/core/util/Tag.hpp>

#include <opentxs/core/script/OTBylaw.hpp>
#include <opentxs/core/script/OTClause.hpp>

#include <irrxml/irrXML.hpp>

#ifdef OT_USE_SCRIPT_CHAI
#   include <opentxs/core/script/OTScriptChai.hpp>
#   include <chaiscript/chaiscript.hpp>
#   ifdef OT_USE_CHAI_STDLIB
#       include <chaiscript/chaiscript_stdlib.hpp>
#   endif
#else
#   include <opentxs/core/script/OTScript.hpp>
#endif

#include <sstream>
#include <fstream>
#include <memory>
#include <iomanip>

using namespace irr;
using namespace io;

namespace opentxs
{

bool AssetContract::ParseFormatted(int64_t& lResult,
                                   const std::string& str_input,
                                   int32_t nFactor, int32_t nPower,
                                   const char* szThousandSeparator,
                                   const char* szDecimalPoint)
{
    OT_ASSERT(nullptr != szThousandSeparator);
    OT_ASSERT(nullptr != szDecimalPoint);

    lResult = 0;

    char theSeparator = szThousandSeparator[0];
    char theDecimalPoint = szDecimalPoint[0];

    int64_t lDollars = 0;
    int64_t lCents = 0;
    int64_t lOutput = 0;
    int64_t lSign = 1;

    bool bHasEnteredDollars = false;
    bool bHasEnteredCents = false;

    int32_t nDigitsCollectedBeforeDot = 0;
    int32_t nDigitsCollectedAfterDot = 0;

    // BUG: &mp isn't used.
    // const std::moneypunct<char, false> &mp = std::use_facet<
    // std::moneypunct<char, false> >(std::locale ());

    std::deque<int64_t> deque_cents;

    for (uint32_t uIndex = 0; uIndex < str_input.length(); ++uIndex) {
        char theChar = str_input[uIndex];

        if (iscntrl(theChar)) // Break at any newline or other control
                              // character.
            break;

        if (0 == isdigit(theChar)) // if it's not a numerical digit.
        {
            if (theSeparator == theChar) continue;

            if (theDecimalPoint == theChar) {
                if (bHasEnteredCents) {
                    // There shouldn't be ANOTHER decimal point if we are
                    // already in the cents.
                    // Therefore, we're done here. Break.
                    //
                    break;
                }

                // If we HAVEN'T entered the cents yet, then this decimal point
                // marks the spot where we DO.
                //
                bHasEnteredDollars = true;
                bHasEnteredCents = true;
                continue;
            } // theChar is the decimal point

            // Once a negative sign appears, it's negative, period.
            // If you put two or three negative signs in a row, it's STILL
            // negative.

            if ('-' == theChar) {
                lSign = -1;
                continue;
            }

            // Okay, by this point, we know it's not numerical, and it's not a
            // separator or decimal point, or
            // sign.
            // We allow letters and symbols BEFORE the numbers start, but not
            // AFTER (that would terminate the
            // number.) Therefore we need to see if the dollars or cents have
            // started yet. If they have, then
            // this is the end, and we break. Otherwise if they haven't, then
            // we're still at the beginning, so
            // we continue.
            //
            if (bHasEnteredDollars || bHasEnteredCents)
                break;
            else
                continue;
        } // not numerical

        // By this point, we KNOW that it's a numeric digit.
        // Are we collecting cents yet? How about dollars?
        // Also, if nPower is 2, then we only collect 2 digits
        // after the decimal point. If we've already collected
        // those, then we need to break.
        //
        if (bHasEnteredCents) {
            ++nDigitsCollectedAfterDot;

            // If "cents" occupy 2 digits after the decimal point,
            // and we are now on the THIRD digit -- then we're done.
            if (nDigitsCollectedAfterDot > nPower) break;

            // Okay, we're in the cents, so let's add this digit...
            //
            deque_cents.push_back(static_cast<int64_t>(theChar - '0'));

            continue;
        }

        // Okay, it's a digit, and we haven't started processing cents yet.
        // How about dollars?
        //
        if (!bHasEnteredDollars) bHasEnteredDollars = true;

        ++nDigitsCollectedBeforeDot;

        // Let's add this digit...
        //
        lDollars *=
            10; // Multiply existing dollars by 10, and then add the new digit.
        lDollars += static_cast<int64_t>(theChar - '0');
    }

    // Time to put it all together...
    //
    lOutput += lDollars;
    lOutput *= static_cast<int64_t>(nFactor); // 1 dollar becomes 100 cents.

    int32_t nTempPower = nPower;

    while (nTempPower > 0) {
        --nTempPower;

        if (deque_cents.size() > 0) {
            lCents += deque_cents.front();
            deque_cents.pop_front();
        }

        lCents *= 10;
    }
    lCents /= 10; // There won't be any rounding errors here, since the last
                  // thing we did in the loop was multiply by 10.

    lOutput += lCents;

    lResult = (lOutput * lSign);

    return true;
}

inline void separateThousands(std::stringstream& sss, int64_t value,
                              const char* szSeparator)
{
    if (value < 1000) {
        sss << value;
        return;
    }

    separateThousands(sss, value / 1000, szSeparator);
    sss << szSeparator << std::setfill('0') << std::setw(3) << value % 1000;
}

int32_t AssetContract::GetCurrencyFactor() const
{
    int32_t nFactor = atoi(m_strCurrencyFactor.Get());
    if (nFactor < 1) nFactor = 1;
    // should be 1, 10, 100, etc.
    OT_ASSERT(nFactor > 0);

    return nFactor;
}

int32_t AssetContract::GetCurrencyDecimalPower() const
{
    int32_t nPower = atoi(m_strCurrencyDecimalPower.Get());
    if (nPower < 0) nPower = 0;
    // should be 0, 1, 2, etc.
    OT_ASSERT(nPower >= 0);
    return nPower;
}

std::string AssetContract::formatLongAmount(int64_t lValue, int32_t nFactor,
                                            int32_t nPower,
                                            const char* szCurrencySymbol,
                                            const char* szThousandSeparator,
                                            const char* szDecimalPoint)
{
    std::stringstream sss;

    // Handle negative values
    if (lValue < 0) {
        sss << "-";
        lValue = -lValue;
    }

    if (NULL != szCurrencySymbol) sss << szCurrencySymbol << " ";

    // For example, if 506 is supposed to be $5.06, then dividing by a factor of
    // 100 results in 5 dollars (integer value) and 6 cents (fractional value).

    // Handle integer value with thousand separaters
    separateThousands(sss, lValue / nFactor, szThousandSeparator);

    // Handle fractional value
    if (1 < nFactor) {
        sss << szDecimalPoint << std::setfill('0') << std::setw(nPower)
            << (lValue % nFactor);
    }

    std::string str_result(sss.str());

    return str_result;
}

// Convert 912545 to "$9,125.45"
//
// (Assuming a Factor of 100, Decimal Power of 2, Currency Symbol of "$",
//  separator of "," and decimal point of ".")
//
bool AssetContract::FormatAmount(int64_t amount,
                                 std::string& str_output) const // Convert 545
                                                                // to $5.45
{
    const std::string str_thousand(OT_THOUSANDS_SEP);
    const std::string str_decimal(OT_DECIMAL_POINT);

    return FormatAmountLocale(amount, str_output, str_thousand, str_decimal);
}

// Convert 912545 to "9,125.45"
//
// (Example assumes a Factor of 100, Decimal Power of 2
//  separator of "," and decimal point of ".")
//
bool AssetContract::FormatAmountWithoutSymbol(
    int64_t amount,
    std::string& str_output) const // Convert 545 to 5.45
{
    const std::string str_thousand(OT_THOUSANDS_SEP);
    const std::string str_decimal(OT_DECIMAL_POINT);

    return FormatAmountWithoutSymbolLocale(amount, str_output, str_thousand,
                                           str_decimal);
}

// Convert "$9,125.45" to 912545.
//
// (Assuming a Factor of 100, Decimal Power of 2, separator of "," and decimal
// point of ".")
//
bool AssetContract::StringToAmount(
    int64_t& amount,
    const std::string& str_input) const // Convert $5.45 to amount 545.
{
    const std::string str_thousand(OT_THOUSANDS_SEP);
    const std::string str_decimal(OT_DECIMAL_POINT);

    return StringToAmountLocale(amount, str_input, str_thousand, str_decimal);
}

bool AssetContract::FormatAmountLocale(int64_t amount, std::string& str_output,
                                       const std::string& str_thousand,
                                       const std::string& str_decimal) const
{
    // Lookup separator and decimal point symbols based on locale.

    // Get a moneypunct facet from the global ("C") locale
    //
    // NOTE: Turns out moneypunct kind of sucks.
    // As a result, for internationalization purposes,
    // these values have to be set here before compilation.
    //
    static String strSeparator(str_thousand.empty() ? OT_THOUSANDS_SEP
                                                    : str_thousand);
    static String strDecimalPoint(str_decimal.empty() ? OT_DECIMAL_POINT
                                                      : str_decimal);

    // NOTE: from web searching, I've determined that locale / moneypunct has
    // internationalization problems. Therefore it looks like if you want to
    // build OT for various languages / regions, you're just going to have to
    // edit stdafx.hpp and change the OT_THOUSANDS_SEP and OT_DECIMAL_POINT
    // variables.
    //
    // The best improvement I can think on that is to check locale and then use
    // it to choose from our own list of hardcoded values. Todo.

    str_output = AssetContract::formatLongAmount(
        amount, GetCurrencyFactor(), GetCurrencyDecimalPower(),
        m_strCurrencySymbol.Get(), strSeparator.Get(), strDecimalPoint.Get());
    return true; // Note: might want to return false if str_output is empty.
}

bool AssetContract::FormatAmountWithoutSymbolLocale(
    int64_t amount, std::string& str_output, const std::string& str_thousand,
    const std::string& str_decimal) const
{
    // --------------------------------------------------------
    // Lookup separator and decimal point symbols based on locale.
    // --------------------------------------------------------
    // Get a moneypunct facet from the global ("C") locale
    //
    // NOTE: Turns out moneypunct kind of sucks.
    // As a result, for internationalization purposes,
    // these values have to be set here before compilation.
    //
    static String strSeparator(str_thousand.empty() ? OT_THOUSANDS_SEP
                                                    : str_thousand);
    static String strDecimalPoint(str_decimal.empty() ? OT_DECIMAL_POINT
                                                      : str_decimal);

    str_output = AssetContract::formatLongAmount(
        amount, GetCurrencyFactor(), GetCurrencyDecimalPower(), NULL,
        strSeparator.Get(), strDecimalPoint.Get());
    return true; // Note: might want to return false if str_output is empty.
}

bool AssetContract::StringToAmountLocale(int64_t& amount,
                                         const std::string& str_input,
                                         const std::string& str_thousand,
                                         const std::string& str_decimal) const
{
    // Lookup separator and decimal point symbols based on locale.

    // Get a moneypunct facet from the global ("C") locale
    //

    // NOTE: from web searching, I've determined that locale / moneypunct has
    // internationalization problems. Therefore it looks like if you want to
    // build OT for various languages / regions, you're just going to have to
    // edit stdafx.hpp and change the OT_THOUSANDS_SEP and OT_DECIMAL_POINT
    // variables.
    //
    // The best improvement I can think on that is to check locale and then use
    // it to choose from our own list of hardcoded values. Todo.

    static String strSeparator(str_thousand.empty() ? OT_THOUSANDS_SEP
                                                    : str_thousand);
    static String strDecimalPoint(str_decimal.empty() ? OT_DECIMAL_POINT
                                                      : str_decimal);

    bool bSuccess = AssetContract::ParseFormatted(
        amount, str_input, GetCurrencyFactor(), GetCurrencyDecimalPower(),
        strSeparator.Get(), strDecimalPoint.Get());

    return bSuccess;
}

AssetContract::AssetContract()
    : Contract()
    , m_bIsCurrency(true)
    , m_bIsShares(false)
{
}

AssetContract::AssetContract(String& unsignedXML)
    : Contract()
    , m_bIsCurrency(true)
    , m_bIsShares(false){
    m_xmlUnsigned.Set(unsignedXML);
    LoadContractXML();
}

AssetContract::AssetContract(const String& name, const String& foldername,
                             const String& filename, const String& strID)
    : Contract(name, foldername, filename, strID)
    , m_bIsCurrency(true)
    , m_bIsShares(false)
{
}

AssetContract::~AssetContract(){
    Release_Script();
}

// Go through the existing list of bylaws at this point, and delete them all.
void AssetContract::Release_Script() {
    while (!m_mapBylaws.empty()){
        OTBylaw * pBylaw = m_mapBylaws.begin()->second;
        OT_ASSERT(NULL != pBylaw);

        m_mapBylaws.erase(m_mapBylaws.begin());
        delete pBylaw;
        pBylaw = NULL;
    }
}

void AssetContract::Release() {
    Release_Script();
    Contract::Release(); // since I've overridden the base class, I call it now...
}


bool AssetContract::DisplayStatistics(String& strContents) const
{
    const String strID(m_ID);

    strContents.Concatenate(" Asset Type:  %s\n"
                            " InstrumentDefinitionID: %s\n"
                            "\n",
                            m_strName.Get(), strID.Get());
    return true;
}

bool AssetContract::SaveContractWallet(Tag& parent) const
{
    const String strID(m_ID);

    // Name is in the clear in memory,
    // and base64 in storage.
    OTASCIIArmor ascName;
    if (m_strName.Exists()) {
        ascName.SetString(m_strName, false); // linebreaks == false
    }

    TagPtr pTag(new Tag("assetType"));

    pTag->add_attribute("name", m_strName.Exists() ? ascName.Get() : "");
    pTag->add_attribute("instrumentDefinitionID", strID.Get());

    parent.add_tag(pTag);

    return true;
}

// currently only "user" accounts (normal user asset accounts) are added to
// this list Any "special" accounts, such as basket reserve accounts, or voucher
// reserve accounts, or cash reserve accounts, are not included on this list.
bool AssetContract::VisitAccountRecords(AccountVisitor& visitor) const
{
    String strInstrumentDefinitionID, strAcctRecordFile;
    GetIdentifier(strInstrumentDefinitionID);
    strAcctRecordFile.Format("%s.a", strInstrumentDefinitionID.Get());

    std::unique_ptr<OTDB::Storable> pStorable(OTDB::QueryObject(
        OTDB::STORED_OBJ_STRING_MAP, OTFolders::Contract().Get(),
        strAcctRecordFile.Get()));

    OTDB::StringMap* pMap = dynamic_cast<OTDB::StringMap*>(pStorable.get());

    // There was definitely a StringMap loaded from local storage.
    // (Even an empty one, possibly.) This is the only block that matters in
    // this function.
    //
    if (nullptr != pMap) {
        Identifier* pNotaryID = visitor.GetNotaryID();
        OT_ASSERT_MSG(nullptr != pNotaryID,
                      "Assert: nullptr Notary ID on functor. "
                      "(How did you even construct the "
                      "thing?)");

        auto& theMap = pMap->the_map;

        // todo: optimize: will probably have to use a database for this,
        // int64_t term.
        // (What if there are a million acct IDs in this flat file? Not
        // scaleable.)
        //
        for (auto& it : theMap) {
            const std::string& str_acct_id =
                it.first; // Containing the account ID.
            const std::string& str_instrument_definition_id =
                it.second; // Containing the instrument definition ID. (Just in
                           // case
                           // someone copied the wrong file here...)

            if (!strInstrumentDefinitionID.Compare(
                    str_instrument_definition_id.c_str())) {
                otErr << "OTAssetContract::VisitAccountRecords: Error: wrong "
                         "instrument definition ID ("
                      << str_instrument_definition_id
                      << ") when expecting: " << strInstrumentDefinitionID
                      << "\n";
            }
            else {
                Account* pAccount = nullptr;
                std::unique_ptr<Account> theAcctAngel;

                const Identifier theAccountID(str_acct_id.c_str());

                // Before loading it from local storage, let's first make sure
                // it's not already loaded.
                // (visitor functor has a list of 'already loaded' accounts,
                // just in case.)
                //
                mapOfAccounts* pLoadedAccounts = visitor.GetLoadedAccts();

                if (nullptr !=
                    pLoadedAccounts) // there are some accounts already loaded,
                { // let's see if the one we're looking for is there...
                    auto found_it = pLoadedAccounts->find(str_acct_id);

                    if (pLoadedAccounts->end() != found_it) // FOUND IT.
                    {
                        pAccount = found_it->second;
                        OT_ASSERT(nullptr != pAccount);

                        if (theAccountID != pAccount->GetPurportedAccountID()) {
                            otErr << "Error: the actual account didn't have "
                                     "the ID that the std::map SAID it had! "
                                     "(Should never happen.)\n";
                            pAccount = nullptr;
                        }
                    }
                }

                // I guess it wasn't already loaded...
                // Let's try to load it.
                //
                if (nullptr == pAccount) {
                    pAccount =
                        Account::LoadExistingAccount(theAccountID, *pNotaryID);
                    theAcctAngel.reset(pAccount);
                }

                bool bSuccessLoadingAccount =
                    ((pAccount != nullptr) ? true : false);
                if (bSuccessLoadingAccount) {
                    bool bTriggerSuccess = visitor.Trigger(*pAccount);
                    if (!bTriggerSuccess)
                        otErr << __FUNCTION__ << ": Error: Trigger Failed.";
                }
                else {
                    otErr << __FUNCTION__ << ": Error: Failed Loading Account!";
                }
            }
        }
        return true;
    }
    return true;
}

// Adds the account to the list. (When account is created.)
bool AssetContract::AddAccountRecord(const Account& theAccount) const
{
    //  Load up account list StringMap. Create it if doesn't already exist.
    //  See if account is already there in the map. Add it otherwise.
    //  Save the StringMap back again. (The account records list for a given
    // instrument definition.)

    const char* szFunc = "OTAssetContract::AddAccountRecord";

    if (theAccount.GetInstrumentDefinitionID() != m_ID) {
        otErr << szFunc << ": Error: theAccount doesn't have the same asset "
                           "type ID as *this does.\n";
        return false;
    }

    const Identifier theAcctID(theAccount);
    const String strAcctID(theAcctID);

    String strInstrumentDefinitionID, strAcctRecordFile;
    GetIdentifier(strInstrumentDefinitionID);
    strAcctRecordFile.Format("%s.a", strInstrumentDefinitionID.Get());

    OTDB::Storable* pStorable = nullptr;
    std::unique_ptr<OTDB::Storable> theAngel;
    OTDB::StringMap* pMap = nullptr;

    if (OTDB::Exists(OTFolders::Contract().Get(),
                     strAcctRecordFile.Get())) // the file already exists; let's
                                               // try to load it up.
        pStorable = OTDB::QueryObject(OTDB::STORED_OBJ_STRING_MAP,
                                      OTFolders::Contract().Get(),
                                      strAcctRecordFile.Get());
    else // the account records file (for this instrument definition) doesn't
         // exist.
        pStorable = OTDB::CreateObject(
            OTDB::STORED_OBJ_STRING_MAP); // this asserts already, on failure.

    theAngel.reset(pStorable);
    pMap = (nullptr == pStorable) ? nullptr
                                  : dynamic_cast<OTDB::StringMap*>(pStorable);

    // It exists.
    //
    if (nullptr == pMap) {
        otErr << szFunc
              << ": Error: failed trying to load or create the account records "
                 "file for instrument definition: " << strInstrumentDefinitionID
              << "\n";
        return false;
    }

    auto& theMap = pMap->the_map;
    auto map_it = theMap.find(strAcctID.Get());

    if (theMap.end() != map_it) // we found it.
    {                           // We were ADDING IT, but it was ALREADY THERE.
        // (Thus, we're ALREADY DONE.)
        // Let's just make sure the right instrument definition ID is associated
        // with this
        // account
        // (it better be, since we loaded the account records file based on the
        // instrument definition ID as its filename...)
        //
        const std::string& str2 = map_it->second; // Containing the instrument
                                                  // definition ID. (Just in
                                                  // case
        // someone copied the wrong file here,
        // --------------------------------          // every account should map
        // to the SAME instrument definition id.)

        if (false == strInstrumentDefinitionID.Compare(str2.c_str())) // should
                                                                      // never
                                                                      // happen.
        {
            otErr << szFunc << ": Error: wrong instrument definition found in "
                               "account records "
                               "file...\n For instrument definition: "
                  << strInstrumentDefinitionID << "\n "
                                                  "For account: " << strAcctID
                  << "\n Found wrong instrument definition: " << str2 << "\n";
            return false;
        }

        return true; // already there (no need to add.) + the instrument
                     // definition ID
                     // matches.
    }

    // it wasn't already on the list...

    // ...so add it.
    //
    theMap[strAcctID.Get()] = strInstrumentDefinitionID.Get();

    // Then save it back to local storage:
    //
    if (!OTDB::StoreObject(*pMap, OTFolders::Contract().Get(),
                           strAcctRecordFile.Get())) {
        otErr << szFunc
              << ": Failed trying to StoreObject, while saving updated "
                 "account records file for instrument definition: "
              << strInstrumentDefinitionID
              << "\n to contain account ID: " << strAcctID << "\n";
        return false;
    }

    // Okay, we saved the updated file, with the account added. (done, success.)
    //
    return true;
}

// Removes the account from the list. (When account is deleted.)
bool AssetContract::EraseAccountRecord(const Identifier& theAcctID) const
{
    //  Load up account list StringMap. Create it if doesn't already exist.
    //  See if account is already there in the map. Erase it, if it is.
    //  Save the StringMap back again. (The account records list for a given
    // instrument definition.)

    const char* szFunc = "OTAssetContract::EraseAccountRecord";

    const String strAcctID(theAcctID);

    String strInstrumentDefinitionID, strAcctRecordFile;
    GetIdentifier(strInstrumentDefinitionID);
    strAcctRecordFile.Format("%s.a", strInstrumentDefinitionID.Get());

    OTDB::Storable* pStorable = nullptr;
    std::unique_ptr<OTDB::Storable> theAngel;
    OTDB::StringMap* pMap = nullptr;

    if (OTDB::Exists(OTFolders::Contract().Get(),
                     strAcctRecordFile.Get())) // the file already exists; let's
                                               // try to load it up.
        pStorable = OTDB::QueryObject(OTDB::STORED_OBJ_STRING_MAP,
                                      OTFolders::Contract().Get(),
                                      strAcctRecordFile.Get());
    else // the account records file (for this instrument definition) doesn't
         // exist.
        pStorable = OTDB::CreateObject(
            OTDB::STORED_OBJ_STRING_MAP); // this asserts already, on failure.

    theAngel.reset(pStorable);
    pMap = (nullptr == pStorable) ? nullptr
                                  : dynamic_cast<OTDB::StringMap*>(pStorable);

    // It exists.
    //
    if (nullptr == pMap) {
        otErr << szFunc
              << ": Error: failed trying to load or create the account records "
                 "file for instrument definition: " << strInstrumentDefinitionID
              << "\n";
        return false;
    }

    // Before we can erase it, let's see if it's even there....
    //
    auto& theMap = pMap->the_map;
    auto map_it = theMap.find(strAcctID.Get());

    // we found it!
    if (theMap.end() != map_it) //  Acct ID was already there...
    {
        theMap.erase(map_it); // remove it
    }

    // it wasn't already on the list...
    // (So it's like success, since the end result is, acct ID will not appear
    // on this list--whether
    // it was there or not beforehand, it's definitely not there now.)

    // Then save it back to local storage:
    //
    if (!OTDB::StoreObject(*pMap, OTFolders::Contract().Get(),
                           strAcctRecordFile.Get())) {
        otErr << szFunc
              << ": Failed trying to StoreObject, while saving updated "
                 "account records file for instrument definition: "
              << strInstrumentDefinitionID
              << "\n to erase account ID: " << strAcctID << "\n";
        return false;
    }

    // Okay, we saved the updated file, with the account removed. (done,
    // success.)
    //
    return true;
}

void AssetContract::CreateContents()
{
    m_xmlUnsigned.Release();

    Tag tag("instrumentDefinition");

    tag.add_attribute("version", m_strVersion.Get());

    // Entity
    {
        TagPtr pTag(new Tag("entity"));
        pTag->add_attribute("shortname", m_strEntityShortName.Get());
        pTag->add_attribute("longname", m_strEntityLongName.Get());
        pTag->add_attribute("email", m_strEntityEmail.Get());
        tag.add_tag(pTag);
    }
    // Issue
    {
        TagPtr pTag(new Tag("issue"));
        pTag->add_attribute("company", m_strIssueCompany.Get());
        pTag->add_attribute("email", m_strIssueEmail.Get());
        pTag->add_attribute("contractUrl", m_strIssueContractURL.Get());
        pTag->add_attribute("type", m_strIssueType.Get());
        tag.add_tag(pTag);
    }

    // [currency|shares]
    if (m_bIsCurrency) {
        TagPtr pTag(new Tag("currency"));
        pTag->add_attribute("name", m_strCurrencyName.Get());
        pTag->add_attribute("tla", m_strCurrencyTLA.Get());
        pTag->add_attribute("symbol", m_strCurrencySymbol.Get());
        pTag->add_attribute("type", m_strCurrencyType.Get());
        pTag->add_attribute("factor", m_strCurrencyFactor.Get());
        pTag->add_attribute("decimalPower", m_strCurrencyDecimalPower.Get());
        pTag->add_attribute("fraction", m_strCurrencyFraction.Get());
        tag.add_tag(pTag);
    }
    else if (m_bIsShares) {
        TagPtr pTag(new Tag("shares"));
        pTag->add_attribute("name", m_strCurrencyName.Get());
        pTag->add_attribute("symbol", m_strCurrencySymbol.Get());
        pTag->add_attribute("type", m_strCurrencyType.Get());
        pTag->add_attribute("issueDate", m_strIssueDate.Get());
        tag.add_tag(pTag);
    }

    //Add any scripted bylaws to the asset contract
    if (!m_mapBylaws.empty()) {
        TagPtr pTag(new Tag("scriptableContract"));

        uint32_t sizeBylawMap = m_mapBylaws.size();
        pTag->add_attribute("numBylaws", formatUint(sizeBylawMap));

        for (auto& it : m_mapBylaws) {
            OTBylaw* pBylaw = it.second;
            OT_ASSERT(nullptr != pBylaw);
            pBylaw->Serialize(*pTag, false);
        }

        tag.add_tag(pTag);
    }

    // This is where OTContract scribes tag with its keys,
    // conditions, etc.
    CreateInnerContents(tag);

    std::string str_result;
    tag.output(str_result);

    m_xmlUnsigned.Format("%s", str_result.c_str());
}

// return -1 if error, 0 if nothing, and 1 if the node was processed.
//
int32_t AssetContract::ProcessXMLNode(IrrXMLReader*& xml)
{
    const char* szFunc = "AssetContract::ProcessXMLNode";
    int32_t nReturnVal = Contract::ProcessXMLNode(xml);

    // Here we call the parent class first.
    // If the node is found there, or there is some error,
    // then we just return either way.  But if it comes back
    // as '0', then nothing happened, and we'll continue executing.
    //
    // -- Note you can choose not to call the parent if
    // you don't want to use any of those xml tags.

    if (nReturnVal == 1 || nReturnVal == (-1)) return nReturnVal;

    const String strNodeName(xml->getNodeName());

    if (strNodeName.Compare("instrumentDefinition")) {
        m_strVersion = xml->getAttributeValue("version");

        otWarn << "\n"
                  "===> Loading XML portion of asset contract into memory "
                  "structures...\n\n"
                  "Digital Asset Contract: " << m_strName
               << "\nContract version: " << m_strVersion << "\n----------\n";
        nReturnVal = 1;
    }
    else if (strNodeName.Compare("issue")) {
        m_strIssueCompany = xml->getAttributeValue("company");
        m_strIssueEmail = xml->getAttributeValue("email");
        m_strIssueContractURL = xml->getAttributeValue("contractUrl");
        m_strIssueType = xml->getAttributeValue("type");

        otInfo << "Loaded Issue company: " << m_strIssueCompany
               << "\nEmail: " << m_strIssueEmail
               << "\nContractURL: " << m_strIssueContractURL
               << "\nType: " << m_strIssueType << "\n----------\n";
        nReturnVal = 1;
    }
    // TODO security validation: validate all the above and below values.
    else if (strNodeName.Compare("currency")) {
        m_bIsCurrency = true; // silver grams
        m_bIsShares = false;

        m_strName = xml->getAttributeValue("name");
        m_strCurrencyName = xml->getAttributeValue("name");
        m_strCurrencySymbol = xml->getAttributeValue("symbol");
        m_strCurrencyType = xml->getAttributeValue("type");

        m_strCurrencyTLA = xml->getAttributeValue("tla");
        m_strCurrencyFactor = xml->getAttributeValue("factor");
        m_strCurrencyDecimalPower = xml->getAttributeValue("decimalPower");
        m_strCurrencyFraction = xml->getAttributeValue("fraction");

        otInfo << "Loaded " << strNodeName << ", Name: " << m_strCurrencyName
               << ", TLA: " << m_strCurrencyTLA
               << ", Symbol: " << m_strCurrencySymbol
               << "\n"
                  "Type: " << m_strCurrencyType
               << ", Factor: " << m_strCurrencyFactor
               << ", Decimal Power: " << m_strCurrencyDecimalPower
               << ", Fraction: " << m_strCurrencyFraction << "\n----------\n";
        nReturnVal = 1;
    }

    //  share_type some type, for example, A or B, or NV (non voting)
    //
    //  share_name this is the int64_t legal name of the company
    //
    //  share_symbol this is the trading name (8 chars max), as it might be
    //      displayed in a market contect, and should be unique within some
    // given market
    //
    //  share_issue_date date of start of this share item (not necessarily IPO)
    else if (strNodeName.Compare("shares")) {
        m_bIsShares = true; // shares of pepsi
        m_bIsCurrency = false;

        m_strName = xml->getAttributeValue("name");
        m_strCurrencyName = xml->getAttributeValue("name");
        m_strCurrencySymbol = xml->getAttributeValue("symbol");
        m_strCurrencyType = xml->getAttributeValue("type");

        m_strIssueDate = xml->getAttributeValue("issueDate");

        otInfo << "Loaded " << strNodeName << ", Name: " << m_strCurrencyName
               << ", Symbol: " << m_strCurrencySymbol
               << "\n"
                  "Type: " << m_strCurrencyType
               << ", Issue Date: " << m_strIssueDate << "\n----------\n";
        nReturnVal = 1;
    } else if (strNodeName.Compare("scriptableContract")) {
        // Load up the Bylaws.
        String strNumBylaws = xml->getAttributeValue("numBylaws");
        int32_t nBylawCount = strNumBylaws.Exists() ? atoi(strNumBylaws.Get()) : 0;
        if (nBylawCount > 0) {
            while (nBylawCount-- > 0) {
                if (!SkipToElement(xml)) {
                    otOut << szFunc << ": Failure: Unable to find expected element for bylaw. \n";
                    return (-1);
                }

                if (!strcmp("bylaw", xml->getNodeName())) {
                    String strName = xml->getAttributeValue("name"); // bylaw name
                    String strLanguage = xml->getAttributeValue("language"); // The script language used in this bylaw.

                    String strNumVariable = xml->getAttributeValue("numVariables"); // number of variables on this bylaw.
                    String strNumClauses = xml->getAttributeValue("numClauses"); // number of clauses on this bylaw.

                    OTBylaw* pBylaw = new OTBylaw(strName.Get(), strLanguage.Get());

                    OT_ASSERT(nullptr != pBylaw);

                    // LOAD VARIABLES AND CONSTANTS.
                    int32_t nCount = strNumVariable.Exists() ? atoi(strNumVariable.Get()) : 0;
                    if (nCount > 0) {
                        while (nCount-- > 0) {
                            if (!Contract::SkipToElement(xml)) {
                                otErr << szFunc << ": Error finding expected next element for variable.\n";
                                delete pBylaw;
                                pBylaw = nullptr;
                                return (-1);
                            }

                            if ((xml->getNodeType() == irr::io::EXN_ELEMENT) && (!strcmp("variable", xml->getNodeName()))) {
                                String strVarName = xml->getAttributeValue("name"); // Variable name (if needed in script code)
                                String strVarValue = xml->getAttributeValue("value"); // Value stored in variable (If this is "true" then a real value is expected in a text field below. Otherwise, it's assumed to be a BLANK STRING.)
                                String strVarType = xml->getAttributeValue("type"); // string or int64_t
                                String strVarAccess = xml->getAttributeValue("access"); // constant, persistent, or important.

                                if (!strVarName.Exists() || !strVarType.Exists() || !strVarAccess.Exists()) {
                                    otErr << szFunc << ": Expected missing name, type, or access type in variable.\n";
                                    delete pBylaw;
                                    pBylaw = nullptr;
                                    return (-1);
                                }

                                // See if the same-named variable already exists on ANY of the OTHER BYLAWS (There can only be one variable on an OTScriptable with a given name.)
                                OTVariable* pVar = GetVariable(strVarName.Get());
                                if (nullptr !=  pVar){ // Uh-oh, it's already there!
                                    otOut << szFunc << ": Error loading variable named " << strVarName << ", since one was already there on one of the bylaws.\n";
                                    delete pBylaw;
                                    pBylaw = nullptr;
                                    return (-1);
                                }
                                // The AddVariable call below checks to see if
                                // it's already there, but only for the
                                // currently-loading bylaw.
                                // Whereas the above call checks this
                                // OTScriptable for all the variables on the
                                // already-loaded bylaws.

                                // VARIABLE TYPE AND ACCESS TYPE
                                OTVariable::OTVariable_Type theVarType = OTVariable::Var_Error_Type;

                                if (strVarType.Compare("integer"))
                                    theVarType = OTVariable::Var_Integer;
                                else if (strVarType.Compare("string"))
                                    theVarType = OTVariable::Var_String;
                                else if (strVarType.Compare("bool"))
                                    theVarType = OTVariable::Var_Bool;
                                else
                                    otErr << szFunc << ": Bad variable type: " << strVarType << ".\n";

                                OTVariable::OTVariable_Access theVarAccess = OTVariable::Var_Error_Access;

                                if (strVarAccess.Compare("constant"))
                                    theVarAccess = OTVariable::Var_Constant;
                                else if (strVarAccess.Compare("persistent"))
                                    theVarAccess = OTVariable::Var_Persistent;
                                else if (strVarAccess.Compare("important"))
                                    theVarAccess = OTVariable::Var_Important;
                                else
                                    otErr << szFunc << ": Bad variable access type: " << strVarAccess << ".\n";

                                if ((OTVariable::Var_Error_Access == theVarAccess) || (OTVariable::Var_Error_Type == theVarType)) {
                                    otErr << szFunc << ": Error loading variable to bylaw: bad type (" << strVarType << ") or access type (" << strVarAccess << ").\n";
                                    delete pBylaw;
                                    pBylaw = nullptr;
                                    return (-1);
                                }

                                bool bAddedVar = false;
                                const std::string str_var_name = strVarName.Get();

                                switch (theVarType) {
                                    case OTVariable::Var_Integer:
                                        if (strVarValue.Exists()) {
                                            const int32_t nVarValue = atoi(strVarValue.Get());
                                            bAddedVar = pBylaw->AddVariable(str_var_name, nVarValue, theVarAccess);
                                        } else {
                                            otErr << szFunc << ": No value found for integer variable: " << strVarName << "\n";
                                            delete pBylaw;
                                            pBylaw = nullptr;
                                            return (-1);
                                        }
                                        break;
                                    case OTVariable::Var_Bool:
                                        if (strVarValue.Exists()) {
                                            const bool bVarValue = strVarValue.Compare("true") ? true : false;
                                            bAddedVar = pBylaw->AddVariable(str_var_name, bVarValue, theVarAccess);
                                        } else {
                                            otErr << szFunc << ": No value found for bool variable: " << strVarName << "\n";
                                            delete pBylaw;
                                            pBylaw = nullptr;
                                            return (-1);
                                        }
                                        break;
                                    case OTVariable::Var_String:{
                                        // I realized I should probably allow empty strings.  :-P
                                        if (strVarValue.Exists() && strVarValue.Compare("exists")) {
                                            strVarValue.Release(); // probably unnecessary.
                                            if (false == Contract::LoadEncodedTextField(xml, strVarValue)) {
                                                otErr << szFunc << ": No value found for string variable: " << strVarName << "\n";
                                                delete pBylaw;
                                                pBylaw = nullptr;
                                                return (-1);
                                            }
                                        } else {
                                            strVarValue.Release(); // Necessary. If it's going to be a blank string, then let's make sure.
                                        }

                                        const std::string str_var_value = strVarValue.Get();
                                        bAddedVar = pBylaw->AddVariable(str_var_name, str_var_value, theVarAccess);
                                        } break;
                                    default:
                                        otErr << szFunc << ": Wrong variable type... somehow AFTER I should have already detected it...\n";
                                        delete pBylaw;
                                        pBylaw = nullptr;
                                        return (-1);
                                }

                                if (!bAddedVar) {
                                    otErr << szFunc << ": Failed adding variable to bylaw.\n";
                                    delete pBylaw;
                                    pBylaw = nullptr;
                                    return (-1);
                                }
                            } else {
                                otErr << szFunc << ": Expected variable element in bylaw.\n";
                                delete pBylaw;
                                pBylaw = nullptr;
                                return (-1); // error condition
                            }
                        }
                    }

                    // LOAD CLAUSES
                    nCount = strNumClauses.Exists() ? atoi(strNumClauses.Get()) : 0;
                    if (nCount > 0) {
                        while (nCount-- > 0) {
                            const char* pElementExpected = "clause";
                            String strTextExpected; // clause's script code will go here.

                            String::Map temp_MapAttributes;
                            // This map contains values we will also want, when we read the clause... (The OTContract::LoadEncodedTextField call below will read all the values as specified in this map.)
                            temp_MapAttributes.insert(std::pair<std::string, std::string>("name", ""));
                            if (!Contract::LoadEncodedTextFieldByName(xml, strTextExpected, pElementExpected, &temp_MapAttributes)){ // </clause>
                                otErr << szFunc << ": Error: Expected " << pElementExpected << " element with text field.\n";
                                delete pBylaw;
                                pBylaw = nullptr;
                                return (-1); // error condition
                            }

                            // Okay we now have the script code in strTextExpected. Next, let's read the clause's NAME from the map. If it's there, and presumably some kind of harsh validation for both, then create a clause object and add to my list here.
                            auto it = temp_MapAttributes.find("name");

                            if ((it != temp_MapAttributes.end())){ // We expected this much.
                                std::string& str_name = it->second;

                                if (str_name.size() > 0){ // SUCCESS
                                    // See if the same-named clause already exists on ANY of the OTHER BYLAWS (There can only be one clause on an OTScriptable with a given name.)
                                    OTClause* pClause = GetClause(str_name.c_str());

                                    if (nullptr != pClause){ // Uh-oh, it's already there!
                                        otOut << szFunc << ": Error loading clause named " << str_name << ", since one was already there on one of the bylaws.\n";
                                        delete pBylaw;
                                        pBylaw = nullptr;
                                        return (-1);
                                    } else if (false == pBylaw->AddClause(str_name.c_str(), strTextExpected.Get())) {
                                        otErr << szFunc << ": Failed adding clause to bylaw.\n";
                                        delete pBylaw;
                                        pBylaw = nullptr;
                                        return (-1); // error condition
                                    }
                                } else {
                                    // else it's empty, which is expected if nothing was there, since that's the default value that we set above for "name" in temp_MapAttributes.
                                    otErr << szFunc << ": Expected clause name.\n";
                                    delete pBylaw;
                                    pBylaw = nullptr;
                                    return (-1); // error condition
                                }
                            } else {
                                otErr << szFunc << ": Strange error: couldn't find name AT ALL.\n";
                                delete pBylaw;
                                pBylaw = nullptr;
                                return (-1); // error condition
                            }
                        }
                    }

                    if (AddBylaw(*pBylaw)) {
                        otInfo << szFunc << ": Loaded Bylaw: " << pBylaw->GetName() << "\n";
                    } else {
                        otErr << szFunc << ": Failed loading Bylaw: " << pBylaw->GetName() << "\n";
                        delete pBylaw;
                        pBylaw = nullptr;
                        return (-1); // error condition
                    }
                } else {
                    otErr << szFunc << ": Expected bylaw element.\n";
                    return (-1); // error condition
                }
            }
        }
    }

    return nReturnVal;
}



OTBylaw* AssetContract::GetBylaw(std::string str_bylaw_name) const {
    if (!AssetContract::ValidateName(str_bylaw_name)){ // this logs, FYI.
        otErr << __FUNCTION__ << ": Error: invalid name.\n";
        return nullptr;
    }

    auto it = m_mapBylaws.find(str_bylaw_name);
    if (m_mapBylaws.end() == it){ // Did NOT find it.
        return nullptr;
    }

    OTBylaw* pBylaw = it->second;
    OT_ASSERT(nullptr != pBylaw);

    return pBylaw;
}

OTBylaw* AssetContract::GetBylawByIndex(int32_t nIndex) const {
    if ((nIndex < 0) || (nIndex >= static_cast<int64_t>(m_mapBylaws.size()))) {
        otErr << __FUNCTION__ << ": Index out of bounds: " << nIndex << "\n";
    } else {
        int32_t nLoopIndex = -1; // will be 0 on first iteration.

        for (auto& it : m_mapBylaws) {
            OTBylaw* pBylaw = it.second;
            OT_ASSERT(nullptr != pBylaw);

            ++nLoopIndex; // 0 on first iteration.

            if (nLoopIndex == nIndex) return pBylaw;
        }
    }
    return nullptr;
}


// Look up the first (and hopefully only) variable registered for a given name.
// (Across all of my Bylaws)
OTVariable* AssetContract::GetVariable(std::string str_VarName){
    if (!AssetContract::ValidateName(str_VarName)){ // this logs, FYI.
        otErr << "AssetContract::GetVariable:  Error: invalid name.\n";
        return nullptr;
    }

    for (auto& it : m_mapBylaws) {
        OTBylaw* pBylaw = it.second;
        OT_ASSERT(nullptr != pBylaw);

        OTVariable* pVar = pBylaw->GetVariable(str_VarName);

        if (nullptr != pVar) // found it.
            return pVar;
    }

    return nullptr;
}

// Find the first (and hopefully the only) clause on this scriptable object,
// with a given name. (Searches ALL Bylaws on *this.)
OTClause* AssetContract::GetClause(std::string str_clause_name) const {
    if (!AssetContract::ValidateName(str_clause_name)){ // this logs, FYI.
        otErr << __FUNCTION__ << ": Error: invalid name.\n";
        return nullptr;
    }

    for (auto& it : m_mapBylaws) {
        OTBylaw* pBylaw = it.second;
        OT_ASSERT(nullptr != pBylaw);

        OTClause* pClause = pBylaw->GetClause(str_clause_name);

        if (nullptr != pClause) // found it.
            return pClause;
    }

    return nullptr;
}


bool AssetContract::AddBylaw(OTBylaw& theBylaw){
    const std::string str_name = theBylaw.GetName().Get();

    if (!AssetContract::ValidateName(str_name)) { // this logs, FYI.
        otErr << "AssetContract::AddBylaw:  Error: invalid name.\n";
        return false;
    }

    if (m_mapBylaws.find(str_name) == m_mapBylaws.end()) {
        // Careful:  This ** DOES ** TAKE OWNERSHIP!  theBylaw will get deleted
        // when this AssetContract is.
        m_mapBylaws.insert(std::pair<std::string, OTBylaw*>(str_name, &theBylaw));
        theBylaw.SetOwnerAgreement(*this);
        return true;
    } else {
        otOut << "AssetContract::AddBylaw: Failed attempt: bylaw already exists on contract.\n ";
    }

    return false;
}


bool AssetContract::Compare(AssetContract& rhs) const {
    const char* szFunc = "AssetContract::Compare";

    if (GetBylawCount() != rhs.GetBylawCount()) {
        otOut << szFunc << ": The number of bylaws does not match.\n";
        return false;
    }

    for (const auto& it : m_mapBylaws) {
        const std::string str_bylaw_name = it.first;
        OTBylaw* pBylaw = it.second;
        OT_ASSERT(nullptr != pBylaw);

        OTBylaw* p2 = rhs.GetBylaw(str_bylaw_name);

        if (nullptr == p2) {
            otOut << szFunc << ": Unable to find bylaw " << str_bylaw_name << " on rhs.\n";
            return false;
        } else if (!pBylaw->Compare(*p2)) {
            otOut << szFunc << ": Bylaws don't match: " << str_bylaw_name << ".\n";
            return false;
        }
    }

    return true;
}


// VALIDATING IDENTIFIERS IN ASSETCONTRACT.
// Only alphanumerics are valid, or '_' (underscore)
bool AssetContract::is_ot_namechar_invalid(char c){
    return !(isalnum(c) || (c == '_'));
}

// static
bool AssetContract::ValidateName(std::string str_name){
    if (str_name.size() <= 0) {
        otErr << "AssetContract::ValidateName: Name has zero size.\n";
        return false;
    } else if (find_if(str_name.begin(), str_name.end(), is_ot_namechar_invalid) != str_name.end()) {
        otErr << "OTScriptable::ValidateName: Name fails validation testing: " << str_name << "\n";
        return false;
    }

    return true;
}

void AssetContract::RegisterOTNativeCallsWithScript(ANDROID_UNUSED OTScript& theScript){
#ifdef OT_USE_SCRIPT_CHAI
    using namespace chaiscript;

    // In the future, this will be polymorphic.
    // But for now, I'm forcing things...

    OTScriptChai* pScript = dynamic_cast<OTScriptChai*>(&theScript);

    if (nullptr != pScript) {
        OT_ASSERT(nullptr != pScript->chai)

        pScript->chai->add(fun(&AssetContract::GetTime), "get_time");
        pScript->chai->add(fun(&AssetContract::GetPi), "get_pi");
        pScript->chai->add(fun(&AssetContract::GetSine), "sin");
        pScript->chai->add(fun(&AssetContract::GetCosine), "cos");
        pScript->chai->add(fun(&AssetContract::GetArcsine), "asin");
        pScript->chai->add(fun(&AssetContract::GetSquareRoot), "sqrt");
        pScript->chai->add(fun(&AssetContract::GetExponential), "exp");
        pScript->chai->add(fun(&AssetContract::GetNaturalLogarithm), "ln");
    } else
#endif // OT_USE_SCRIPT_CHAI
    {
        otErr << "OTScriptable::RegisterOTNativeCallsWithScript: Failed dynamic casting OTScript to OTScriptChai \n";
    }
}


// Returns a string, containing seconds as int32_t. (Time in seconds.)
std::string AssetContract::GetTime(){
    const time64_t CURRENT_TIME = OTTimeGetCurrentTime();
    const int64_t lTime = OTTimeGetSecondsFromTime(CURRENT_TIME);
    String strTime;
    strTime.Format("%" PRId64, lTime);
    return	strTime.Get();
}
// Returns a string, containing Pi
std::string AssetContract::GetPi(){
    String strPi;
    strPi.Format("%F", M_PI);
    return strPi.Get();
}
// Returns a string, containing the sine value for the given angle in radians
std::string AssetContract::GetSine(const std::string angleRadians){
    double angleRadiansValue = atof(angleRadians.c_str());
    double result = sin(angleRadiansValue);
    String strSine;
    strSine.Format("%F", result);
    return strSine.Get();
}
// Returns a string, containing the cosine value for the given angle in radians
std::string AssetContract::GetCosine(const std::string angleRadians){
    double angleRadiansValue = atof(angleRadians.c_str());
    double result = cos(angleRadiansValue);
    String strCosine;
    strCosine.Format("%F", result);
    return strCosine.Get();
}
// Returns a string, containing the arcsine value for the given angle in radians
std::string AssetContract::GetArcsine(const std::string angleRadians){
    double angleRadiansValue = atof(angleRadians.c_str());
    double result = asin(angleRadiansValue);
    String strArcsine;
    strArcsine.Format("%F", result);
    return strArcsine.Get();
}
// Returns a string, containing the square root of the supplied value
std::string AssetContract::GetSquareRoot(const std::string value){
    double valueAsDouble = atof(value.c_str());
    double result = sqrt(valueAsDouble);
    String strSquareRoot;
    strSquareRoot.Format("%F", result);
    return strSquareRoot.Get();
}
// Returns a string, containing the exponential of the supplied value
std::string AssetContract::GetExponential(const std::string value){
    double valueAsDouble = atof(value.c_str());
    double result = exp(valueAsDouble);
    String strExponential;
    strExponential.Format("%F", result);
    return strExponential.Get();
}
// Returns a string, containing the natural logarithm of the supplied value
std::string AssetContract::GetNaturalLogarithm(const std::string value){
    double valueAsDouble = atof(value.c_str());
    double result = log(valueAsDouble);
    String strNaturalLogarithm;
    strNaturalLogarithm.Format("%F", result);
    return strNaturalLogarithm.Get();
}


bool AssetContract::ExecuteClause(OTClause & theCallbackClause, mapOfVariables & theParameters, OTVariable & varReturnVal){
    const std::string str_clause_name = theCallbackClause.GetName().Exists() ? theCallbackClause.GetName().Get() : "";
    OT_ASSERT(AssetContract::ValidateName(str_clause_name));

    OTBylaw* pBylaw = theCallbackClause.GetBylaw();
    OT_ASSERT(nullptr != pBylaw);

    // By this point, we have the clause we are executing as theCallbackClause,
    // and we have the Bylaw it belongs to, as pBylaw.
    const std::string str_code = theCallbackClause.GetCode(); // source code for the script.
    const std::string str_language = pBylaw->GetLanguage(); // language it's in. (Default is "chai")

    std::shared_ptr<OTScript> pScript = OTScriptFactory(str_language, str_code);

    // SET UP THE NATIVE CALLS, REGISTER THE PARTIES, REGISTER THE VARIABLES,
    // AND EXECUTE THE SCRIPT.
    if (pScript) {
        // Register the special server-side native OT calls we make available to
        // all scripts.
        RegisterOTNativeCallsWithScript(*pScript);

        // Add the parameters...
        for (auto& it : theParameters) {
            const std::string str_var_name = it.first;
            OTVariable* pVar = it.second;
            OT_ASSERT((nullptr != pVar) && (str_var_name.size() > 0));

            pVar->RegisterForExecution(*pScript);
        }

        // Also need to loop through the Variables on pBylaw and register those as well.
        // This sets all the variables as CLEAN so we can check for dirtiness after execution.
        pBylaw->RegisterVariablesForExecution(*pScript);

        //SetDisplayLabel(&str_clause_name);
        //pScript->SetDisplayFilename(m_strLabel.Get());

        if (!pScript->ExecuteScript(&varReturnVal)) {
            otErr << "AssetContract::ExecuteClause: Error while running clause on assetContract.\n";
        } else {
            otOut << "AssetContract::ExecuteClause: Successfully executed clause on assetContract.\n\n";
            return true;
        }
    } else {
        otErr << "AssetContract::ExecuteClause: Error instantiating script!\n";
    }

    return false;
}


} // namespace opentxs

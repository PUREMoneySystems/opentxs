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

#include <opentxs/server/OTServer.hpp>
#include <opentxs/server/ClientConnection.hpp>
#include <opentxs/server/ConfigLoader.hpp>
#include <opentxs/server/Macros.hpp>
#include <opentxs/server/ServerSettings.hpp>
#include <opentxs/server/PayDividendVisitor.hpp>

#include <opentxs/ext/Helpers.hpp>
#include <opentxs/ext/OTPayment.hpp>
#include <opentxs/cash/Purse.hpp>
#include <opentxs/cash/Token.hpp>
#include <opentxs/basket/Basket.hpp>
#include <opentxs/core/crypto/OTAsymmetricKey.hpp>
#include <opentxs/core/Account.hpp>
#include <opentxs/core/AssetContract.hpp>
#include <opentxs/core/crypto/OTCachedKey.hpp>
#include <opentxs/core/Cheque.hpp>
#include <opentxs/core/util/OTDataFolder.hpp>
#include <opentxs/core/crypto/OTEnvelope.hpp>
#include <opentxs/core/util/OTFolders.hpp>
#include <opentxs/core/crypto/OTKeyring.hpp>
#include <opentxs/core/Ledger.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/trade/OTMarket.hpp>
#include <opentxs/core/Message.hpp>
#include <opentxs/core/crypto/OTNymOrSymmetricKey.hpp>
#include <opentxs/core/trade/OTOffer.hpp>
#include <opentxs/core/script/OTParty.hpp>
#include <opentxs/core/script/OTPartyAccount.hpp>
#include <opentxs/core/crypto/OTPassword.hpp>
#include <opentxs/core/util/OTPaths.hpp>
#include <opentxs/core/recurring/OTPaymentPlan.hpp>
#include <opentxs/core/OTServerContract.hpp>
#include <opentxs/core/script/OTSmartContract.hpp>
#include <opentxs/core/trade/OTTrade.hpp>

#include <irrxml/irrXML.hpp>

#include <string>
#include <map>
#include <memory>
#include <fstream>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#endif

#define SERVER_PID_FILENAME "ot.pid"

namespace opentxs
{

namespace
{

void askInteractively(std::string& strContract, std::string& strNotaryID,
                      std::string& strCert, std::string& strNymID,
                      std::string& strCachedKey)
{
    const char * szInstructions =
        "\n\n ==> WARNING: Main file not found. To create it, continue this process now...\n\n"
        "REQUIREMENTS:\n"
        "-- You must already have a temporary wallet, where you have created one Nym.\n"
        "   (That Nym will be the Signer Nym for your new Notary server.)\n"
        "   And FYI, you should delete the temporary wallet after the new notary\n"
        "   is successfully up and running. (Do NOT use it as a real wallet.)\n"
        "-- Create a new notary server contract. The easiest way is to use\n"
        "   the Moneychanger GUI to do this. (Otherwise, 'opentxs newserver')\n"
        "-- The Moneychanger GUI will create a Zipfile containing the new\n"
        "   Signer Nym's credentials.\n"
        "-- The Moneychanger GUI will also create a text file containing:\n"
        "   1. The new Notary ID.\n"
        "   2. The Signer Nym ID.\n"
        "   3. The cachedKey (from client_data/wallet.xml)\n"
        "   4. The new Notary Server Contract itself.\n"
        "\n(If you don't use Moneychanger to create the notary server contract, then\n"
        "you will have to pull together the above pieces by hand.)\n"
        "FYI, on Linux, the wallet.xml is found in: ~/.ot/client_data\n"
        "On a Mac:\n/Users/username/Library/Application Support/OpenTransactions/client_data\n\n"
        " ==> WARNING: Main file not found. To create it, continue this "
        "process now...\n\n";

    Log::Output(0, szInstructions);
    Log::Output(0, "Enter the NotaryID for your server contract: ");
    strNotaryID = OT_CLI_ReadLine();
    Log::Output(0, "Enter the Signer Nym ID: ");
    strNymID = OT_CLI_ReadLine();
    Log::Output(0, "Paste the cachedKey (ONLY the base64-encoded portion) below. It can\n"
                   "be found by pasting the wallet.xml contents into 'opentxs decode'\n"
                   "MORE EASILY, the cachedKey is found in the New_Notary_Creation_File.txt\n"
                   "that is automatically generated by Moneychanger when creating a new\n"
                   "notary server contract.\n\n"
                   "Paste the cachedKey below. Terminate with '~' on a line by itself.\n\n");

    strCachedKey = OT_CLI_ReadUntilEOF();
    
//    Log::Output(0, "Paste the contents of the server Nym's certfile, "
//                   "including public/PRIVATE, below.\n"
//                   "NOTE: LEAVE THIS BLANK unless you REALLY want to use the "
//                   "OLD system. If you leave this\n"
//                   "blank (preferred), it will instead use the new "
//                   "credentials system. (Just make sure\n"
//                   "you copied over the \"credentials\" folder, as described "
//                   "above, since we're about to\n"
//                   "use it, if you leave this blank.)\n"
//                   "Terminate with '~' on a line by itself.\n\n");
//    strCert = OT_CLI_ReadUntilEOF();
    
    std::string str_formed_path;
    OTDB::FormPathString(str_formed_path, OTFolders::Credential().Get(),
                         strNymID.c_str());
    Log::Output(0, "---------------------------------------------------------\n");
    Log::Output(0, "===> Next, create this folder on your system:\n");
    Log::Output(0, str_formed_path.c_str());
    Log::Output(0, "\n\nOnce the above folder is created, unzip this file inside it:\nNew_Notary_SignerNym_Credentials.zip\n\n");
    Log::Output(0, "NOTE: That's the Zipfile that Moneychanger created. If you didn't use\n"
                "Moneychanger, then you need to copy the Signer Nym's credentials by hand from\n"
                "the client_data/credentials folder into the server_data/credentials folder.\n\n"
                "Once the files are in that folder, press Enter to continue...");
    
    strCert = OT_CLI_ReadLine();
    strCert = "";
    
    // signed server contract
    Log::Output(0, "\nPaste the complete, signed, server contract below. (You "
                   "must already have it.)\n"
                   "Terminate with '~' on a line by itself.\n\n");

    strContract = OT_CLI_ReadUntilEOF();
}

} // namespace

#ifdef _WIN32
int32_t OTCron::__trans_refill_amount =
    500; // The number of transaction numbers Cron will grab for itself, when it
         // gets low, before each round.
int32_t OTCron::__cron_ms_between_process = 10000; // The number of milliseconds
                                                   // (ideally) between each
                                                   // "Cron Process" event.
int32_t OTCron::__cron_max_items_per_nym = 10;     // The maximum number of cron
// items any given Nym can have
// active at the same time.
#endif

void OTServer::ActivateCron()
{
    Log::vOutput(1, "OTServer::ActivateCron: %s \n",
                 m_Cron.ActivateCron() ? "(STARTED)" : "FAILED");
}

/// Currently the test server calls this 10 times per second.
/// It also processes all the input/output at the same rate.
/// It sleeps in between. (See testserver.cpp for the call
/// and OTLog::Sleep() for the sleep code.)
///
void OTServer::ProcessCron()
{
    if (!m_Cron.IsActivated()) return;

    bool bAddedNumbers = false;

    // Cron requires transaction numbers in order to process.
    // So every time before I call Cron.Process(), I make sure to replenish
    // first.
    while (m_Cron.GetTransactionCount() < OTCron::GetCronRefillAmount()) {
        int64_t lTransNum = 0;
        bool bSuccess = transactor_.issueNextTransactionNumber(lTransNum);

        if (bSuccess) {
            m_Cron.AddTransactionNumber(lTransNum);
            bAddedNumbers = true;
        }
        else
            break;
    }

    if (bAddedNumbers) {
        m_Cron.SaveCron();
    }

    m_Cron.ProcessCronItems(); // This needs to be called regularly for trades,
                               // markets, payment plans, etc to process.

    // NOTE:  TODO:  OTHER RE-OCCURRING SERVER FUNCTIONS CAN GO HERE AS WELL!!
    //
    // Such as sweeping server accounts after expiration dates, etc.
}

const Nym& OTServer::GetServerNym() const
{
    return m_nymServer;
}

bool OTServer::IsFlaggedForShutdown() const
{
    return m_bShutdownFlag;
}

OTServer::OTServer()
    : mainFile_(this)
    , notary_(this)
    , transactor_(this)
    , userCommandProcessor_(this)
    , m_bReadOnly(false)
    , m_bShutdownFlag(false)
    , m_pServerContract()
{
}

OTServer::~OTServer()
{
    // PID -- Set it to 0 in the lock file so the next time we run OT, it knows
    // there isn't
    // another copy already running (otherwise we might wind up with two copies
    // trying to write
    // to the same data folder simultaneously, which could corrupt the data...)
    //
    //    OTLog::vError("m_strDataPath: %s\n", m_strDataPath.Get());
    //    OTLog::vError("SERVER_PID_FILENAME: %s\n", SERVER_PID_FILENAME);

    String strDataPath;
    const bool bGetDataFolderSuccess = OTDataFolder::Get(strDataPath);
    if (!m_bReadOnly && bGetDataFolderSuccess) {
        String strPIDPath;
        OTPaths::AppendFile(strPIDPath, strDataPath, SERVER_PID_FILENAME);

        std::ofstream pid_outfile(strPIDPath.Get());

        if (pid_outfile.is_open()) {
            uint32_t the_pid = 0;
            pid_outfile << the_pid;
            pid_outfile.close();
        }
        else
            Log::vError("Failed trying to open data locking file (to wipe "
                        "PID back to 0): %s\n",
                        strPIDPath.Get());
    }
}

void OTServer::Init(bool readOnly)
{
    m_bReadOnly = readOnly;

    if (!OTDataFolder::IsInitialized()) {
        Log::vError("Unable to Init data folders!");
        OT_FAIL;
    }
    if (!ConfigLoader::load(m_strWalletFilename)) {
        Log::vError("Unable to Load Config File!");
        OT_FAIL;
    }

    String dataPath;
    bool bGetDataFolderSuccess = OTDataFolder::Get(dataPath);

    // PID -- Make sure we're not running two copies of OT on the same data
    // simultaneously here.
    if (bGetDataFolderSuccess) {
        // If we want to WRITE to the data location, then we can't be in
        // read-only mode.
        if (!readOnly) {
            // 1. READ A FILE STORING THE PID. (It will already exist, if OT is
            // already running.)
            //
            // We open it for reading first, to see if it already exists. If it
            // does, we read the number. 0 is fine, since we overwrite with 0 on
            // shutdown. But any OTHER number means OT is still running. Or it
            // means it was killed while running and didn't shut down properly,
            // and that you need to delete the pid file by hand before running
            // OT again. (This is all for the purpose of preventing two copies
            // of OT running at the same time and corrupting the data folder.)
            //
            String strPIDPath;
            OTPaths::AppendFile(strPIDPath, dataPath, SERVER_PID_FILENAME);

            std::ifstream pid_infile(strPIDPath.Get());

            // 2. (IF FILE EXISTS WITH ANY PID INSIDE, THEN DIE.)
            if (pid_infile.is_open()) {
                uint32_t old_pid = 0;
                pid_infile >> old_pid;
                pid_infile.close();

                // There was a real PID in there.
                if (old_pid != 0) {
                    uint64_t lPID = old_pid;
                    Log::vError(
                        "\n\n\nIS OPEN-TRANSACTIONS ALREADY RUNNING?\n\n"
                        "I found a PID (%" PRIu64
                        ") in the data lock file, located "
                        "at: %s\n\n"
                        "If the OT process with PID %" PRIu64
                        " is truly not running "
                        "anymore, "
                        "then just ERASE THAT FILE and then RESTART.\n",
                        lPID, strPIDPath.Get(), lPID);
                    exit(-1);
                }
                // Otherwise, though the file existed, the PID within was 0.
                // (Meaning the previous instance of OT already set it to 0 as
                // it was shutting down.)
            }
            // Next let's record our PID to the same file, so other copies of OT
            // can't trample on US.

            // 3. GET THE CURRENT (ACTUAL) PROCESS ID.
            uint64_t the_pid = 0;

#ifdef _WIN32
            the_pid = GetCurrentProcessId();
#else
            the_pid = getpid();
#endif

            // 4. OPEN THE FILE IN WRITE MODE, AND SAVE THE PID TO IT.
            std::ofstream pid_outfile(strPIDPath.Get());

            if (pid_outfile.is_open()) {
                pid_outfile << the_pid;
                pid_outfile.close();
            }
            else {
                Log::vError("Failed trying to open data locking file (to "
                            "store PID %" PRIu64 "): %s\n",
                            the_pid, strPIDPath.Get());
            }
        }
    }
    OTDB::InitDefaultStorage(OTDB_DEFAULT_STORAGE, OTDB_DEFAULT_PACKER);

    // Load up the transaction number and other OTServer data members.
    bool mainFileExists = m_strWalletFilename.Exists()
                              ? OTDB::Exists(".", m_strWalletFilename.Get())
                              : false;

    if (!mainFileExists) {
        if (readOnly) {
            Log::vError(
                "Error: Main file non-existent (%s). "
                "Plus, unable to create, since read-only flag is set.\n",
                m_strWalletFilename.Get());
            OT_FAIL;
        }
        else {
            std::string strContract;
            std::string strNotaryID;
            std::string strCert;
            std::string strNymID;
            std::string strCachedKey;
            askInteractively(strContract, strNotaryID, strCert, strNymID,
                             strCachedKey);
            mainFileExists = mainFile_.CreateMainFile(
                strContract, strNotaryID, strCert, strNymID, strCachedKey);
        }
    }

    if (mainFileExists) {
        if (!mainFile_.LoadMainFile(readOnly)) {
            Log::vError("Error in Loading Main File!\n");
            OT_FAIL;
        }
    }

    // With the Server's private key loaded, and the latest transaction number
    // loaded, and all the various other data (contracts, etc) the server is now
    // ready for operation!
}

// msg, the request msg from payer, which is attached WHOLE to the Nymbox
// receipt. contains payment already.
// or pass pPayment instead: we will create our own msg here (with payment
// inside) to be attached to the receipt.
// szCommand for passing payDividend (as the message command instead of
// sendNymInstrument, the default.)
bool OTServer::SendInstrumentToNym(
    const Identifier& NOTARY_ID, const Identifier& SENDER_NYM_ID,
    const Identifier& RECIPIENT_NYM_ID,
    Message* pMsg,             // the request msg from payer, which is attached
                               // WHOLE to the Nymbox receipt. contains payment
                               // already.
    const OTPayment* pPayment, // or pass this instead: we will create
                               // our own msg here (with message
                               // inside) to be attached to the
                               // receipt.
    const char* szCommand)
{
    OT_ASSERT_MSG(
        !((nullptr == pMsg) && (nullptr == pPayment)),
        "pMsg and pPayment -- these can't BOTH be nullptr.\n"); // must provide
                                                                // one
                                                                // or the other.
    OT_ASSERT_MSG(
        !((nullptr != pMsg) && (nullptr != pPayment)),
        "pMsg and pPayment -- these can't BOTH be not-nullptr.\n"); // can't
                                                                    // provide
                                                                    // both.
    OT_ASSERT_MSG((nullptr == pPayment) ||
                      ((nullptr != pPayment) && pPayment->IsValid()),
                  "OTServer::SendInstrumentToNym: You can only pass a valid "
                  "payment here.");
    // If a payment was passed in (for us to use it to construct pMsg, which is
    // nullptr in the case where payment isn't nullptr)
    // Then we grab it in string form, so we can pass it on...
    String strPayment;
    if (nullptr != pPayment) {
        const bool bGotPaymentContents =
            pPayment->GetPaymentContents(strPayment);
        if (!bGotPaymentContents)
            Log::vError("%s: Error GetPaymentContents Failed", __FUNCTION__);
    }
    const bool bDropped = DropMessageToNymbox(
        NOTARY_ID, SENDER_NYM_ID, RECIPIENT_NYM_ID,
        OTTransaction::instrumentNotice, pMsg,
        (nullptr != pMsg) ? nullptr : &strPayment, szCommand);

    return bDropped;
}

// Can't be static (transactor_.issueNextTransactionNumber is called...)
//
// About pMsg...
// (Normally) when you send a cheque to someone, you encrypt it inside an
// envelope, and that
// envelope is attached to a OTMessage (sendNymInstrument) and sent to the
// server. The server
// takes your entire OTMessage and attaches it to an instrumentNotice
// (OTTransaction) which is
// added to the recipient's Nymbox.
// In that case, just pass the pointer to the incoming message here as pMsg, and
// the OT Server
// will attach it as described.
// But let's say you are paying a dividend. The server can't just attach your
// dividend request in
// that case. Normally the recipient's cheque is already in the request. But
// with a dividend, there
// could be a thousand recipients, and their individual vouchers are only
// generated and sent AFTER
// the server receives the "pay dividend" request.
// Therefore in that case, nullptr would be passed for pMsg, meaning that inside
// this function we have
// to generate our own OTMessage "from the server" instead of "from the sender".
// After all, the server's
// private key is the only signer we have in here. And the recipient will be
// expecting to have to
// open a message, so we must create one to give him. So if pMsg is nullptr,
// then
// this function will
// create a message "from the server", containing the instrument, and drop it
// into the recipient's nymbox
// as though it were some incoming message from a normal user.
// This message, in the case of payDividend, should be an "payDividendResponse"
// message, "from" the server
// and "to" the recipient. The payment instrument must be attached to that new
// message, and therefore it
// must be passed into this function.
// Of course, if pMsg was not nullptr, that means the message (and instrument
// inside of it) already exist,
// so no instrument would need to be passed. But if pMsg IS nullptr, that means
// the
// msg must be generated,
// and thus the instrument MUST be passed in, so that that can be done.
// Therefore the instrument will sometimes be passed in, and sometimes not.
// Therefore the instrument must
// be passed as a pointer.
//
// Conclusion: if pMsg is passed in, then pass a null instrument. (Since the
// instrument is already on pMsg.)
//                (And since the instrument defaults to nullptr, this makes pMsg
// the final argument in the call.)
//         but if pMsg is nullptr, then you must pass the payment instrument as
// the
// next argument. (So pMsg can be created with it.)
// Note: you cannot pass BOTH, or the instrument will simply be ignored, since
// it's already assumed to be in pMsg.
// You might ask: what about the original request then, doesn't the recipient
// get a copy of that? Well, maybe we
// pass it in here and attach it to the new message. Or maybe we just set it as
// the voucher memo.
//
bool OTServer::DropMessageToNymbox(const Identifier& NOTARY_ID,
                                   const Identifier& SENDER_NYM_ID,
                                   const Identifier& RECIPIENT_NYM_ID,
                                   OTTransaction::transactionType theType,
                                   Message* pMsg, const String* pstrMessage,
                                   const char* szCommand) // If you pass
                                                          // something here, it
                                                          // will
// replace pMsg->m_strCommand below
{
    OT_ASSERT_MSG(
        !((nullptr == pMsg) && (nullptr == pstrMessage)),
        "pMsg and pstrMessage -- these can't BOTH be nullptr.\n"); // must
                                                                   // provide
                                                                   // one or the
                                                                   // other.
    OT_ASSERT_MSG(
        !((nullptr != pMsg) && (nullptr != pstrMessage)),
        "pMsg and pstrMessage -- these can't BOTH be not-nullptr.\n"); // can't
    // provide
    // both.
    const char* szFunc = "OTServer::DropMessageToNymbox";
    int64_t lTransNum = 0;
    const bool bGotNextTransNum =
        transactor_.issueNextTransactionNumber(lTransNum);

    if (!bGotNextTransNum) {
        Log::vError(
            "%s: Error: failed trying to get next transaction number.\n",
            szFunc);
        return false;
    }
    switch (theType) {
    case OTTransaction::message:
        break;
    case OTTransaction::instrumentNotice:
        break;
    default:
        Log::vError(
            "%s: Unexpected transactionType passed here (expected message "
            "or instrumentNotice.)\n",
            szFunc);
        return false;
    }
    // If pMsg was not already passed in here, then
    // create pMsg using pstrMessage.
    //
    std::unique_ptr<Message> theMsgAngel;

    if (nullptr == pMsg) // we have to create it ourselves.
    {
        pMsg = new Message;
        theMsgAngel.reset(pMsg);
        if (nullptr != szCommand)
            pMsg->m_strCommand = szCommand;
        else {
            switch (theType) {
            case OTTransaction::message:
                pMsg->m_strCommand = "sendNymMessage";
                break;
            case OTTransaction::instrumentNotice:
                pMsg->m_strCommand = "sendNymInstrument";
                break;
            default:
                break; // should never happen.
            }
        }
        pMsg->m_strNotaryID = m_strNotaryID;
        pMsg->m_bSuccess = true;
        SENDER_NYM_ID.GetString(pMsg->m_strNymID);
        RECIPIENT_NYM_ID.GetString(pMsg->m_strNymID2); // set the recipient ID
                                                       // in pMsg to match our
                                                       // recipient ID.
        // Load up the recipient's public key (so we can encrypt the envelope
        // to him that will contain the payment instrument.)
        //
        Nym nymRecipient(RECIPIENT_NYM_ID);

        bool bLoadedNym =
            nymRecipient.LoadPublicKey(); // Old style (deprecated.) But this
                                          // function calls the new style,
                                          // LoadCredentials, at the top.
                                          // Eventually we'll just call that
                                          // here directly.
        if (!bLoadedNym) {
            Log::vError("%s: Failed trying to load public key for recipient.\n",
                        szFunc);
            return false;
        }
        else if (!nymRecipient.VerifyPseudonym()) {
            Log::vError("%s: Failed trying to verify Nym for recipient.\n",
                        szFunc);
            return false;
        }
        const OTAsymmetricKey& thePubkey = nymRecipient.GetPublicEncrKey();
        // Wrap the message up into an envelope and attach it to pMsg.
        //
        OTEnvelope theEnvelope;

        pMsg->m_ascPayload.Release();

        if ((nullptr != pstrMessage) && pstrMessage->Exists() &&
            theEnvelope.Seal(thePubkey, *pstrMessage) && // Seal pstrMessage
                                                         // into theEnvelope,
                                                         // using nymRecipient's
                                                         // public key.
            theEnvelope.GetAsciiArmoredData(
                pMsg->m_ascPayload)) // Grab the sealed version as
                                     // base64-encoded string, into
                                     // pMsg->m_ascPayload.
        {
            pMsg->SignContract(m_nymServer);
            pMsg->SaveContract();
        }
        else {
            Log::vError("%s: Failed trying to seal envelope containing message "
                        "(or while grabbing the base64-encoded result.)\n",
                        szFunc);
            return false;
        }

        // By this point, pMsg is all set up, signed and saved. Its payload
        // contains
        // the envelope (as base64) containing the encrypted message.
    }
    //  else // pMsg was passed in, so it's not nullptr. No need to create it
    // ourselves like above. (pstrMessage should be nullptr anyway in this
    // case.)
    //  {
    //       // Apparently no need to do anything in here at all.
    //  }
    // Grab a string copy of pMsg.
    //
    const String strInMessage(*pMsg);
    Ledger theLedger(RECIPIENT_NYM_ID, RECIPIENT_NYM_ID,
                     NOTARY_ID); // The recipient's Nymbox.
    // Drop in the Nymbox
    if ((theLedger.LoadNymbox() && // I think this loads the box receipts too,
                                   // since I didn't call "LoadNymboxNoVerify"
         //          theLedger.VerifyAccount(m_nymServer)    &&    // This loads
         // all the Box Receipts, which is unnecessary.
         theLedger.VerifyContractID() && // Instead, we'll verify the IDs and
                                         // Signature only.
         theLedger.VerifySignature(m_nymServer))) {
        // Create the instrumentNotice to put in the Nymbox.
        OTTransaction* pTransaction =
            OTTransaction::GenerateTransaction(theLedger, theType, lTransNum);

        if (nullptr != pTransaction) // The above has an OT_ASSERT within, but I
                                     // just like to check my pointers.
        {
            // NOTE: todo: SHOULD this be "in reference to" itself? The reason,
            // I assume we are doing this
            // is because there is a reference STRING so "therefore" there must
            // be a reference # as well. Eh?
            // Anyway, it must be understood by those involved that a message is
            // stored inside. (Which has no transaction #.)

            pTransaction->SetReferenceToNum(lTransNum); // <====== Recipient
                                                        // RECEIVES entire
                                                        // incoming message as
                                                        // string here, which
                                                        // includes the sender
                                                        // user ID,
            pTransaction->SetReferenceString(
                strInMessage); // and has an OTEnvelope in the payload. Message
                               // is signed by sender, and envelope is encrypted
                               // to recipient.

            pTransaction->SignContract(m_nymServer);
            pTransaction->SaveContract();
            theLedger.AddTransaction(*pTransaction); // Add the message
                                                     // transaction to the
                                                     // nymbox. (It will
                                                     // cleanup.)

            theLedger.ReleaseSignatures();
            theLedger.SignContract(m_nymServer);
            theLedger.SaveContract();
            theLedger.SaveNymbox(); // We don't grab the Nymbox hash here, since
                                    // nothing important changed (just a message
                                    // was sent.)

            // Any inbox/nymbox/outbox ledger will only itself contain
            // abbreviated versions of the receipts, including their hashes.
            //
            // The rest is stored separately, in the box receipt, which is
            // created
            // whenever a receipt is added to a box, and deleted after a receipt
            // is removed from a box.
            //
            pTransaction->SaveBoxReceipt(theLedger);

            return true;
        }
        else // should never happen
        {
            const String strRecipientNymID(RECIPIENT_NYM_ID);
            Log::vError(
                "%s: Failed while trying to generate transaction in order to "
                "add a message to Nymbox: %s\n",
                szFunc, strRecipientNymID.Get());
        }
    }
    else {
        const String strRecipientNymID(RECIPIENT_NYM_ID);
        Log::vError("%s: Failed while trying to load or verify Nymbox: %s\n",
                    szFunc, strRecipientNymID.Get());
    }

    return false;
}

bool OTServer::GetConnectInfo(String& strHostname, int32_t& nPort) const
{
    if (!m_pServerContract) return false;

    return m_pServerContract->GetConnectInfo(strHostname, nPort);
}

zcert_t* OTServer::GetTransportKey() const
{
    return OTServerContract::LoadOrCreateTransportKey(m_strServerNymID);
}

} // namespace opentxs

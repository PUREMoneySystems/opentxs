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

#ifndef OPENTXS_CLIENT_OT_ME_HPP
#define OPENTXS_CLIENT_OT_ME_HPP

#include <opentxs/core/util/Common.hpp>

namespace opentxs
{

class String;

EXPORT int32_t OT_CLI_GetArgsCount(const std::string& str_Args);
EXPORT std::string OT_CLI_GetValueByKey(const std::string& str_Args,
                                        const std::string& str_key);
EXPORT std::string OT_CLI_GetValueByIndex(const std::string& str_Args,
                                          int32_t nIndex);
EXPORT std::string OT_CLI_GetKeyByIndex(const std::string& str_Args,
                                        int32_t nIndex);

class OTScript;
class OTScriptChai;
class OTVariable;

class OT_ME
{
public:
    EXPORT OT_ME();
    EXPORT ~OT_ME();

    EXPORT int32_t VerifyMessageSuccess(const std::string& str_Message) const;

    EXPORT int32_t
        VerifyMsgBalanceAgrmntSuccess(const std::string& NOTARY_ID,
                                      const std::string& NYM_ID,
                                      const std::string& ACCOUNT_ID,
                                      const std::string& str_Message) const;

    EXPORT int32_t VerifyMsgTrnxSuccess(const std::string& NOTARY_ID,
                                        const std::string& NYM_ID,
                                        const std::string& ACCOUNT_ID,
                                        const std::string& str_Message) const;

    EXPORT int32_t
        InterpretTransactionMsgReply(const std::string& NOTARY_ID,
                                     const std::string& NYM_ID,
                                     const std::string& ACCOUNT_ID,
                                     const std::string& str_Attempt,
                                     const std::string& str_Response) const;

    EXPORT int32_t
        ExecuteScript_ReturnInt(const std::string& str_Code,
                                std::string str_DisplayName = "<BLANK>");
    EXPORT void ExecuteScript_ReturnVoid(
        const std::string& str_Code, std::string str_DisplayName = "<BLANK>");

    EXPORT void AddVariable(const std::string& str_var_name,
                            OTVariable& theVar);
    EXPORT OTVariable* FindVariable(const std::string& str_var_name);

    EXPORT static OTVariable* FindVariable2(const std::string& str_var_name);

    // OTMeCpp implementation

    EXPORT bool make_sure_enough_trans_nums(int32_t nNumberNeeded,
                                            const std::string& NOTARY_ID,
                                            const std::string& NYM_ID) const;

    EXPORT std::string register_nym(const std::string& NOTARY_ID,
                                    const std::string& NYM_ID) const;

    EXPORT std::string check_nym(const std::string& NOTARY_ID,
                                 const std::string& NYM_ID,
                                 const std::string& TARGET_NYM_ID) const;

    EXPORT std::string create_nym(int32_t nKeybits,
                                  const std::string& NYM_ID_SOURCE,
                                  const std::string& ALT_LOCATION) const;

    EXPORT std::string issue_asset_type(const std::string& NOTARY_ID,
                                        const std::string& NYM_ID,
                                        const std::string& THE_CONTRACT) const;

    EXPORT std::string issue_basket_currency(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& THE_BASKET) const;

    EXPORT std::string exchange_basket_currency(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& INSTRUMENT_DEFINITION_ID,
        const std::string& THE_BASKET, const std::string& ACCOUNT_ID,
        bool IN_OR_OUT) const;

    EXPORT std::string retrieve_contract(const std::string& NOTARY_ID,
                                         const std::string& NYM_ID,
                                         const std::string& CONTRACT_ID) const;

    EXPORT std::string load_or_retrieve_contract(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& CONTRACT_ID) const;

    EXPORT std::string create_asset_acct(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& INSTRUMENT_DEFINITION_ID) const;

    EXPORT std::string stat_asset_account(const std::string& ACCOUNT_ID) const;

    EXPORT bool retrieve_account(const std::string& NOTARY_ID,
                                 const std::string& NYM_ID,
                                 const std::string& ACCOUNT_ID,
                                 bool bForceDownload = false) const;

    EXPORT bool retrieve_nym(const std::string& NOTARY_ID,
                             const std::string& NYM_ID,
                             bool bForceDownload = true) const;

    EXPORT std::string send_transfer(const std::string& NOTARY_ID,
                                     const std::string& NYM_ID,
                                     const std::string& ACCT_FROM,
                                     const std::string& ACCT_TO, int64_t AMOUNT,
                                     const std::string& NOTE) const;

    EXPORT std::string process_inbox(const std::string& NOTARY_ID,
                                     const std::string& NYM_ID,
                                     const std::string& ACCOUNT_ID,
                                     const std::string& RESPONSE_LEDGER) const;

    EXPORT bool accept_inbox_items(const std::string& ACCOUNT_ID,
                                   int32_t nItemType,
                                   const std::string& INDICES) const;

    EXPORT bool discard_incoming_payments(const std::string& NOTARY_ID,
                                          const std::string& NYM_ID,
                                          const std::string& INDICES) const;

    EXPORT bool cancel_outgoing_payments(const std::string& NYM_ID,
                                         const std::string& ACCOUNT_ID,
                                         const std::string& INDICES) const;

    EXPORT bool accept_from_paymentbox(const std::string& ACCOUNT_ID,
                                       const std::string& INDICES,
                                       const std::string& PAYMENT_TYPE) const;

    EXPORT std::string load_public_encryption_key(
        const std::string& NYM_ID) const;

    EXPORT std::string load_public_signing_key(const std::string& NYM_ID) const;

    EXPORT std::string load_or_retrieve_encrypt_key(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& TARGET_NYM_ID) const;

    EXPORT std::string send_user_msg_pubkey(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& RECIPIENT_NYM_ID,
        const std::string& RECIPIENT_PUBKEY,
        const std::string& THE_MESSAGE) const;

    EXPORT std::string send_user_pmnt_pubkey(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& RECIPIENT_NYM_ID,
        const std::string& RECIPIENT_PUBKEY,
        const std::string& THE_INSTRUMENT) const;

    EXPORT std::string send_user_cash_pubkey(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& RECIPIENT_NYM_ID,
        const std::string& RECIPIENT_PUBKEY, const std::string& THE_INSTRUMENT,
        const std::string& INSTRUMENT_FOR_SENDER) const;

    EXPORT std::string send_user_msg(const std::string& NOTARY_ID,
                                     const std::string& NYM_ID,
                                     const std::string& RECIPIENT_NYM_ID,
                                     const std::string& THE_MESSAGE) const;

    EXPORT std::string send_user_payment(const std::string& NOTARY_ID,
                                         const std::string& NYM_ID,
                                         const std::string& RECIPIENT_NYM_ID,
                                         const std::string& THE_PAYMENT) const;

    EXPORT std::string send_user_cash(const std::string& NOTARY_ID,
                                      const std::string& NYM_ID,
                                      const std::string& RECIPIENT_NYM_ID,
                                      const std::string& THE_PAYMENT,
                                      const std::string& SENDERS_COPY) const;

    EXPORT bool withdraw_and_send_cash(const std::string& ACCT_ID,
                                       const std::string& RECIPIENT_NYM_ID,
                                       int64_t AMOUNT) const;

    EXPORT std::string get_payment_instrument(
        const std::string& NOTARY_ID, const std::string& NYM_ID, int32_t nIndex,
        const std::string& PRELOADED_INBOX = "") const;

    EXPORT std::string get_box_receipt(const std::string& NOTARY_ID,
                                       const std::string& NYM_ID,
                                       const std::string& ACCT_ID,
                                       int32_t nBoxType,
                                       int64_t TRANS_NUM) const;

    EXPORT std::string retrieve_mint(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& INSTRUMENT_DEFINITION_ID) const;

    EXPORT std::string load_or_retrieve_mint(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& INSTRUMENT_DEFINITION_ID) const;

    EXPORT std::string create_market_offer(
        const std::string& ASSET_ACCT_ID, const std::string& CURRENCY_ACCT_ID,
        int64_t scale, int64_t minIncrement, int64_t quantity, int64_t price,
        bool bSelling, int64_t lLifespanInSeconds, const std::string& STOP_SIGN,
        int64_t ACTIVATION_PRICE) const;

    EXPORT std::string kill_market_offer(const std::string& NOTARY_ID,
                                         const std::string& NYM_ID,
                                         const std::string& ASSET_ACCT_ID,
                                         int64_t TRANS_NUM) const;

    EXPORT std::string kill_payment_plan(const std::string& NOTARY_ID,
                                         const std::string& NYM_ID,
                                         const std::string& ACCT_ID,
                                         int64_t TRANS_NUM) const;

    EXPORT std::string cancel_payment_plan(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& THE_PAYMENT_PLAN) const;

    EXPORT std::string activate_smart_contract(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& ACCT_ID, const std::string& AGENT_NAME,
        const std::string& THE_SMART_CONTRACT) const;

    EXPORT std::string trigger_clause(const std::string& NOTARY_ID,
                                      const std::string& NYM_ID,
                                      int64_t TRANS_NUM,
                                      const std::string& CLAUSE_NAME,
                                      const std::string& STR_PARAM) const;

    EXPORT std::string withdraw_cash(const std::string& NOTARY_ID,
                                     const std::string& NYM_ID,
                                     const std::string& ACCT_ID,
                                     int64_t AMOUNT) const;

    EXPORT bool easy_withdraw_cash(const std::string& ACCT_ID,
                                   int64_t AMOUNT) const;

    EXPORT std::string export_cash(const std::string& NOTARY_ID,
                                   const std::string& FROM_NYM_ID,
                                   const std::string& INSTRUMENT_DEFINITION_ID,
                                   const std::string& TO_NYM_ID,
                                   const std::string& STR_INDICES,
                                   bool bPasswordProtected,
                                   std::string& STR_RETAINED_COPY) const;

    EXPORT std::string withdraw_voucher(const std::string& NOTARY_ID,
                                        const std::string& NYM_ID,
                                        const std::string& ACCT_ID,
                                        const std::string& RECIP_NYM_ID,
                                        const std::string& STR_MEMO,
                                        int64_t AMOUNT) const;

    EXPORT std::string pay_dividend(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& SOURCE_ACCT_ID,
        const std::string& SHARES_INSTRUMENT_DEFINITION_ID,
        const std::string& STR_MEMO, int64_t AMOUNT_PER_SHARE) const;

    EXPORT std::string deposit_cheque(const std::string& NOTARY_ID,
                                      const std::string& NYM_ID,
                                      const std::string& ACCT_ID,
                                      const std::string& STR_CHEQUE) const;

    EXPORT bool deposit_cash(const std::string& NOTARY_ID,
                             const std::string& NYM_ID,
                             const std::string& ACCT_ID,
                             const std::string& STR_PURSE) const;

    EXPORT bool deposit_local_purse(const std::string& NOTARY_ID,
                                    const std::string& NYM_ID,
                                    const std::string& ACCT_ID,
                                    const std::string& STR_INDICES) const;

    EXPORT std::string get_market_list(const std::string& NOTARY_ID,
                                       const std::string& NYM_ID) const;

    EXPORT std::string get_market_offers(const std::string& NOTARY_ID,
                                         const std::string& NYM_ID,
                                         const std::string& MARKET_ID,
                                         int64_t MAX_DEPTH) const;

    EXPORT std::string get_nym_market_offers(const std::string& NOTARY_ID,
                                             const std::string& NYM_ID) const;

    EXPORT std::string get_market_recent_trades(
        const std::string& NOTARY_ID, const std::string& NYM_ID,
        const std::string& MARKET_ID) const;

    EXPORT std::string adjust_usage_credits(
        const std::string& NOTARY_ID, const std::string& USER_NYM_ID,
        const std::string& TARGET_NYM_ID, const std::string& ADJUSTMENT) const;

    EXPORT bool networkFailureRaw(); // This returns m_bNetworkFailure
    EXPORT bool networkFailure();    // This returns m_bNetworkFailure but also resets it back to false.
    
private:
    OT_ME(const OT_ME&);
    OT_ME& operator=(const OT_ME&);

    static OT_ME* s_pMe;

    OT_ME* r_pPrev; // For reference only. Do not delete.
    std::shared_ptr<OTScript> m_pScript;

    bool m_bNetworkFailure;
    
    bool HaveWorkingScript();

    bool Register_OTDB_With_Script();
    bool Register_CLI_With_Script();
    bool Register_API_With_Script();
    bool Register_Headers_With_Script();

#ifdef OT_USE_SCRIPT_CHAI
    bool SetupScriptObject();
    bool Register_OTDB_With_Script_Chai(const OTScriptChai& theScript) const;
    bool Register_CLI_With_Script_Chai(const OTScriptChai& theScript) const;
    bool Register_API_With_Script_Chai(const OTScriptChai& theScript) const;
    bool Register_Headers_With_Script_Chai(const OTScriptChai& theScript) const;
#endif
    bool NewScriptExists(const String& strScriptFilename, bool bIsHeader,
                         String& out_ScriptFilepath) const;
};

} // namespace opentxs

#endif // OPENTXS_CLIENT_OT_ME_HPP

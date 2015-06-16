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

#include <opentxs/server/ServerSettings.hpp>

namespace opentxs
{

// These are default values. There are configurable in ~/.ot/server.cfg
// (static)

int64_t ServerSettings::__min_market_scale = 1;
// The number of client requests that will be processed per heartbeat.
int32_t ServerSettings::__heartbeat_no_requests = 10;
// number of ms between each heartbeat.
int32_t ServerSettings::__heartbeat_ms_between_beats = 100;
// The Nym who's allowed to do certain
// commands even if they are turned off.
std::string ServerSettings::__override_nym_id;

// NOTE: These are all static variables, and these are all just default values.
//       (The ACTUAL values are configured in ~/.ot/server.cfg)
//
bool ServerSettings::__admin_usage_credits =
    false; // Are usage credits REQUIRED in order to use this server?
bool ServerSettings::__admin_server_locked =
    false; // Is server currently locked to non-override Nyms?
bool ServerSettings::__cmd_usage_credits =
    true; // Command for setting / viewing usage credits. (Keep this true even if usage credits are turned off. Otherwise the users won't get a server response when they ask it for the policy.)
bool ServerSettings::__cmd_issue_asset = true;
bool ServerSettings::__cmd_get_contract = true;
bool ServerSettings::__cmd_check_notary_id = true;
bool ServerSettings::__cmd_create_user_acct = true;
bool ServerSettings::__cmd_del_user_acct = true;
bool ServerSettings::__cmd_check_nym = true;
bool ServerSettings::__cmd_get_requestnumber = true;
bool ServerSettings::__cmd_get_trans_nums = true;
bool ServerSettings::__cmd_send_message = true;
bool ServerSettings::__cmd_get_nymbox = true;
bool ServerSettings::__cmd_process_nymbox = true;
bool ServerSettings::__cmd_create_asset_acct = true;
bool ServerSettings::__cmd_del_asset_acct = true;
bool ServerSettings::__cmd_get_acct = true;
bool ServerSettings::__cmd_get_inbox = true;
bool ServerSettings::__cmd_get_outbox = true;
bool ServerSettings::__cmd_process_inbox = true;
bool ServerSettings::__cmd_issue_basket = false;
bool ServerSettings::__transact_exchange_basket = true;
bool ServerSettings::__cmd_notarize_transaction = true;
bool ServerSettings::__transact_process_inbox = true;
bool ServerSettings::__transact_transfer = true;
bool ServerSettings::__transact_withdrawal = true;
bool ServerSettings::__transact_deposit = true;
bool ServerSettings::__transact_withdraw_voucher = true;
bool ServerSettings::__transact_deposit_cheque = true;
bool ServerSettings::__transact_pay_dividend = true;
bool ServerSettings::__cmd_get_mint = true;
bool ServerSettings::__transact_withdraw_cash = true;
bool ServerSettings::__transact_deposit_cash = true;
bool ServerSettings::__cmd_get_market_list = true;
bool ServerSettings::__cmd_get_market_offers = true;
bool ServerSettings::__cmd_get_market_recent_trades = true;
bool ServerSettings::__cmd_get_nym_market_offers = true;
bool ServerSettings::__transact_market_offer = true;
bool ServerSettings::__transact_payment_plan = true;
bool ServerSettings::__transact_cancel_cron_item = true;
bool ServerSettings::__transact_smart_contract = true;
bool ServerSettings::__cmd_trigger_clause = true;

// Todo: Might set ALL of these to false (so you're FORCED to set them true
// in the server.cfg file.) This way you're also assured that the right data
// folder was found, before you start unlocking the server messages!
//

} // namespace opentxs

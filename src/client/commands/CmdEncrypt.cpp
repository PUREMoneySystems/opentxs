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

#include "CmdEncrypt.hpp"

#include <opentxs/client/OTAPI.hpp>
#include <opentxs/core/Log.hpp>

using namespace opentxs;
using namespace std;

CmdEncrypt::CmdEncrypt()
{
    command = "encrypt";
    args[0] = "--hisnym <nym>";
    category = catAdmin;
    help = "Encrypt plaintext input using hisnym's public key.";
}

CmdEncrypt::~CmdEncrypt()
{
}

int32_t CmdEncrypt::runWithOptions()
{
    return run(getOption("hisnym"));
}

int32_t CmdEncrypt::run(string hisnym)
{
    if (!checkNym("hisnym", hisnym)) {
        return -1;
    }

    string input = inputText("the plaintext to be encrypted");
    if ("" == input) {
        return -1;
    }

    string output = OTAPI_Wrap::Encrypt(hisnym, input);
    if ("" == output) {
        otOut << "Error: cannot encrypt input.\n";
        return -1;
    }

    dashLine();
    otOut << "Encrypted:\n\n";
    cout << output << "\n";

    return 1;
}

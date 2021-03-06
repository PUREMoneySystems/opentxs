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

#include "CmdNewBasket.hpp"

#include "CmdShowAssets.hpp"
#include "../ot_made_easy_ot.hpp"

#include <opentxs/client/OTAPI.hpp>
#include <opentxs/core/Log.hpp>

using namespace opentxs;
using namespace std;

CmdNewBasket::CmdNewBasket()
{
    command = "newbasket";
    args[0] = "--server <server>";
    args[1] = "--mynym <nym>";
    args[2] = "--assets <nrOfAssets>";
    args[2] = "--minimum <minTransfer>";
    category = catBaskets;
    help = "Create a new basket currency.";
}

CmdNewBasket::~CmdNewBasket()
{
}

int32_t CmdNewBasket::runWithOptions()
{
    return run(getOption("server"), getOption("mynym"), getOption("assets"),
               getOption("minimum"));
}

int32_t CmdNewBasket::run(string server, string mynym, string assets,
                          string minimum)
{
    if (!checkServer("server", server)) {
        return -1;
    }

    if (!checkNym("mynym", mynym)) {
        return -1;
    }

    if (!checkValue("assets", assets)) {
        return -1;
    }

    int32_t assetCount = stol(assets);
    if (assetCount < 2) {
        otOut << "Error: invalid asset count for basket.\n";
        return -1;
    }

    if (!checkValue("minimum", minimum)) {
        return -1;
    }

    int64_t minTransfer = stoll(minimum);
    if (minTransfer < 1) {
        otOut << "Error: invalid minimum transfer amount for basket.\n";
        return -1;
    }

    string basket = OTAPI_Wrap::GenerateBasketCreation(mynym, minTransfer);
    if ("" == basket) {
        otOut << "Error: cannot create basket.\n";
        return -1;
    }

    for (int32_t i = 0; i < assetCount; i++) {
        CmdShowAssets showAssets;
        showAssets.run();

        otOut << "\nThis basket currency has " << assetCount
              << " subcurrencies.\n";
        otOut << "So far you have defined " << i << " of them.\n";
        otOut << "Please PASTE the instrument definition ID for a subcurrency "
                 "of this "
                 "basket: ";

        string assetType = inputLine();
        if ("" == assetType) {
            otOut << "Error: empty instrument definition.\n";
            return -1;
        }

        string assetContract = OTAPI_Wrap::GetAssetType_Contract(assetType);
        if ("" == assetContract) {
            otOut << "Error: invalid instrument definition.\n";
            i--;
            continue;
        }

        otOut << "Enter minimum transfer amount for that instrument definition "
                 "[100]: ";
        minTransfer = 100;
        string minAmount = inputLine();
        if ("" != minAmount) {
            minTransfer = OTAPI_Wrap::StringToAmount(assetType, minAmount);
            if (1 > minTransfer) {
                otOut << "Error: invalid minimum transfer amount.\n";
                i--;
                continue;
            }
        }

        basket = OTAPI_Wrap::AddBasketCreationItem(mynym, basket, assetType,
                                                   minTransfer);
        if ("" == basket) {
            otOut << "Error: cannot create basket item.\n";
            return -1;
        }
    }

    otOut << "Here's the basket we're issuing:\n\n" << basket << "\n";

    string response = MadeEasy::issue_basket_currency(server, mynym, basket);
    int32_t status = responseStatus(response);
    switch (status) {
    case 1: {
        otOut << "\n\n SUCCESS in issue_basket_currency! Server response:\n\n";
        cout << response << "\n";

        string strNewID =
            OTAPI_Wrap::Message_GetNewInstrumentDefinitionID(response);
        bool bGotNewID = "" != strNewID;
        bool bRetrieved = false;
        string strEnding = ".";

        if (bGotNewID) {
            response = MadeEasy::retrieve_contract(server, mynym, strNewID);
            strEnding = ": " + strNewID;

            if (1 == responseStatus(response)) {
                bRetrieved = true;
            }
        }
        otOut << "Server response: SUCCESS in issue_basket_currency!\n";
        otOut << (bRetrieved ? "Success" : "Failed")
              << " retrieving new basket contract" << strEnding << "\n";
        break;
    }
    case 0:
        otOut << "\n\n FAILURE in issue_basket_currency! Server response:\n\n";
        cout << response << "\n";
        otOut << " FAILURE in issue_basket_currency!\n";
        break;
    default:
        otOut << "\n\nError in issue_basket_currency! status is: " << status
              << "\n";

        if ("" != response) {
            otOut << "Server response:\n\n";
            cout << response << "\n";
            otOut << "\nError in issue_basket_currency! status is: " << status
                  << "\n";
        }
        break;
    }
    otOut << "\n";

    return (0 == status) ? -1 : status;
}

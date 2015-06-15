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

#ifndef OPENTXS_CORE_OTSERVERCONTRACT_HPP
#define OPENTXS_CORE_OTSERVERCONTRACT_HPP

#include "Contract.hpp"
#include <czmq.h>

namespace opentxs
{

class String;
class Tag;

class OTServerContract : public Contract
{
public:
    EXPORT OTServerContract();
    EXPORT OTServerContract(String& name, String& foldername, String& filename,
                            String& strID);
    EXPORT virtual ~OTServerContract();

    EXPORT bool GetConnectInfo(String& strHostname, int32_t& nPort) const;
    EXPORT unsigned char* GetTransportKey() const;
    EXPORT size_t GetTransportKeyLength() const;
    static zcert_t* LoadOrCreateTransportKey(const String& nymID);
    EXPORT virtual void CreateContents(); // Only used when first generating an
                                          // asset or server contract. Meant for
                                          // contracts which never change after
                                          // that point.  Otherwise does the
                                          // same thing as UpdateContents. (But
                                          // meant for a different purpose.)
    virtual bool SaveContractWallet(Tag& parent) const;
    virtual bool DisplayStatistics(String& strContents) const;

protected:
    // return -1 if error, 0 if nothing, and 1 if the node was processed.
    virtual int32_t ProcessXMLNode(irr::io::IrrXMLReader*& xml);

protected:
    String m_strHostname;
    int32_t m_nPort;
    String m_strURL;
    unsigned char* m_transportKey;
    size_t m_transportKeyLength;
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTSERVERCONTRACT_HPP

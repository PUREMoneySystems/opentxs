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

#ifndef OPENTXS_CORE_SCRIPT_OTCLAUSE_HPP
#define OPENTXS_CORE_SCRIPT_OTCLAUSE_HPP

#include <opentxs/core/String.hpp>

#include <string>

namespace opentxs
{

class OTBylaw;
class Tag;

class OTClause
{
    String m_strName;  // Name of this Clause.
    String m_strCode;  // script code.
    OTBylaw* m_pBylaw; // the Bylaw that this clause belongs to.

public:
    void SetBylaw(OTBylaw& theBylaw)
    {
        m_pBylaw = &theBylaw;
    }

    EXPORT const String& GetName() const
    {
        return m_strName;
    }

    OTBylaw* GetBylaw() const
    {
        return m_pBylaw;
    }

    EXPORT const char* GetCode() const;

    EXPORT void SetCode(const std::string& str_code);
    
    bool Compare(const OTClause& rhs) const;

    OTClause();
    OTClause(const char* szName, const char* szCode);
    virtual ~OTClause();

    void Serialize(Tag& parent) const;
};

} // namespace opentxs

#endif // OPENTXS_CORE_SCRIPT_OTCLAUSE_HPP

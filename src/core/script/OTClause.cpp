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

#include <opentxs/core/script/OTClause.hpp>

#include <opentxs/core/crypto/OTASCIIArmor.hpp>
#include <opentxs/core/util/Tag.hpp>
#include <opentxs/core/Log.hpp>

// ------------- OPERATIONS -------------
// Below this point, have all the actions that a party might do.
//
// (The party will internally call the appropriate agent according to its own
// rules.
// the script should not care how the party chooses its agents. At the most, the
// script
// only cares that the party has an active agent, but does not actually speak
// directly
// to said agent.)

namespace opentxs
{

OTClause::OTClause()
    : m_pBylaw(nullptr)
{
}

OTClause::OTClause(const char* szName, const char* szCode)
    : m_pBylaw(nullptr)
{
    if (nullptr != szName) m_strName.Set(szName);

    if (nullptr != szCode) m_strCode = szCode;

    // Todo security:  validation on the above fields.
}

OTClause::~OTClause()
{
    // nothing to delete.

    m_pBylaw =
        nullptr; // I wasn't the owner, it was a pointer for convenience only.
}

void OTClause::SetCode(const std::string & str_code)
{
    m_strCode.Set(str_code.c_str());
}

const char* OTClause::GetCode() const
{
    if (m_strCode.Exists()) return m_strCode.Get();

    return "print(\"(Empty script.)\")"; // todo hardcoding
}

void OTClause::Serialize(Tag& parent) const
{
    OTASCIIArmor ascCode;

    if (m_strCode.GetLength() > 2)
        ascCode.SetString(m_strCode);
    else
        otErr << "Empty script code in OTClause::Serialize()\n";

    TagPtr pTag(new Tag("clause", ascCode.Get()));

    pTag->add_attribute("name", m_strName.Get());

    parent.add_tag(pTag);
}

// Done
bool OTClause::Compare(const OTClause& rhs) const
{
    if (!(GetName().Compare(rhs.GetName()))) {
        otOut << "OTClause::Compare: Names don't match: " << GetName() << " / "
              << rhs.GetName() << " \n";
        return false;
    }

    if (!(m_strCode.Compare(rhs.GetCode()))) {
        otOut << "OTClause::Compare: Source code for interpreted script fails "
                 "to match, on clause: " << GetName() << " \n";
        return false;
    }

    return true;
}

} // namespace opentxs

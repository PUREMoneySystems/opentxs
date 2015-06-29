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
#include <opentxs/core/Nym.hpp>
#include <opentxs/core/OTServerContract.hpp>
#include <opentxs/core/crypto/OTASCIIArmor.hpp>
#include <opentxs/core/crypto/OTCrypto.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/util/OTFolders.hpp>
#include <opentxs/core/OTStorage.hpp>
#include <opentxs/core/util/Tag.hpp>

#include <fstream>
#include <cstring>
#include <irrxml/irrXML.hpp>

// zcert_public_key returns a 32 bit public key.
const int32_t TRANSPORT_KEY_SIZE = 32;

namespace opentxs
{

OTServerContract::OTServerContract()
    : Contract()
{
    m_nPort = 0;
}

OTServerContract::OTServerContract(String& name, String& foldername,
                                   String& filename, String& strID) :
    Contract(name, foldername, filename, strID),
    m_transportKey(nullptr),
    m_transportKeyLength(0)
{
    m_nPort = 0;
}

OTServerContract::~OTServerContract()
{
    if (nullptr != m_transportKey) {
        uint8_t * pKey = m_transportKey;
        delete [] pKey;
        m_transportKey = nullptr;
        m_transportKeyLength = 0;
    }
}

bool OTServerContract::GetConnectInfo(String& strHostname, int32_t& nPort) const
{
    if (m_strHostname.GetLength()) {
        strHostname = m_strHostname;
        nPort = m_nPort;
        return true;
    }
    return false;
}

unsigned char* OTServerContract::GetTransportKey() const
{
    return m_transportKey;
}

size_t OTServerContract::GetTransportKeyLength() const
{
    return m_transportKeyLength;
}
    
bool OTServerContract::DisplayStatistics(String& strContents) const
{
    const String strID(m_ID);

    strContents.Concatenate(" Notary Provider: %s\n"
                            " NotaryID: %s\n"
                            "\n",
                            m_strName.Get(), strID.Get());

    return true;
}

bool OTServerContract::SaveContractWallet(Tag& parent) const
{
    const String strID(m_ID);

    // Name is in the clear in memory,
    // and base64 in storage.
    OTASCIIArmor ascName;
    if (m_strName.Exists()) {
        ascName.SetString(m_strName, false); // linebreaks == false
    }

    TagPtr pTag(new Tag("notaryProvider"));

    pTag->add_attribute("name", m_strName.Exists() ? ascName.Get() : "");
    pTag->add_attribute("notaryID", strID.Get());

    parent.add_tag(pTag);

    return true;
}

zcert_t* OTServerContract::LoadOrCreateTransportKey(const String& nymID)
{
    std::string filepath;
    OTDB::FormPathString(filepath, OTFolders::Credential().Get(), nymID.Get(),
                         "transportKey");

    if (!zcert_load(filepath.c_str())) {
        // File does not exist: create keypair and store.
        // This creates two files: `filepath` and `filepath`_secret.
        zcert_save(zcert_new(), filepath.c_str());
    }

    return zcert_load(filepath.c_str());
}

void OTServerContract::CreateContents()
{
    m_xmlUnsigned.Release();

    Tag tag("notaryProviderContract");

    tag.add_attribute("version", m_strVersion.Get());

    // Entity
    {
        TagPtr pTag(new Tag("entity"));
        pTag->add_attribute("shortname", m_strEntityShortName.Get());
        pTag->add_attribute("longname", m_strEntityLongName.Get());
        pTag->add_attribute("email", m_strEntityEmail.Get());
        pTag->add_attribute("serverURL", m_strURL.Get());
        tag.add_tag(pTag);
    }
    // notaryServer
    {
        TagPtr pTag(new Tag("notaryServer"));
        pTag->add_attribute("hostname", m_strHostname.Get());
        pTag->add_attribute("port", formatInt(m_nPort));
        pTag->add_attribute("URL", m_strURL.Get());
        tag.add_tag(pTag);
    }

    // Write the transportKey
    const Nym* nym = m_mapNyms["signer"];
    const unsigned char* transportKey = zcert_public_key(
        OTServerContract::LoadOrCreateTransportKey(String(nym->GetConstID())));
    // base64-encode the binary public key because the encoded key
    // (zcert_public_txt()) does Z85 encoding, which contains the '<','>' chars.
    // See http://rfc.zeromq.org/spec:32.

    tag.add_tag("transportKey", OTCrypto::It()->Base64Encode(
                                    transportKey, TRANSPORT_KEY_SIZE, false));

    // This is where OTContract scribes tag with its keys,
    // conditions, etc.
    CreateInnerContents(tag);

    std::string str_result;
    tag.output(str_result);

    m_xmlUnsigned.Format("%s", str_result.c_str());
}

// This is the serialization code for READING FROM THE CONTRACT
// return -1 if error, 0 if nothing, and 1 if the node was processed.
int32_t OTServerContract::ProcessXMLNode(irr::io::IrrXMLReader*& xml)
{
    // Here we call the parent class first.
    // If the node is found there, or there is some error,
    // then we just return either way.  But if it comes back
    // as '0', then nothing happened, and we'll continue executing.
    //
    // -- Note you can choose not to call the parent if
    // you don't want to use any of those xml tags.

    auto result = Contract::ProcessXMLNode(xml);
    if (result) return result;

    if (!strcmp("notaryProviderContract", xml->getNodeName())) {
        m_strVersion = xml->getAttributeValue("version");

        otWarn << "\n"
                  "===> Loading XML portion of server contract into memory "
                  "structures...\n\n"
                  "Notary Server Name: " << m_strName
               << "\nContract version: " << m_strVersion << "\n----------\n";
        return 1;
    }
    if (!strcmp("notaryServer", xml->getNodeName())) {
        m_strHostname = xml->getAttributeValue("hostname");
        m_nPort = atoi(xml->getAttributeValue("port"));
        m_strURL = xml->getAttributeValue("URL");

        otWarn << "\n"
                  "Notary Server connection info:\n --- Hostname: "
               << m_strHostname << "\n --- Port: " << m_nPort
               << "\n --- URL:" << m_strURL << "\n\n";
        return 1;
    }
    if (!strcmp("transportKey", xml->getNodeName())) {
        if (!SkipToTextField(xml)) {
            return -1;
        }
        const char* transportKeyB64 = xml->getNodeData();
        if (!transportKeyB64) return -1;
        std::string transportKeyB64Trimmed(transportKeyB64);
        String::trim(transportKeyB64Trimmed);
        size_t outLen;
        m_transportKey = OTCrypto::It()->Base64Decode(
            transportKeyB64Trimmed.c_str(), &outLen, false);
        
        if (outLen != TRANSPORT_KEY_SIZE) {
            if (m_transportKey) {
                delete m_transportKey;
            }
            m_transportKey = nullptr;
            m_transportKeyLength = 0;
            return -1;
        }
        m_transportKeyLength = outLen;
        
        return 1;
    }

    return 0;
}

} // namespace opentxs

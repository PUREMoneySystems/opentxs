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

#include <opentxs/core/crypto/OTSignedFile.hpp>

#include <opentxs/core/crypto/OTASCIIArmor.hpp>
#include <opentxs/core/util/Tag.hpp>
#include <opentxs/core/Log.hpp>
#include <opentxs/core/OTStorage.hpp>

#include <cstring>
#include <irrxml/irrXML.hpp>

namespace opentxs
{

String& OTSignedFile::GetFilePayload()
{
    return m_strSignedFilePayload;
}

void OTSignedFile::SetFilePayload(const String& strArg)
{
    m_strSignedFilePayload = strArg;
}

String& OTSignedFile::GetSignerNymID()
{
    return m_strSignerNymID;
}

void OTSignedFile::SetSignerNymID(const String& strArg)
{
    m_strSignerNymID = strArg;
}

void OTSignedFile::UpdateContents()
{
    // I release this because I'm about to repopulate it.
    m_xmlUnsigned.Release();

    Tag tag("signedFile");

    tag.add_attribute("version", m_strVersion.Get());
    tag.add_attribute("localDir", m_strLocalDir.Get());
    tag.add_attribute("filename", m_strSignedFilename.Get());

    if (m_strSignerNymID.Exists()) {
        tag.add_attribute("signer", m_strSignerNymID.Get());
    }

    if (m_strSignedFilePayload.Exists()) {
        OTASCIIArmor ascPayload(m_strSignedFilePayload);
        tag.add_tag("filePayload", ascPayload.Get());
    }

    std::string str_result;
    tag.output(str_result);

    m_xmlUnsigned.Concatenate("%s", str_result.c_str());
}

int32_t OTSignedFile::ProcessXMLNode(irr::io::IrrXMLReader*& xml)
{
    int32_t nReturnVal = 0;

    // Here we call the parent class first.
    // If the node is found there, or there is some error,
    // then we just return either way.  But if it comes back
    // as '0', then nothing happened, and we'll continue executing.
    //
    // -- Note you can choose not to call the parent if
    // you don't want to use any of those xml tags.
    // As I do below, in the case of OTAccount.
    // if (nReturnVal = ot_super::ProcessXMLNode(xml))
    //    return nReturnVal;

    if (!strcmp("signedFile", xml->getNodeName())) {
        m_strVersion = xml->getAttributeValue("version");

        m_strPurportedLocalDir = xml->getAttributeValue("localDir");
        m_strPurportedFilename = xml->getAttributeValue("filename");
        m_strSignerNymID = xml->getAttributeValue("signer");

        nReturnVal = 1;
    }
    else if (!strcmp("filePayload", xml->getNodeName())) {
        if (false ==
            Contract::LoadEncodedTextField(xml, m_strSignedFilePayload)) {
            otErr << "Error in OTSignedFile::ProcessXMLNode: filePayload field "
                     "without value.\n";
            return (-1); // error condition
        }

        return 1;
    }

    return nReturnVal;
}

// We just loaded a certain subdirectory/filename
// This file also contains that information within it.
// This function allows me to compare the two and make sure
// the file that I loaded is what it claims to be.
//
// Make sure you also VerifySignature() whenever doing something
// like this  :-)
//
// Assumes SetFilename() has been set, and that LoadFile() has just been called.
bool OTSignedFile::VerifyFile()
{
    if (m_strLocalDir.Compare(m_strPurportedLocalDir) &&
        m_strSignedFilename.Compare(m_strPurportedFilename))
        return true;

    otErr << __FUNCTION__ << ": Failed verifying signed file:\n"
                             "Expected directory: " << m_strLocalDir
          << "  Found: " << m_strPurportedLocalDir
          << "\n"
             "Expected filename:  " << m_strSignedFilename
          << "  Found: " << m_strPurportedFilename << "\n";
    return false;
}

OTSignedFile::OTSignedFile(const String& LOCAL_SUBDIR, const String& FILE_NAME)
    : Contract()
{
    m_strContractType.Set("FILE");

    SetFilename(LOCAL_SUBDIR, FILE_NAME);
}

OTSignedFile::OTSignedFile(const char* LOCAL_SUBDIR, const String& FILE_NAME)
    : Contract()
{
    m_strContractType.Set("FILE");

    String strLocalSubdir(LOCAL_SUBDIR);

    SetFilename(strLocalSubdir, FILE_NAME);
}

OTSignedFile::OTSignedFile(const char* LOCAL_SUBDIR, const char* FILE_NAME)
    : Contract()
{
    m_strContractType.Set("FILE");

    String strLocalSubdir(LOCAL_SUBDIR), strFile_Name(FILE_NAME);

    SetFilename(strLocalSubdir, strFile_Name);
}

// This is entirely separate from the OTContract saving methods.  This is
// specifically
// for saving the internal file payload based on the internal file information,
// which
// this method assumes has already been set (using SetFilename())
bool OTSignedFile::SaveFile()
{
    const String strTheFileName(m_strFilename);
    const String strTheFolderName(m_strFoldername);

    // OTContract doesn't natively make it easy to save a contract to its own
    // filename.
    // Funny, I know, but OTContract is designed to save either to a specific
    // filename,
    // or to a string parameter, or to the internal rawfile member. It doesn't
    // normally
    // save to its own filename that was used to load it. But OTSignedFile is
    // different...

    // This saves to a file, the name passed in as a char *.
    return SaveContract(strTheFolderName.Get(), strTheFileName.Get());
}

// Assumes SetFilename() has already been set.
bool OTSignedFile::LoadFile()
{
    //    otOut << "DEBUG LoadFile (Signed) folder: %s file: %s \n",
    // m_strFoldername.Get(), m_strFilename.Get());

    if (OTDB::Exists(m_strFoldername.Get(), m_strFilename.Get()))
        return LoadContract();

    return false;
}

void OTSignedFile::SetFilename(const String& LOCAL_SUBDIR,
                               const String& FILE_NAME)
{
    // OTSignedFile specific variables.
    m_strLocalDir = LOCAL_SUBDIR;
    m_strSignedFilename = FILE_NAME;

    // OTContract variables.
    m_strFoldername = m_strLocalDir;
    m_strFilename = m_strSignedFilename;

    /*
    m_strFilename.Format("%s%s" // data_folder/
                         "%s%s" // nyms/
                         "%s",  // 5bf9a88c.nym
                         OTLog::Path(), OTLog::PathSeparator(),
                         m_strLocalDir.Get(), OTLog::PathSeparator(),
                         m_strSignedFilename.Get());
    */
    // Software Path + Local Sub-directory + Filename
    //
    // Finished Product:    "transaction/nyms/5bf9a88c.nym"
}

OTSignedFile::OTSignedFile()
    : Contract()
{
    m_strContractType.Set("FILE");
}

OTSignedFile::~OTSignedFile()
{
    Release_SignedFile();
}

void OTSignedFile::Release_SignedFile()
{
    m_strSignedFilePayload.Release(); // This is the file contents we were
                                      // wrapping.
                                      // We can release this now.

//  m_strLocalDir.Release();          // We KEEP these, *not* release, because LoadContract()
//  m_strSignedFilename.Release();    // calls Release(), and these are our core values. We
                                      // don't want to lose them when the file is loaded.

    // Note: Additionally, neither does OTContract release m_strFilename here,
    // for the SAME reason.

    m_strPurportedLocalDir.Release();
    m_strPurportedFilename.Release();
}

void OTSignedFile::Release()
{
    Release_SignedFile();

    Contract::Release();

    m_strContractType.Set("FILE");
}

} // namespace opentxs

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

#ifndef OPENTXS_CORE_OTSTRING_HPP
#define OPENTXS_CORE_OTSTRING_HPP

#ifdef _WIN32
#include "util/win32_utf8conv.hpp" // support for changing between std::string and std::wstring
#endif

#include <stddef.h>
#include <cstdint>
#include <string>
#include <iosfwd>
#include <list>
#include <map>
#include <cstdarg>

#define MAX_STRING_LENGTH 0x800000 // this is about 8 megs.

#ifdef __GNUC__
#define ATTR_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define ATTR_PRINTF(a, b)
#endif

#ifdef _MSC_VER
#define PRI_SIZE "Iu"
#else
#define PRI_SIZE "zu"
#endif

namespace opentxs
{

class OTASCIIArmor;
class Contract;
class Identifier;
class Nym;
class OTSignature;

class String
{
public:
    typedef std::list<std::string> List;
    typedef std::map<std::string, std::string> Map;

public:
    EXPORT friend std::ostream& operator<<(std::ostream& os, const String& obj);

    EXPORT String();
    EXPORT String(const String& value);
    EXPORT String(const OTASCIIArmor& value);
    String(const OTSignature& value);
    EXPORT String(const Contract& value);
    EXPORT String(const Identifier& value);
    String(Nym& value);
    EXPORT String(const char* value);
    String(const char* value, size_t size);
    EXPORT String(const std::string& value);
    EXPORT virtual ~String();

    EXPORT virtual void Release();

    void Initialize();

    EXPORT String& operator=(String rhs);

    static bool vformat(const char* fmt, std::va_list* pvl, std::string& s)
        ATTR_PRINTF(1, 0);

    void swap(String& rhs);
    bool operator>(const String& rhs) const;
    bool operator<(const String& rhs) const;
    bool operator<=(const String& rhs) const;
    bool operator>=(const String& rhs) const;
    EXPORT bool operator==(const String& rhs) const;

    EXPORT static std::string& trim(std::string& str);
    EXPORT static std::string replace_chars(const std::string& str,
                                            const std::string& charsFrom,
                                            const char& charTo);
#ifdef _WIN32
    EXPORT static std::wstring s2ws(const std::string& s);
    EXPORT static std::string ws2s(const std::wstring& s);
#endif

public:
    static size_t safe_strlen(const char* s, size_t max);

    EXPORT static std::string LongToString(const int64_t& lNumber);
    EXPORT static std::string UlongToString(const uint64_t& uNumber);

    EXPORT static int64_t  StringToLong(const std::string& number);
    EXPORT static uint64_t StringToUlong(const std::string& number);

    EXPORT int64_t  ToLong() const;
    EXPORT uint64_t ToUlong() const;

    EXPORT static int32_t  StringToInt(const std::string& number);
    EXPORT static uint32_t StringToUint(const std::string& number);

    EXPORT int32_t  ToInt() const;
    EXPORT uint32_t ToUint() const;

    EXPORT bool At(uint32_t index, char& c) const;
    EXPORT bool Exists() const;
    EXPORT bool empty() const;
    EXPORT bool DecodeIfArmored(bool escapedIsAllowed = true);
    EXPORT uint32_t GetLength() const;
    EXPORT bool Compare(const char* compare) const;
    EXPORT bool Compare(const String& compare) const;

    EXPORT bool Contains(const char* compare) const;
    bool Contains(const String& compare) const;

    EXPORT const char* Get() const;
    // new_string MUST be at least nEnforcedMaxLength in size if
    // nEnforcedMaxLength is passed in at all.
    //
    // That's because this function forces the null terminator at
    // that length, minus 1. For example, if the max is set to 10, then
    // the valid range is 0..9. Therefore 9 (10 minus 1) is where the
    // nullptr terminator goes.
    //
    EXPORT void Set(const char* data, uint32_t enforcedMaxLength = 0);
    EXPORT void Set(const String& data);
    // For a straight-across, exact-size copy of bytes.
    // Source not expected to be null-terminated.
    EXPORT bool MemSet(const char* mem, uint32_t size);
    EXPORT void Concatenate(const char* arg, ...) ATTR_PRINTF(2, 3);
    void Concatenate(const String& data);
    void Truncate(uint32_t index);
    EXPORT void Format(const char* fmt, ...) ATTR_PRINTF(2, 3);
    void ConvertToUpperCase() const;
    EXPORT bool TokenizeIntoKeyValuePairs(Map& map) const;
    EXPORT void OTfgets(std::istream& ofs);
    // true  == there are more lines to read.
    // false == this is the last line. Like EOF.
    bool sgets(char* buffer, uint32_t size);

    char sgetc();
    void sungetc();
    void reset();

    void WriteToFile(std::ostream& ofs) const;
    void Release_String();
    EXPORT void zeroMemory() const;

private:
    // You better have called Initialize() or Release() before you dare call
    // this.
    void LowLevelSetStr(const String& buffer);

    // Only call this right after calling Initialize() or Release().
    // Also, this function ASSUMES the new_string pointer is good.
    void LowLevelSet(const char* data, uint32_t enforcedMaxLength);

protected:
    uint32_t length_;
    uint32_t position_;
    char* data_;
};

// bool operator >(const OTString& s1, const OTString& s2);
// bool operator <(const OTString& s1, const OTString& s2);
// bool operator >=(const OTString& s1, const OTString& s2);
// bool operator <=(const OTString& s1, const OTString& s2);

} // namespace opentxs

#endif // OPENTXS_CORE_OTSTRING_HPP

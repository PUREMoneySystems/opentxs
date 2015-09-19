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

#ifndef OPENTXS_CORE_OTDATA_HPP
#define OPENTXS_CORE_OTDATA_HPP

#include <cstdint>

namespace opentxs
{

class OTASCIIArmor;

class OTData
{
public:
    EXPORT OTData();
    EXPORT OTData(const void* data, uint32_t size);
    EXPORT OTData(const OTData& source);
    EXPORT OTData(const OTASCIIArmor& source);
    EXPORT virtual ~OTData();

    EXPORT void Release();

    void SetSize(uint32_t size);

    inline const void* GetPointer() const
    {
        return data_;
    }

    EXPORT OTData& operator=(OTData rhs);
    EXPORT void swap(OTData& rhs);
    EXPORT bool operator==(const OTData& rhs) const;
    EXPORT bool operator!=(const OTData& rhs) const;
    EXPORT OTData& operator+=(const OTData& rhs);
    EXPORT bool IsEmpty() const;
    EXPORT bool empty() const;

    inline uint32_t GetSize() const
    {
        return size_;
    }

    EXPORT void Assign(const OTData& source);
    EXPORT void Assign(const void* data, uint32_t size);
    EXPORT void Concatenate(const void* data, uint32_t size);
    EXPORT bool Randomize(uint32_t size);
    EXPORT void zeroMemory() const;
    EXPORT uint32_t OTfread(uint8_t* data, uint32_t size);

    inline void reset()
    {
        position_ = 0;
    }

protected:
    inline void Initialize()
    {
        data_ = nullptr;
        size_ = 0;
        position_ = 0;
    }

private:
    void* data_=nullptr;
    uint32_t position_=0;
    uint32_t size_=0; // TODO: MAX_SIZE ?? security.
};

} // namespace opentxs

#endif // OPENTXS_CORE_OTDATA_HPP

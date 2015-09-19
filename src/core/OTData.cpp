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

#include <opentxs/core/OTData.hpp>
#include <opentxs/core/crypto/OTASCIIArmor.hpp>
#include <opentxs/core/crypto/OTPassword.hpp>
#include <opentxs/core/util/Assert.hpp>
#include <utility>
#include <cstring>
#include <cstdint>

namespace opentxs
{

OTData::OTData() { }

OTData::OTData(const OTData& source)
{
    Assign(source);
}

OTData::OTData(const OTASCIIArmor& source)
{
    if (source.Exists()) {
        source.GetData(*this);
    }
}

OTData::OTData(const void* data, uint32_t size)
{
    Assign(data, size);
}

OTData::~OTData()
{
    Release();
}

bool OTData::operator==(const OTData& rhs) const
{
    if (size_ != rhs.size_) {
        return false;
    }

    if (size_ == 0 && rhs.size_ == 0) {
        return true;
    }
    // TODO security: replace memcmp with a more secure
    // version. Still, though, I am managing it internal to
    // the class.
    if (std::memcmp(data_, rhs.data_, size_) == 0) {
        return true;
    }

    return false;
}

bool OTData::operator!=(const OTData& rhs) const
{
    return !operator==(rhs);
}

// First use reset() to set the internal position to 0.
// Then you pass in the buffer where the results go.
// You pass in the length of that buffer.
// It returns how much was actually read.
// If you start at position 0, and read 100 bytes, then
// you are now on position 100, and the next OTfread will
// proceed from that position. (Unless you reset().)
uint32_t OTData::OTfread(uint8_t* data, uint32_t size)
{
    OT_ASSERT(data != nullptr && size > 0);

    uint32_t sizeToRead = 0;

    if (data_ != nullptr && position_ < GetSize()) {
        // If the size is 20, and position is 5 (I've already read the first 5
        // bytes) then the size remaining to read is 15. That is, GetSize()
        // minus position_.
        sizeToRead = GetSize() - position_;

        if (size < sizeToRead) {
            sizeToRead = size;
        }
        OTPassword::safe_memcpy(
            data, size, static_cast<uint8_t*>(data_) + position_, sizeToRead);
        position_ += sizeToRead;
    }

    return sizeToRead;
}

void OTData::zeroMemory() const
{
    if (data_ != nullptr) {
        OTPassword::zeroMemory(data_, size_);
    }
}

void OTData::Release()
{
    if (data_ != nullptr) {
        // For security reasons, we clear the memory to 0 when deleting the
        // object. (Seems smart.)
        OTPassword::zeroMemory(data_, size_);
        delete[] static_cast<uint8_t*>(data_);
        // If data_ was already nullptr, no need to re-Initialize().
        Initialize();
    }
}

OTData& OTData::operator=(OTData rhs)
{
    swap(rhs);
    return *this;
}

void OTData::swap(OTData& rhs)
{
    std::swap(data_, rhs.data_);
    std::swap(position_, rhs.position_);
    std::swap(size_, rhs.size_);
}

void OTData::Assign(const OTData& source)
{
    // can't assign to self.
    if (&source == this) {
        return;
    }

    if (!source.IsEmpty()) {
        Assign(source.data_, source.size_);
    }
    else {
        // Otherwise if it's empty, then empty this also.
        Release();
    }
}

bool OTData::empty() const
{
    return size_ < 1;
}

bool OTData::IsEmpty() const // Deprecated.
{
    return empty();
}

void OTData::Assign(const void* data, uint32_t size)
{
    // This releases all memory and zeros out all members.
    Release();

    if (data != nullptr && size > 0) {
        data_ = static_cast<void*>(new uint8_t[size]);
        OT_ASSERT(data_ != nullptr);
        OTPassword::safe_memcpy(data_, size, data, size);
        size_ = size;
    }
    // TODO: else error condition.  Could just ASSERT() this.
}

bool OTData::Randomize(uint32_t size)
{
    Release(); // This releases all memory and zeros out all members.
    if (size > 0) {
        data_ = static_cast<void*>(new uint8_t[size]);
        OT_ASSERT(data_ != nullptr);

        if (!OTPassword::randomizeMemory_uint8(static_cast<uint8_t*>(data_),
                                               size)) {
            // randomizeMemory already logs, so I'm not logging again twice
            // here.
            delete[] static_cast<uint8_t*>(data_);
            data_ = nullptr;
            return false;
        }

        size_ = size;
        return true;
    }
    // else error condition.  Could just ASSERT() this.
    return false;
}

void OTData::Concatenate(const void* data, uint32_t size)
{
    OT_ASSERT(data != nullptr);
    OT_ASSERT(size > 0);

    if (size == 0) {
        return;
    }

    if (size_ == 0) {
        Assign(data, size);
        return;
    }

    void* newData = nullptr;
    uint32_t newSize = GetSize() + size;

    if (newSize > 0) {
        newData = static_cast<void*>(new uint8_t[newSize]);
        OT_ASSERT(newData != nullptr);
        OTPassword::zeroMemory(newData, newSize);
    }
    // If there's a new memory buffer (for the combined..)
    if (newData != nullptr) {
        // if THIS object has data inside of it...
        if (!IsEmpty()) {
            // Copy THIS object into the new
            // buffer, starting at the
            // beginning.
            OTPassword::safe_memcpy(newData, newSize, data_, GetSize());
        }

        // Next we copy the data being appended...
        OTPassword::safe_memcpy(static_cast<uint8_t*>(newData) + GetSize(),
                                newSize - GetSize(), data, size);
    }

    if (data_ != nullptr) {
        delete[] static_cast<uint8_t*>(data_);
    }

    data_ = newData;
    size_ = newSize;
}

OTData& OTData::operator+=(const OTData& rhs)
{
    if (rhs.GetSize() > 0) {
        Concatenate(rhs.data_, rhs.GetSize());
    }
    return *this;
}

void OTData::SetSize(uint32_t size)
{
    Release();

    if (size > 0) {
        data_ = static_cast<void*>(new uint8_t[size]);
        OT_ASSERT(data_ != nullptr);
        OTPassword::zeroMemory(data_, size);
        size_ = size;
    }
}

} // namespace opentxs

/*
 * Copyright (C) 2008-2016 TrinityCore <http://www.trinitycore.org/>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <OpenSSLCrypto.h>
#include <openssl/crypto.h>
#include <vector>
#include <thread>
#include <mutex>

std::vector<std::mutex*> cryptoLocks;

static void lockingCallback(int mode, int type, const char* /*file*/, int /*line*/)
{
    if (mode & CRYPTO_LOCK)
        cryptoLocks[type]->lock();
    else
        cryptoLocks[type]->unlock();
}

static void threadIdCallback(CRYPTO_THREADID * id)
{
    CRYPTO_THREADID_set_numeric(id, std::hash<std::thread::id>()(std::this_thread::get_id()));
}

void OpenSSLCrypto::threadsSetup(boost::filesystem::path const& providerModulePath)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#if TRINITY_PLATFORM == TRINITY_PLATFORM_WINDOWS
    OSSL_PROVIDER_set_default_search_path(nullptr, providerModulePath.string().c_str());
#endif
    LegacyProvider = OSSL_PROVIDER_load(nullptr, "legacy");
    DefaultProvider = OSSL_PROVIDER_load(nullptr, "default");
#endif
}

void OpenSSLCrypto::threadsCleanup()
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_unload(LegacyProvider);
    OSSL_PROVIDER_unload(DefaultProvider);
    OSSL_PROVIDER_set_default_search_path(nullptr, nullptr);
#endif
}

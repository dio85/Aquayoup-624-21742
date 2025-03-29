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

/**
* @file main.cpp
* @brief Authentication Server main program
*
* This file contains the main program for the
* authentication server
*/

#include "SessionManager.h"
#include "AppenderDB.h"
#include "ProcessPriority.h"
#include "RealmList.h"
#include "GitRevision.h"
#include "SslContext.h"
#include "DatabaseLoader.h"
#include "LoginRESTService.h"
#include <iostream>
#include <boost/program_options.hpp>
#include <boost/filesystem/path.hpp>
#include <google/protobuf/stubs/common.h>

using boost::asio::ip::tcp;
using namespace boost::program_options;
namespace fs = boost::filesystem;

#ifndef _TRINITY_BNET_CONFIG
# define _TRINITY_BNET_CONFIG  "bnetserver.conf"
#endif

#if PLATFORM == PLATFORM_WINDOWS
#include "ServiceWin32.h"
#include <boost/asio/signal_set.hpp>
char serviceName[] = "bnetserver";
char serviceLongName[] = "TrinityCore bnet service";
char serviceDescription[] = "TrinityCore Battle.net emulator authentication service";
/*
* -1 - not in service mode
*  0 - stopped
*  1 - running
*  2 - paused
*/
int m_ServiceStatus = -1;

static boost::asio::deadline_timer* _serviceStatusWatchTimer;
void ServiceStatusWatcher(std::weak_ptr<Trinity::Asio::DeadlineTimer> serviceStatusWatchTimerRef, std::weak_ptr<Trinity::Asio::IoContext> ioContextRef, boost::system::error_code const& error);
#endif

bool StartDB();
void StopDB();
void SignalHandler(std::weak_ptr<Trinity::Asio::IoContext> ioContextRef, boost::system::error_code const& error, int signalNumber);
void KeepDatabaseAliveHandler(std::weak_ptr<Trinity::Asio::DeadlineTimer> dbPingTimerRef, int32 dbPingInterval, boost::system::error_code const& error);
void BanExpiryHandler(std::weak_ptr<Trinity::Asio::DeadlineTimer> banExpiryCheckTimerRef, int32 banExpiryCheckInterval, boost::system::error_code const& error);
variables_map GetConsoleArguments(int argc, char** argv, fs::path& configFile, std::string& configService);


int main(int argc, char** argv)
{
    signal(SIGABRT, &Trinity::AbortHandler);

    auto configFile = fs::absolute(_TRINITY_BNET_CONFIG);
    std::string configService;
    auto vm = GetConsoleArguments(argc, argv, configFile, configService);
    // exit if help or version is enabled
    if (vm.count("help") || vm.count("version"))
        return 0;

    GOOGLE_PROTOBUF_VERIFY_VERSION;

#if PLATFORM == PLATFORM_WINDOWS
    if (configService.compare("install") == 0)
        return WinServiceInstall() ? 0 : 1;
    else if (configService.compare("uninstall") == 0)
        return WinServiceUninstall() ? 0 : 1;
    else if (configService.compare("run") == 0)
        return WinServiceRun() ? 0 : 1;
#endif

    std::string configError;
    if (!sConfigMgr->LoadInitial(configFile.generic_string(),
                                 std::vector<std::string>(argv, argv + argc),
                                 configError))
    {
        printf("Error in config file: %s\n", configError.c_str());
        return 1;
    }

    sLog->RegisterAppender<AppenderDB>();
    sLog->Initialize(nullptr);

    TC_LOG_INFO("server.bnetserver", "%s (bnetserver)", GitRevision::GetFullVersion());
    TC_LOG_INFO("server.bnetserver", "<Ctrl-C> to stop.\n");
    TC_LOG_INFO("server.bnetserver", "Using configuration file %s.", sConfigMgr->GetFilename().c_str());
    TC_LOG_INFO("server.bnetserver", "Using SSL version: %s (library: %s)", OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION));
    TC_LOG_INFO("server.bnetserver", "Using Boost version: %i.%i.%i", BOOST_VERSION / 100000, BOOST_VERSION / 100 % 1000, BOOST_VERSION % 100);

    // Seed the OpenSSL's PRNG here.
    // That way it won't auto-seed when calling BigNumber::SetRand and slow down the first world login
    BigNumber seed;
    seed.SetRand(16 * 8);

    // bnetserver PID file creation
    std::string pidFile = sConfigMgr->GetStringDefault("PidFile", "");
    if (!pidFile.empty())
    {
        if (uint32 pid = CreatePIDFile(pidFile))
            TC_LOG_INFO("server.bnetserver", "Daemon PID: %u\n", pid);
        else
        {
            TC_LOG_ERROR("server.bnetserver", "Cannot create PID file %s.\n", pidFile.c_str());
            return 1;
        }
    }

    if (!Battlenet::SslContext::Initialize())
    {
        TC_LOG_ERROR("server.bnetserver", "Failed to initialize SSL context");
        return 1;
    }

    // Initialize the database connection
    if (!StartDB())
        return 1;
    std::shared_ptr<Trinity::Asio::IoContext> ioContext = std::make_shared<Trinity::Asio::IoContext>();
    // Start the listening port (acceptor) for auth connections
    int32 bnport = sConfigMgr->GetIntDefault("BattlenetPort", 1119);
    if (bnport < 0 || bnport > 0xFFFF)
    {
        TC_LOG_ERROR("server.bnetserver", "Specified battle.net port (%d) out of allowed range (1-65535)", bnport);
        StopDB();
        ioContext.reset();
        return 1;
    }

    if (!sLoginService.Start(ioContext.get()))
    {
        StopDB();
        TC_LOG_ERROR("server.bnetserver", "Failed to initialize login service");
        return 1;
    }

    // Get the list of realms for the server
    sRealmList->Initialize(*ioContext, sConfigMgr->GetIntDefault("RealmsStateUpdateDelay", 10));

    std::string bindIp = sConfigMgr->GetStringDefault("BindIP", "0.0.0.0");

    sSessionMgr.StartNetwork(*ioContext, bindIp, bnport);

    // Set signal handlers
    boost::asio::signal_set signals(*ioContext, SIGINT, SIGTERM);
#if PLATFORM == PLATFORM_WINDOWS
    signals.add(SIGBREAK);
#endif
    signals.async_wait(std::bind(&SignalHandler, std::weak_ptr<Trinity::Asio::IoContext>(ioContext), std::placeholders::_1, std::placeholders::_2));

    // Set process priority according to configuration settings
    SetProcessPriority("server.bnetserver");

    // Enabled a timed callback for handling the database keep alive ping
    int32 _dbPingInterval = sConfigMgr->GetIntDefault("MaxPingTime", 30);
    std::shared_ptr<Trinity::Asio::DeadlineTimer> _dbPingTimer = std::make_shared<Trinity::Asio::DeadlineTimer>(*ioContext);
    _dbPingTimer->expires_from_now(std::chrono::minutes(_dbPingInterval));
    _dbPingTimer->async_wait([timerRef = std::weak_ptr(_dbPingTimer), _dbPingInterval](boost::system::error_code const& error) mutable
    {
        KeepDatabaseAliveHandler(std::move(timerRef), _dbPingInterval, error);
    });

     int32 _banExpiryCheckInterval = sConfigMgr->GetIntDefault("BanExpiryCheckInterval", 60);
    std::shared_ptr<Trinity::Asio::DeadlineTimer> _banExpiryCheckTimer = std::make_shared<Trinity::Asio::DeadlineTimer>(*ioContext);
    _banExpiryCheckTimer->expires_after(std::chrono::seconds(_banExpiryCheckInterval));
    _banExpiryCheckTimer->async_wait([timerRef = std::weak_ptr(_banExpiryCheckTimer), _banExpiryCheckInterval](boost::system::error_code const& error) mutable
     {
        BanExpiryHandler(std::move(timerRef), _banExpiryCheckInterval, error);
     });

#if PLATFORM == PLATFORM_WINDOWS
    std::shared_ptr<Trinity::Asio::DeadlineTimer> serviceStatusWatchTimer;
    if (m_ServiceStatus != -1)
    {
        serviceStatusWatchTimer = std::make_shared<Trinity::Asio::DeadlineTimer>(*ioContext);
        serviceStatusWatchTimer->expires_after(std::chrono::seconds(1));
        serviceStatusWatchTimer->async_wait([timerRef = std::weak_ptr(serviceStatusWatchTimer), ioContextRef = std::weak_ptr(ioContext)](boost::system::error_code const& error) mutable
        {
            ServiceStatusWatcher(std::move(timerRef), std::move(ioContextRef), error);
        });
    }
#endif

    // Start the io service worker loop
    ioContext->run();

    _banExpiryCheckTimer->cancel();
    _dbPingTimer->cancel();

    sLoginService.Stop();

    sSessionMgr.StopNetwork();

    sRealmList->Close();

    // Close the Database Pool and library
    StopDB();

    TC_LOG_INFO("server.bnetserver", "Halting process...");

    signals.cancel();

    _banExpiryCheckTimer->cancel();
    _dbPingTimer->cancel();
    google::protobuf::ShutdownProtobufLibrary();
    return 0;
}

/// Initialize connection to the database
bool StartDB()
{
    MySQL::Library_Init();

    // Load databases
    DatabaseLoader loader("server.bnetserver", DatabaseLoader::DATABASE_NONE);
    loader
        .AddDatabase(LoginDatabase, "Login");

    if (!loader.Load())
        return false;

    TC_LOG_INFO("server.bnetserver", "Started auth database connection pool.");
    sLog->SetRealmId(0); // Enables DB appenders when realm is set.
    return true;
}

/// Close the connection to the database
void StopDB()
{
    LoginDatabase.Close();
    MySQL::Library_End();
}

void SignalHandler(std::weak_ptr<Trinity::Asio::IoContext> ioContextRef, boost::system::error_code const& error, int /*signalNumber*/)
{
    if (!error)
        if (std::shared_ptr<Trinity::Asio::IoContext> ioContext = ioContextRef.lock())
            ioContext->stop();
}

void KeepDatabaseAliveHandler(std::weak_ptr<Trinity::Asio::DeadlineTimer> dbPingTimerRef, int32 dbPingInterval, boost::system::error_code const& error)
{
    if (!error)
    {
        if (std::shared_ptr<Trinity::Asio::DeadlineTimer> dbPingTimer = dbPingTimerRef.lock())
        {
            TC_LOG_INFO("server.bnetserver", "Ping MySQL to keep connection alive");
            LoginDatabase.KeepAlive();

            dbPingTimer->expires_after(std::chrono::minutes(dbPingInterval));
            dbPingTimer->async_wait([timerRef = std::move(dbPingTimerRef), dbPingInterval](boost::system::error_code const& error) mutable
            {
                    KeepDatabaseAliveHandler(std::move(timerRef), dbPingInterval, error);
            });
        }
    }
}

void BanExpiryHandler(std::weak_ptr<Trinity::Asio::DeadlineTimer> banExpiryCheckTimerRef, int32 banExpiryCheckInterval, boost::system::error_code const& error)
{
    if (!error)
    {
        if (std::shared_ptr<Trinity::Asio::DeadlineTimer> banExpiryCheckTimer = banExpiryCheckTimerRef.lock())
        {
            LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_DEL_EXPIRED_IP_BANS));
            LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_UPD_EXPIRED_ACCOUNT_BANS));
            //LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_DEL_BNET_EXPIRED_ACCOUNT_BANNED));

            banExpiryCheckTimer->expires_from_now(std::chrono::seconds(banExpiryCheckInterval));
            banExpiryCheckTimer->async_wait(std::bind(&BanExpiryHandler, banExpiryCheckTimerRef, banExpiryCheckInterval, std::placeholders::_1));
        }
    }
}

#if PLATFORM == PLATFORM_WINDOWS
void ServiceStatusWatcher(std::weak_ptr<Trinity::Asio::DeadlineTimer> serviceStatusWatchTimerRef, std::weak_ptr<Trinity::Asio::IoContext> ioContextRef, boost::system::error_code const& error)
{
    if (!error)
    {
        if (std::shared_ptr<Trinity::Asio::IoContext> ioContext = ioContextRef.lock())
        {
            if (m_ServiceStatus == 0)
            {
                ioContext->stop();
            }
            else if (std::shared_ptr<Trinity::Asio::DeadlineTimer> serviceStatusWatchTimer = serviceStatusWatchTimerRef.lock())
            {
                serviceStatusWatchTimer->expires_after(std::chrono::seconds(1));
                serviceStatusWatchTimer->async_wait([timerRef = std::move(serviceStatusWatchTimerRef), ioContextRef = std::move(ioContextRef)](boost::system::error_code const& error) mutable
                    {
                        ServiceStatusWatcher(std::move(timerRef), std::move(ioContextRef), error);
                    });
            }
        }
    }
}
#endif

variables_map GetConsoleArguments(int argc, char** argv, fs::path& configFile, std::string& configService)
{
    (void)configService;

    options_description all("Allowed options");
    all.add_options()
        ("help,h", "print usage message")
        ("version,v", "print version build info")
        ("config,c", value<fs::path>(&configFile)->default_value(fs::absolute(_TRINITY_BNET_CONFIG)),
                     "use <arg> as configuration file")
        ;
#if PLATFORM == PLATFORM_WINDOWS
    options_description win("Windows platform specific options");
    win.add_options()
        ("service,s", value<std::string>(&configService)->default_value(""), "Windows service options: [install | uninstall]")
        ;

    all.add(win);
#endif
    variables_map variablesMap;
    try
    {
        store(command_line_parser(argc, argv).options(all).allow_unregistered().run(), variablesMap);
        notify(variablesMap);
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << "\n";
    }

    if (variablesMap.count("help"))
    {
        std::cout << all << "\n";
    }
    else if (variablesMap.count("version"))
    {
        std::cout << GitRevision::GetFullVersion() << "\n";
    }

    return variablesMap;
}

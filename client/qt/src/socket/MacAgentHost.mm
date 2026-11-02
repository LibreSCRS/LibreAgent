// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "MacAgentHost.h"

#include <QLoggingCategory>
#include <QProcess>
#include <QString>
#include <QStringList>

#include <unistd.h>

#import <AppKit/AppKit.h>

namespace LibreSCRS::AgentClient {

namespace {

Q_LOGGING_CATEGORY(lcMacAgentHost, "librescrs.agentclient.machost")

NSString* const kHostBundleId = @"org.librescrs.LibreMac";
constexpr char kAgentJobLabel[] = "org.librescrs.agent";

/// Applications as the user means it: the system folder (also reachable
/// through the data volume's firmlink) and the per-user one. A copy anywhere
/// else — a mounted disk image, Downloads — runs translocated and cannot
/// register a lasting agent, so it is reported, not launched.
bool inApplications(NSString* path)
{
    NSString* userApplications = [NSHomeDirectory() stringByAppendingString:@"/Applications/"];
    return [path hasPrefix:@"/Applications/"] || [path hasPrefix:@"/System/Volumes/Data/Applications/"] ||
           [path hasPrefix:userApplications];
}

void kickAgentJob()
{
    // No -k: an agent that is already running must not be killed and
    // restarted; for a job that is not registered this fails harmlessly.
    QProcess::startDetached(QStringLiteral("/bin/launchctl"),
                            {QStringLiteral("kickstart"),
                             QStringLiteral("gui/%1/%2").arg(::getuid()).arg(QLatin1StringView(kAgentJobLabel))});
}

} // namespace

AgentStartResult startMacAgentHost()
{
    @autoreleasepool {
        NSURL* host = nil;
        NSArray<NSURL*>* urls = [NSWorkspace.sharedWorkspace URLsForApplicationsWithBundleIdentifier:kHostBundleId];
        for (NSURL* url in urls) {
            NSString* path = url.URLByResolvingSymlinksInPath.path;
            if (path != nil && inApplications(path)) {
                host = url;
                break;
            }
        }
        if (host == nil) {
            qCInfo(lcMacAgentHost) << "agent host not in Applications; copies elsewhere:" << urls.count;
            return urls.count > 0 ? AgentStartResult::NotInApplications : AgentStartResult::NotInstalled;
        }
        NSWorkspaceOpenConfiguration* configuration = [NSWorkspaceOpenConfiguration configuration];
        configuration.activates = NO;
        configuration.addsToRecentItems = NO;
        // The handler runs on an arbitrary queue; kicking the job needs no
        // thread of ours, and a host that registers its job on launch makes the
        // kick a harmless no-op.
        [NSWorkspace.sharedWorkspace openApplicationAtURL:host
                                            configuration:configuration
                                        completionHandler:^(NSRunningApplication* app, NSError* error) {
                                          if (app != nil && error == nil) {
                                              kickAgentJob();
                                          }
                                        }];
    }
    // A host that is already running and only had its job stopped needs the
    // kick now; one still launching gets it again from the handler above.
    kickAgentJob();
    return AgentStartResult::Requested;
}

} // namespace LibreSCRS::AgentClient

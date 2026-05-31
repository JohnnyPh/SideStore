//
//  EMProxyWrwapper.swift
//  SideStore
//
//  Created by Magesh K on 22/02/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
private import em_proxy

public func startEMProxy(bind_addr: String) {
    #if targetEnvironment(simulator)
    print("startEMProxy(\(bind_addr) is no-op on simulator")
    #else
    let host = NSString(string: bind_addr)
    guard let hostPointer = host.utf8String else { return }

    _ = em_proxy.start_emotional_damage(hostPointer)
    #endif
}

public func stopEMProxy() {
    #if targetEnvironment(simulator)
    print("stopEMProxy() is no-op on simulator")
    #else
    em_proxy.stop_emotional_damage()
    #endif
}

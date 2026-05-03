/**
 * This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Copyright Contributors to the Zowe Project.
 *
 */

import { accessSync, constants, readFileSync } from "node:fs";
import { homedir } from "node:os";
import * as path from "node:path";
import type { ISshSession } from "@zowe/zos-uss-for-zowe-sdk";
import * as sshConfig from "ssh-config";

export interface ISshConfigExt extends ISshSession {
    name?: string;
    useSshAgent?: boolean; // Flag to indicate this profile should use SSH agent
}
// biome-ignore lint/complexity/noStaticOnlyClass: Utilities class has static methods
export class SshConfigUtils {
    // Cache for SSH config to avoid re-parsing on every call
    private static configCache: ISshConfigExt[] | null = null;
    private static configCacheTimestamp: number = 0;
    private static readonly CACHE_TTL = 5000; // 5 seconds cache TTL

    /**
     * Clear the SSH config cache to force a refresh on next access
     */
    public static clearCache(): void {
        this.configCache = null;
        this.configCacheTimestamp = 0;
    }

    public static async findPrivateKeys(): Promise<string[]> {
        const keyNames = ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"];
        const privateKeyPaths: Set<string> = new Set();
        // Check standard ~/.ssh private keys
        for (const algo of keyNames) {
            const keyPath = path.resolve(homedir(), ".ssh", algo);
            try {
                accessSync(keyPath, constants.R_OK);
                privateKeyPaths.add(keyPath);
            } catch {
                // Ignore missing keys
            }
        }
        return Array.from(privateKeyPaths);
    }

    public static async migrateSshConfig(forceRefresh = false): Promise<ISshConfigExt[]> {
        // Check cache first (unless force refresh is requested)
        const now = Date.now();
        if (!forceRefresh && this.configCache && (now - this.configCacheTimestamp) < this.CACHE_TTL) {
            return this.configCache;
        }

        const homeDir = homedir();
        const filePath = path.join(homeDir, ".ssh", "config");
        let fileContent: string;
        try {
            fileContent = readFileSync(filePath, "utf-8");
        } catch {
            // Cache empty result
            this.configCache = [];
            this.configCacheTimestamp = now;
            return [];
        }

        const parsedConfig = sshConfig.parse(fileContent);
        const SSHConfigs: ISshConfigExt[] = [];

        // First, check if there's a global IdentityAgent in Host * section
        let globalIdentityAgent = false;
        for (const config of parsedConfig) {
            if (config.type === sshConfig.LineType.DIRECTIVE && config.param === "Host") {
                const hostValue = typeof config.value === "object" ? config.value[0].val : (config.value as string);
                if (hostValue === "*" && Array.isArray((config as sshConfig.Section).config)) {
                    for (const subConfig of (config as sshConfig.Section).config) {
                        if (typeof subConfig === "object" && "param" in subConfig && "value" in subConfig) {
                            const param = (subConfig as sshConfig.Directive).param.toLowerCase();
                            if (param === "identityagent") {
                                globalIdentityAgent = true;
                                break;
                            }
                        }
                    }
                }
                if (globalIdentityAgent) break;
            }
        }

        for (const config of parsedConfig) {
            if (config.type === sshConfig.LineType.DIRECTIVE && config.param === "Host") {
                const session: ISshConfigExt = {};
                // If it has multiple names, take the first
                session.name = typeof config.value === "object" ? config.value[0].val : (config.value as string);
                // Skip host names that contain wildcard characters
                if (session.name.includes("*") || session.name.includes("?")) continue;

                let hasIdentityAgent = globalIdentityAgent; // Start with global setting
                
                if (Array.isArray((config as sshConfig.Section).config)) {
                    // Check if IdentityAgent is configured in this specific host section
                    for (const subConfig of (config as sshConfig.Section).config) {
                        if (typeof subConfig === "object" && "param" in subConfig && "value" in subConfig) {
                            const param = (subConfig as sshConfig.Directive).param.toLowerCase();
                            if (param === "identityagent") {
                                hasIdentityAgent = true;
                                break;
                            }
                        }
                    }
                    
                    // Second pass: parse configuration
                    for (const subConfig of (config as sshConfig.Section).config) {
                        if (typeof subConfig === "object" && "param" in subConfig && "value" in subConfig) {
                            const param = (subConfig as sshConfig.Directive).param.toLowerCase();
                            const value = subConfig.value as string;

                            switch (param) {
                                case "hostname":
                                    session.hostname = value;
                                    break;
                                case "port":
                                    session.port = Number.parseInt(value, 10);
                                    break;
                                case "user":
                                    session.user = value;
                                    break;
                                case "identityfile":
                                    // Always include IdentityFile in the profile
                                    // SSH agent will be tried first (if available), then fall back to this key
                                    session.privateKey = path.normalize(
                                        value.startsWith("~") ? path.join(homeDir, value.slice(2)) : value,
                                    );
                                    break;
                                case "connecttimeout":
                                    session.handshakeTimeout = Number.parseInt(value, 10) * 1000;
                                    break;
                                default:
                                    break;
                            }
                        }
                    }
                }
                
                // Set flag to indicate this profile should use SSH agent
                if (hasIdentityAgent) {
                    session.useSshAgent = true;
                }
                
                SSHConfigs.push(session);
            }
        }
        
        // Cache the result
        this.configCache = SSHConfigs;
        this.configCacheTimestamp = now;
        
        return SSHConfigs;
    }
}

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

import { readFileSync } from "node:fs";
import * as path from "node:path";
import {
    type Config,
    ConfigBuilder,
    ConfigSchema,
    ConfigUtils,
    type IConfig,
    type IConfigBuilderOpts,
    type IConfigProfile,
    type IImperativeConfig,
    type IProfAttrs,
    type IProfile,
    type IProfileLoaded,
    type IProfileTypeConfiguration,
    Logger,
    type ProfileInfo,
} from "@zowe/imperative";
import type { ISshSession } from "@zowe/zos-uss-for-zowe-sdk";
import { NodeSSH } from "node-ssh";
import { ConfigFileUtils } from "./ConfigFileUtils";
import {
    type IDisposable,
    type inputBoxOpts,
    MESSAGE_TYPE,
    type PrivateKeyWarningOptions,
    type ProgressCallback,
    type PromptForProfileOptions,
    type qpItem,
    type qpOpts,
} from "./doc";
import { type ISshConfigExt, SshConfigUtils } from "./SshConfigUtils";

export abstract class AbstractConfigManager {
    public constructor(private mProfilesCache: ProfileInfo) {}

    protected abstract showMessage(message: string, type: MESSAGE_TYPE): void;
    protected abstract showInputBox(opts: inputBoxOpts): Promise<string | undefined>;
    protected abstract withProgress<T>(message: string, task: (progress: ProgressCallback) => Promise<T>): Promise<T>;
    protected abstract showMenu(opts: qpOpts): Promise<string | undefined>;
    protected abstract showCustomMenu(opts: qpOpts): Promise<qpItem | undefined>;
    protected abstract getCurrentDir(): string | undefined;
    protected abstract getProfileSchemas(): IProfileTypeConfiguration[];
    protected abstract showPrivateKeyWarning(opts: PrivateKeyWarningOptions): Promise<boolean>;
    protected abstract getClientSetting<T>(setting: keyof ISshSession): T | undefined;
    protected abstract showStatusBar(): IDisposable | undefined;

    private migratedConfigs: ISshConfigExt[];
    private filteredMigratedConfigs: ISshConfigExt[];
    private validationResult: ISshConfigExt | undefined;
    private selectedProfile: ISshConfigExt | undefined;
    private sshProfiles: IProfileLoaded[];
    private sshRegex = /^ssh\s+(?:([a-zA-Z0-9_-]+)@)?([a-zA-Z0-9.-]+)/;
    private flagRegex = /-(\w+)(?:\s+("[^"]+"|'[^']+'|\S+))?/g;
    // Track profiles that successfully authenticated via SSH agent (for manual connections)
    private sshAgentProfiles: Set<string> = new Set();

    public async promptForProfile(
        profileName?: string,
        options?: PromptForProfileOptions,
    ): Promise<IProfileLoaded | undefined> {
        const {
            setExistingProfile = true,
            prioritizeProjectLevelConfig = true,
            disableCreateNewProfile = false,
        } = options ?? {};
        this.validationResult = undefined;
        if (profileName) {
            return { profile: this.getMergedAttrs(profileName), message: "", failNotFound: false, type: "ssh" };
        }

        this.sshProfiles = this.fetchAllSshProfiles().filter(({ name, profile }) => name && profile?.host);

        // Get configs from ~/.ssh/config (force refresh to pick up any recent changes)
        this.migratedConfigs = await SshConfigUtils.migrateSshConfig(true);

        // Parse to remove migratable configs that already exist on the team config
        this.filteredMigratedConfigs = this.migratedConfigs.filter(
            (migratedConfig) =>
                !this.sshProfiles.some((sshProfile) => sshProfile.profile?.host === migratedConfig.hostname),
        );

        // Build menu items with enhanced SSH config display
        const menuItems: qpItem[] = [];

        // Add "Create New SSH Host" option if profile creation is enabled
        if (!disableCreateNewProfile) {
            menuItems.push({ label: "$(plus) Add New SSH Host..." });
        }

        // Add existing Zowe profiles
        if (this.sshProfiles.length > 0) {
            menuItems.push({ label: "Zowe SSH Profiles", separator: true });
            this.sshProfiles.forEach(({ name, profile }) => {
                menuItems.push({
                    label: name!,
                    description: profile!.host!,
                });
            });
        }

        // Add SSH config profiles (show all, not just filtered ones) with enhanced display
        if (!disableCreateNewProfile && this.migratedConfigs.length > 0) {
            menuItems.push({ label: "SSH Config Profiles (~/.ssh/config)", separator: true });
            this.migratedConfigs.forEach(({ name, hostname, user, privateKey, port }) => {
                const details: string[] = [];
                if (user) details.push(`${user}@${hostname}`);
                else details.push(hostname!);
                if (port && port !== 22) details.push(`port ${port}`);
                if (privateKey) {
                    const keyName = path.basename(privateKey);
                    details.push(`🔑 ${keyName}`);
                }
                menuItems.push({
                    label: name!,
                    description: details.join(" • "),
                });
            });
        }

        // Prompt user for ssh (new config, existing, migrating)
        let result: qpItem | undefined;

        if (disableCreateNewProfile) {
            const selectedLabel = await this.showMenu({
                items: menuItems,
                placeholder: "Select configured SSH host",
            });

            if (!selectedLabel) return;

            result = menuItems.find((item) => item.label === selectedLabel);
        } else {
            result = await this.showCustomMenu({
                items: menuItems,
                placeholder: "Select configured SSH host or enter user@host",
            });
        }

        // If nothing selected, return
        if (!result) return;

        // If result is add new SSH host then create a new config, if not use migrated configs
        this.selectedProfile = this.migratedConfigs.find(
            ({ name, hostname, user, privateKey, port }) => {
                if (result?.label !== name) return false;
                
                // Build the same description format to match
                const details: string[] = [];
                if (user) details.push(`${user}@${hostname}`);
                else details.push(hostname!);
                if (port && port !== 22) details.push(`port ${port}`);
                if (privateKey) {
                    const keyName = path.basename(privateKey);
                    details.push(`🔑 ${keyName}`);
                }
                return result?.description === details.join(" • ");
            }
        );

        if (result.description === "Custom SSH Host") {
            const createNewConfig = await this.createNewProfile(result.label);
            if (!createNewConfig) return undefined;
            this.selectedProfile = createNewConfig;
        } else if (result.label === "$(plus) Add New SSH Host...") {
            const createNewConfig = await this.createNewProfile();
            if (!createNewConfig) return undefined;
            this.selectedProfile = createNewConfig;
        }

        // If an existing team config profile was selected
        if (!this.selectedProfile) {
            const statusBar = this.showStatusBar();
            const foundProfile = this.sshProfiles.find(({ name }) => name === result.label);
            if (foundProfile) {
                const validConfig = await this.validateConfig({
                    name: foundProfile.name,
                    hostname: foundProfile?.profile?.host,
                    port: foundProfile?.profile?.port,
                    privateKey: foundProfile?.profile?.privateKey,
                    keyPassphrase: foundProfile?.profile?.keyPassphrase,
                    user: foundProfile?.profile?.user,
                    password: foundProfile?.profile?.password,
                });

                if (validConfig === undefined) {
                    statusBar?.dispose();
                    return;
                }

                if (setExistingProfile || Object.keys(validConfig).length > 0) {
                    if (validConfig.password) {
                        foundProfile.profile.privateKey = foundProfile.profile.keyPassphrase = undefined;
                    }
                    await this.setProfile(validConfig, foundProfile.name);
                }
                statusBar?.dispose();
                return { ...foundProfile, profile: { ...foundProfile.profile, ...validConfig } };
            }
        }

        // Check if this profile is from SSH config (either SSH agent or custom private key)
        const profileKey = this.selectedProfile ?
            `${this.selectedProfile.hostname}:${this.selectedProfile.user}` : '';
        const isFromSshConfig = this.selectedProfile && this.migratedConfigs.some(
            (config) => config.hostname === this.selectedProfile?.hostname &&
                       config.user === this.selectedProfile?.user
        );
        const usesSshAgent = this.selectedProfile?.useSshAgent ||
                             this.sshAgentProfiles.has(profileKey);
        
        // For profiles from SSH config OR using SSH agent, skip creating project config
        // since we'll write to global config
        // For manually created profiles, prioritize creating a team config in the local workspace if it exists
        if (!isFromSshConfig && !usesSshAgent) {
            const useProject = prioritizeProjectLevelConfig && this.getCurrentDir() !== undefined;
            await this.createZoweSchema(!useProject);
        }

        // Prompt for a new profile name with the hostname (for adding a new config) or host value (for migrating from a config)
        this.selectedProfile = await this.getNewProfileName(this.selectedProfile!, this.mProfilesCache.getTeamConfig());

        if (!this.selectedProfile?.name) {
            this.showMessage("SSH setup cancelled.", MESSAGE_TYPE.WARNING);
            return;
        }

        // Attempt connection if private key was provided and it has not been validated
        if (this.validationResult === undefined && this.selectedProfile.privateKey) {
            const statusBar = this.showStatusBar();
            this.validationResult = await this.validateConfig(this.selectedProfile, false);
            statusBar?.dispose();
            
            // If we have a private key from SSH config, don't fall through to password prompts
            // Mark as validated (even if it failed) to prevent password prompts
            if (this.validationResult === undefined) {
                this.validationResult = {}; // Empty object means validation attempted but no modifications needed
            }
        }

        // If no explicit private key, try to find and validate with default SSH keys
        // This handles cases where SSH config has user but no IdentityFile (relies on SSH agent or default keys)
        if (this.validationResult === undefined) {
            const statusBar = this.showStatusBar();
            await this.validateFoundPrivateKeys();
            statusBar?.dispose();
            
            // If we found and validated with a key, mark as done to prevent password prompts
            // Skip password prompt if this profile is from SSH config OR uses SSH agent
            const profileKey = `${this.selectedProfile?.hostname}:${this.selectedProfile?.user}`;
            const isFromSshConfig = this.migratedConfigs.some(
                (config) => config.hostname === this.selectedProfile?.hostname &&
                           config.user === this.selectedProfile?.user
            );
            const usesSshAgent = this.selectedProfile?.useSshAgent ||
                                 this.sshAgentProfiles.has(profileKey);
            
            if (this.validationResult === undefined && this.selectedProfile.user &&
                (isFromSshConfig || usesSshAgent)) {
                // If we have a user from SSH config or SSH agent but no password, don't ask for one
                // This allows SSH agent authentication to work
                this.validationResult = {}; // Mark as validated to prevent password prompts
            }
        }

        if (this.validationResult === undefined) {
            const statusBar = this.showStatusBar();
            // Attempt to validate with given URL/creds
            // Don't ask for password if we already have a private key from SSH config
            const shouldAskForPassword = !this.selectedProfile.privateKey;
            this.validationResult = await this.validateConfig(this.selectedProfile, shouldAskForPassword);
            statusBar?.dispose();
        }

        // If validateConfig returns modifications, merge them with the selected profile
        if (this.validationResult && Object.keys(this.validationResult).length >= 1) {
            // Only clear privateKey/keyPassphrase if password authentication was used
            if (this.validationResult.password) {
                this.selectedProfile.privateKey = this.selectedProfile.keyPassphrase = undefined;
            }
            this.selectedProfile = { ...this.selectedProfile, ...this.validationResult };
        }
        // If we have a user from SSH config but no password or private key, allow it
        // This supports SSH agent authentication and server-side authorized_keys
        // Don't require password for SSH config profiles with user configured
        const hasUserFromSshConfig = this.selectedProfile?.user &&
            this.migratedConfigs.some(config =>
                // Match by hostname and user (name might have changed during profile creation)
                config.hostname === this.selectedProfile?.hostname &&
                config.user === this.selectedProfile?.user
            );
        
        // If no private key or password is on the profile, check if it's from SSH config with user
        // OR if it's marked as using SSH agent (either from SSH config or tracked in sshAgentProfiles)
        const profileKeyForCheck = `${this.selectedProfile?.hostname}:${this.selectedProfile?.user}`;
        const shouldUseSshAgent = this.migratedConfigs.some(
            (config) => config.hostname === this.selectedProfile?.hostname &&
                       config.user === this.selectedProfile?.user &&
                       config.useSshAgent
        ) || this.sshAgentProfiles.has(profileKeyForCheck) || this.selectedProfile?.useSshAgent;
        
        // Check if password was provided during validation (it's in validationResult but not yet merged)
        const hasPassword = this.selectedProfile?.password || this.validationResult?.password;
        
        if (!this.selectedProfile?.privateKey && !hasPassword &&
            !hasUserFromSshConfig && !shouldUseSshAgent) {
            this.showMessage("SSH setup cancelled.", MESSAGE_TYPE.WARNING);
            return;
        }

        await this.setProfile(this.selectedProfile);

        return {
            name: this.selectedProfile.name,
            message: "",
            failNotFound: false,
            type: "ssh",
            profile: {
                host: this.selectedProfile.hostname,
                name: this.selectedProfile.name,
                password: this.selectedProfile.password,
                user: this.selectedProfile.user,
                privateKey: this.selectedProfile.privateKey,
                handshakeTimeout: this.selectedProfile.handshakeTimeout,
                port: this.selectedProfile.port,
                keyPassphrase: this.selectedProfile.keyPassphrase,
            },
        };
    }

    protected abstract storeServerPath(host: string, path: string): void;

    public static validateDeployPath(this: void, input: string): string | null {
        const trimmed = input.trim();
        if (!trimmed) return "Path cannot be empty.";
        if (trimmed.length > 1024) return "Path is longer than the USS max path length of 1024.";
        if (trimmed.endsWith("/c/build-out")) return "Cannot deploy on top of a dev build. Choose another location.";

        return path.isAbsolute(trimmed.replace(/^~/, ""))
            ? null
            : "Invalid deploy directory format. Ensure it matches the expected pattern.";
    }

    public async promptForDeployDirectory(host: string, defaultServerPath: string): Promise<string> {
        const input = await this.showInputBox({
            title: "Enter deploy directory",
            value: defaultServerPath,
            validateInput: (input) => AbstractConfigManager.validateDeployPath(input),
        });
        if (input === undefined) {
            this.showMessage("SSH setup cancelled.", MESSAGE_TYPE.WARNING);
            return undefined;
        }

        const deployDir = input?.trim();
        if (host && deployDir !== defaultServerPath) {
            this.storeServerPath(host, deployDir);
        }
        return deployDir;
    }

    private async createNewProfile(knownConfigOpts?: string): Promise<ISshConfigExt | undefined> {
        const SshProfile: ISshConfigExt = {};

        let sshResponse: string | undefined;

        // KnownConfigOpts is defined if a custom option is selected via the first quickpick (ex: user@host is entered in search bar)
        if (!knownConfigOpts) {
            sshResponse = await this.showInputBox({
                title: "Enter SSH connection command",
                placeHolder: "E.g. ssh user@example.com",
            });
        } else {
            sshResponse = `ssh ${knownConfigOpts}`;
            const match = sshResponse.match(this.sshRegex);
            if (!match || match[0].length < sshResponse.length) {
                this.showMessage(
                    "Invalid custom connection format. Ensure it matches the expected pattern.",
                    MESSAGE_TYPE.ERROR,
                );
                return undefined;
            }
        }

        if (sshResponse === undefined) {
            this.showMessage("SSH setup cancelled.", MESSAGE_TYPE.WARNING);
            return undefined;
        }

        const sshMatch = sshResponse.match(this.sshRegex);

        if (!sshMatch) {
            this.showMessage("Invalid SSH command format. Ensure it matches the expected pattern.", MESSAGE_TYPE.ERROR);
            return undefined;
        }

        SshProfile.user = sshMatch[1] || require("node:os").userInfo().username;
        SshProfile.hostname = sshMatch[2];

        let flagMatch: RegExpExecArray | null;

        if (!knownConfigOpts) {
            // biome-ignore lint/suspicious/noAssignInExpressions: We just want to use the regex array in the loop
            while ((flagMatch = this.flagRegex.exec(sshResponse)) !== null) {
                const [, flag, value] = flagMatch;
                // Check for missing value
                if (!value) {
                    this.showMessage(`Missing value for flag -${flag}.`, MESSAGE_TYPE.ERROR);
                    return undefined;
                }

                const unquotedValue = value.replace(/^["']|["']$/g, ""); // Remove surrounding quotes

                // Map aliases to consistent keys
                if (flag === "p" || flag.toLowerCase() === "port") {
                    const portNumber = Number.parseInt(unquotedValue, 10);
                    if (Number.isNaN(portNumber)) {
                        this.showMessage(
                            `Invalid value for flag ${flag.length > 1 ? "-" : ""}-${flag}. Port must be a valid number.`,
                            MESSAGE_TYPE.ERROR,
                        );
                        return undefined;
                    }
                    SshProfile.port = portNumber;
                } else if (flag === "i" || flag.toLowerCase() === "identity_file") {
                    SshProfile.privateKey = unquotedValue;
                }

                // Validate if quotes are required
                if (/\s/.test(unquotedValue) && !/^["'].*["']$/.test(value)) {
                    this.showMessage(
                        `Invalid value for flag ${flag.length > 1 ? "-" : ""}-${flag}. Values with spaces must be quoted.`,
                        MESSAGE_TYPE.ERROR,
                    );
                    return undefined;
                }
            }
        }
        return SshProfile;
    }
    // Cloned method
    private async createZoweSchema(global: boolean): Promise<void> {
        try {
            const homeDir = ConfigUtils.getZoweDir();

            const user = false;
            const workspaceDir = this.getCurrentDir();

            const config = this.mProfilesCache.getTeamConfig();

            if (config.layerExists(global ? homeDir : workspaceDir)) return;

            config.api.layers.activate(user, global);

            const profSchemas = this.getProfileSchemas();
            config.setSchema(ConfigSchema.buildSchema(profSchemas));

            // Note: IConfigBuilderOpts not exported
            // const opts: IConfigBuilderOpts = {
            const opts: IConfigBuilderOpts = {
                // getSecureValue: this.promptForProp.bind(this),
                populateProperties: true,
            };
            // Build new config and merge with existing layer
            const baseProfSchema = profSchemas.find((schema) => schema.type === "base");
            const impConfig: Partial<IImperativeConfig> = {
                profiles: [baseProfSchema],
                baseProfile: baseProfSchema,
            };
            const newConfig: IConfig = await ConfigBuilder.build(impConfig, global, opts);
            config.api.layers.merge(newConfig);
            // Use api.layers.write() instead of save() to avoid keyring prompts on MacOS
            config.api.layers.write();
        } catch {}
    }

    private async validateConfig(newConfig: ISshConfigExt, askForPassword = true): Promise<ISshConfigExt | undefined> {
        const configModifications: ISshConfigExt | undefined = {};
        // Track if we started with a private key to avoid asking for password later
        const hadPrivateKeyInitially = !!newConfig.privateKey;
        
        try {
            const privateKeyPath = newConfig.privateKey;

            if (!newConfig.user) {
                const userModification = await this.showInputBox({
                    title: `Enter user for host: '${newConfig.hostname}'`,
                    placeHolder: "Enter the user for the target host",
                });
                configModifications.user = userModification;
            }

            // Check if we have a private key that can be read
            let hasValidPrivateKey = false;
            if (privateKeyPath) {
                try {
                    const keyContent = readFileSync(path.normalize(privateKeyPath), "utf-8");
                    hasValidPrivateKey = keyContent && keyContent.length > 0;
                } catch (error) {
                    // Key file doesn't exist or can't be read
                    hasValidPrivateKey = false;
                }
            }

            // Check if this profile should use SSH agent (from SSH config with IdentityAgent)
            const shouldUseSshAgent = this.migratedConfigs.some(
                (config) => config.hostname === newConfig.hostname &&
                           config.user === newConfig.user &&
                           config.useSshAgent
            );

            // Only ask for password if we don't have a valid private key, no password is set,
            // and the profile is not configured to use SSH agent
            if (!hasValidPrivateKey && !newConfig.password && !shouldUseSshAgent) {
                const passwordPrompt = askForPassword && (await this.promptForPassword(newConfig, configModifications));
                return passwordPrompt ? { ...configModifications, ...passwordPrompt } : undefined;
            }

            const authResult = await this.attemptConnection({ ...newConfig, ...configModifications });
            if (authResult.usedSshAgent) {
                configModifications.useSshAgent = true;
            }
        } catch (err) {
            const errorMessage = `${err}`;
            if (newConfig.privateKey && errorMessage.includes("All configured authentication methods failed")) {
                if (!(await this.handleInvalidPrivateKey(newConfig))) {
                    return undefined;
                }
                newConfig.privateKey = undefined;
                if (newConfig.password) {
                    return await this.validateConfig(newConfig, askForPassword);
                }
            }

            if (errorMessage.includes("Invalid username")) {
                const testUser = await this.showInputBox({
                    title: `Enter user for host: '${newConfig.hostname}'`,
                    placeHolder: "Enter the user for the target host",
                });

                if (!testUser) return undefined;
                try {
                    await this.attemptConnection({ ...newConfig, user: testUser });
                    return { user: testUser };
                } catch {
                    return undefined;
                }
            }

            if (errorMessage.includes("but no passphrase given") || errorMessage.includes("integrity check failed")) {
                const privateKeyPath = newConfig.privateKey;
                for (let attempts = 0; attempts < 3; attempts++) {
                    const testKeyPassphrase = await this.showInputBox({
                        title: `Enter passphrase for key '${privateKeyPath}'`,
                        password: true,
                        placeHolder: "Enter passphrase for key",
                    });

                    try {
                        await this.attemptConnection({
                            ...newConfig,
                            ...configModifications,
                            keyPassphrase: testKeyPassphrase,
                        });
                        return { ...configModifications, keyPassphrase: testKeyPassphrase };
                    } catch (error) {
                        if (!`${error}`.includes("integrity check failed")) break;
                        this.showMessage(`Passphrase Authentication Failed (${attempts + 1}/3)`, MESSAGE_TYPE.ERROR);
                    }
                }
                if (!(await this.handleInvalidPrivateKey(newConfig))) {
                    return undefined;
                }
                newConfig.privateKey = undefined;
                newConfig.keyPassphrase = undefined;
                return undefined;
            }

            if (errorMessage.includes("All configured authentication methods failed")) {
                // Don't ask for password if we originally had a private key from SSH config
                // This prevents password prompts when SSH key authentication is configured
                const shouldAskPassword = askForPassword && !hadPrivateKeyInitially;
                const passwordPrompt = shouldAskPassword
                    ? await this.promptForPassword(newConfig, configModifications)
                    : undefined;

                // If password authentication succeeded and we had a private key that failed,
                // comment out the private key in the configuration file
                if (passwordPrompt && newConfig.privateKey) {
                    if (!(await this.handleInvalidPrivateKey(newConfig))) {
                        return undefined;
                    }
                }

                return passwordPrompt ? { ...configModifications, ...passwordPrompt } : undefined;
            }

            if (errorMessage.includes("Timed out while waiting for handshake")) {
                this.showMessage("Timed out while waiting for handshake", MESSAGE_TYPE.ERROR);
                return undefined;
            }

            if (errorMessage.includes("Cannot parse privateKey: Malformed OpenSSH private key")) {
                await this.handleInvalidPrivateKey(newConfig);
                return undefined;
            }

            if (errorMessage.includes("FOTS1668") || errorMessage.includes("FOTS1669")) {
                this.showMessage(errorMessage, MESSAGE_TYPE.ERROR);
                return undefined;
            }
        }
        return configModifications;
    }

    private async attemptConnection(config: ISshConfigExt): Promise<{ usedSshAgent?: boolean }> {
        const ssh = new NodeSSH();
        const logger = Logger.getAppLogger();

        try {
            // Try 1: If explicit private key is provided, try it first
            if (config.privateKey) {
                try {
                    logger.info(`[attemptConnection] Trying explicit private key: ${config.privateKey}`);
                    const connectionConfig: any = {
                        host: config.hostname,
                        port: config.port || 22,
                        username: config.user,
                        privateKey: readFileSync(path.normalize(config.privateKey), "utf8"),
                        readyTimeout: config.handshakeTimeout || this.getClientSetting("handshakeTimeout") || 30000,
                        tryKeyboard: true,
                    };
                    if (config.keyPassphrase) {
                        connectionConfig.passphrase = config.keyPassphrase;
                    }
                    
                    logger.info(`[attemptConnection] Attempting connection with private key to ${config.hostname}:${config.port || 22} as ${config.user}`);
                    await ssh.connect(connectionConfig);
                    
                    if (ssh.isConnected()) {
                        logger.info(`[attemptConnection] Successfully connected with private key`);
                        // Test the connection
                        const result = await ssh.execCommand("exit");
                        if (result.stderr?.startsWith("FOTS1668")) {
                            throw new Error("FOTS1668 error detected");
                        }
                        return { usedSshAgent: false }; // Success with private key!
                    }
                } catch (err) {
                    logger.info(`[attemptConnection] Private key authentication failed: ${err.message}`);
                    logger.info(`[attemptConnection] Trying SSH agent as fallback`);
                    // Disconnect if partially connected
                    if (ssh.isConnected()) {
                        ssh.dispose();
                    }
                    // Fall through to try SSH agent
                }
            }
            
            // Try 2: If no private key OR private key failed, try SSH agent (unless password is provided)
            if (!config.password) {
                logger.info(`[attemptConnection] Trying SSH agent authentication`);
                
                const connectionConfig: any = {
                    host: config.hostname,
                    port: config.port || 22,
                    username: config.user,
                    readyTimeout: config.handshakeTimeout || this.getClientSetting("handshakeTimeout") || 30000,
                    tryKeyboard: true,
                };
                
                // Try 1Password agent path first (more reliable than SSH_AUTH_SOCK)
                const onePasswordAgent = path.join(
                    require("node:os").homedir(),
                    "Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
                );
                try {
                    require("node:fs").accessSync(onePasswordAgent);
                    logger.info(`[attemptConnection] Using 1Password agent: ${onePasswordAgent}`);
                    connectionConfig.agent = onePasswordAgent;
                } catch {
                    logger.info(`[attemptConnection] 1Password agent not available at ${onePasswordAgent}`);
                    
                    // Fall back to SSH_AUTH_SOCK if 1Password agent not found
                    if (process.env.SSH_AUTH_SOCK) {
                        logger.info(`[attemptConnection] Using SSH agent from SSH_AUTH_SOCK: ${process.env.SSH_AUTH_SOCK}`);
                        connectionConfig.agent = process.env.SSH_AUTH_SOCK;
                    } else {
                        logger.info(`[attemptConnection] No SSH agent found`);
                    }
                }
                
                if (connectionConfig.agent) {
                    logger.info(`[attemptConnection] Attempting connection with SSH agent to ${config.hostname}:${config.port || 22} as ${config.user}`);
                    logger.info(`[attemptConnection] Auth config: agent=${!!connectionConfig.agent}, privateKey=false, password=false`);
                    
                    await ssh.connect(connectionConfig);
                    
                    if (ssh.isConnected()) {
                        logger.info(`[attemptConnection] Successfully connected with SSH agent`);
                        // Test the connection
                        const result = await ssh.execCommand("exit");
                        if (result.stderr?.startsWith("FOTS1668")) {
                            throw new Error("FOTS1668 error detected");
                        }
                        return { usedSshAgent: true }; // Success with SSH agent!
                    }
                }
            }
            
            // Try 3: If password is provided, use it
            if (config.password) {
                logger.info(`[attemptConnection] Using password authentication`);
                const connectionConfig: any = {
                    host: config.hostname,
                    port: config.port || 22,
                    username: config.user,
                    password: config.password,
                    readyTimeout: config.handshakeTimeout || this.getClientSetting("handshakeTimeout") || 30000,
                    tryKeyboard: true,
                };
                
                logger.info(`[attemptConnection] Attempting connection with password to ${config.hostname}:${config.port || 22} as ${config.user}`);
                logger.info(`[attemptConnection] Auth config: agent=false, privateKey=false, password=true`);
                
                await ssh.connect(connectionConfig);
            }
            
            // Final connection check
            if (!ssh.isConnected()) {
                throw new Error("Failed to connect to SSH: All configured authentication methods failed");
            }
            // Test the connection by executing a simple command
            const result = await ssh.execCommand("exit");
            if (result.stderr?.startsWith("FOTS1668")) {
                throw new Error(result.stderr);
            }
            return { usedSshAgent: false }; // Success with password
        } finally {
            ssh.dispose();
        }
    }

    private async promptForPassword(
        config: ISshConfigExt,
        configModifications: ISshConfigExt,
    ): Promise<ISshConfigExt | undefined> {
        for (let attempts = 0; attempts < 3; attempts++) {
            const testPassword = await this.showInputBox({
                title: `${configModifications.user ?? config.user}@${config.hostname}'s password:`,
                password: true,
                placeHolder: "Enter your password",
            });

            if (!testPassword) return undefined;

            try {
                await this.attemptConnection({ ...config, ...configModifications, password: testPassword });
                return { password: testPassword };
            } catch (error) {
                if (`${error}`.includes("FOTS1668")) {
                    this.showMessage("Password Expired on Target System", MESSAGE_TYPE.ERROR);
                    return undefined;
                }
                this.showMessage(`Password Authentication Failed (${attempts + 1}/3)`, MESSAGE_TYPE.ERROR);
            }
        }
        this.showMessage(
            `Authentication failed. Please check your password or ensure your account is not locked out.`,
            MESSAGE_TYPE.ERROR,
        );

        return undefined;
    }

    private async validateFoundPrivateKeys() {
        // Create a progress bar using the custom Gui.withProgress
        await this.withProgress("Validating Private Keys...", async (progress) => {
            // Check if this profile should use SSH agent (from SSH config with IdentityAgent)
            const shouldUseSshAgent = this.migratedConfigs.some(
                (config) => config.hostname === this.selectedProfile?.hostname &&
                           config.user === this.selectedProfile?.user &&
                           config.useSshAgent
            );
            
            // Skip default key validation if profile should use SSH agent
            // Find private keys located at ~/.ssh/ and attempt to connect with them
            if (!this.validationResult && !shouldUseSshAgent) {
                const foundPrivateKeys = await SshConfigUtils.findPrivateKeys();
                for (const privateKey of foundPrivateKeys) {
                    const testValidation: ISshConfigExt = { ...this.selectedProfile };
                    testValidation.privateKey = privateKey;

                    const result = await this.validateConfig(testValidation, false);

                    progress(100 / foundPrivateKeys.length);

                    if (result) {
                        this.validationResult = {};
                        // If SSH agent was used as fallback, don't include the privateKey
                        if (result.useSshAgent) {
                            this.selectedProfile = { ...this.selectedProfile, ...result };
                            // Track this profile as using SSH agent for later config writing
                            const profileKey = `${this.selectedProfile.hostname}:${this.selectedProfile.user}`;
                            this.sshAgentProfiles.add(profileKey);
                        } else {
                            // Private key file worked, include it in the profile
                            this.selectedProfile = { ...this.selectedProfile, ...result, privateKey };
                        }
                        return;
                    }
                }
                
                // If no private key files worked, try SSH agent authentication
                // This handles cases where keys are loaded via ssh-add but not in ~/.ssh/config
                const testValidation: ISshConfigExt = { ...this.selectedProfile };
                // Don't set privateKey - this will cause SSH library to use agent
                const result = await this.validateConfig(testValidation, false);
                
                if (result) {
                    this.validationResult = {};
                    this.selectedProfile = { ...this.selectedProfile, ...result };
                    // Mark this as an SSH agent profile for proper config handling
                    this.selectedProfile.useSshAgent = true;
                    // Track this profile as using SSH agent for later config writing
                    const profileKey = `${this.selectedProfile.hostname}:${this.selectedProfile.user}`;
                    this.sshAgentProfiles.add(profileKey);
                    return;
                }
            }

            // Match hostname to configurations from ~/.ssh/config file
            let validationAttempts = this.migratedConfigs.filter(
                (config) => config.hostname === this.selectedProfile?.hostname,
            );

            // If multiple matches exist, narrow down by user
            if (validationAttempts.length > 1 && this.selectedProfile?.user) {
                validationAttempts = validationAttempts.filter((config) => config.user === this.selectedProfile?.user);
            } else {
                // If no user is specified, allow all configs where the hostname matches
                validationAttempts = validationAttempts.filter(
                    (config) => !this.selectedProfile?.user || config.user === this.selectedProfile?.user,
                );
            }

            for (const profile of validationAttempts) {
                const testValidation: ISshConfigExt = profile;
                const result = await this.validateConfig(testValidation, false);
                progress(100 / validationAttempts.length);
                if (result !== undefined) {
                    this.validationResult = {};
                    // Preserve all SSH config parameters from the matched profile
                    this.selectedProfile = {
                        ...this.selectedProfile,
                        user: testValidation.user || this.selectedProfile.user,
                        privateKey: testValidation.privateKey,
                        port: testValidation.port || this.selectedProfile.port,
                        keyPassphrase: testValidation.keyPassphrase,
                        handshakeTimeout: testValidation.handshakeTimeout || this.selectedProfile.handshakeTimeout,
                    };
                    if (Object.keys(result).length >= 1) {
                        this.selectedProfile = {
                            ...this.selectedProfile,
                            ...result,
                        };
                    }
                    return;
                }
            }
        });
    }

    private async setProfile(selectedConfig: ISshConfigExt, updatedProfile?: string): Promise<void> {
        const configApi = this.mProfilesCache.getTeamConfig().api;
        
        // Check if this profile should use SSH agent ONLY (no explicit privateKey in original config)
        // If a profile has both IdentityAgent and IdentityFile, treat it as a key-based profile
        // with SSH agent as a fallback, not as an SSH agent-only profile
        const matchingConfig = this.migratedConfigs.find(
            (config) => config.hostname === selectedConfig.hostname &&
                       config.user === selectedConfig.user
        );
        // Check both the migrated config AND the selected config for useSshAgent flag
        // This handles both SSH config profiles and manually created profiles that use SSH agent
        const shouldUseSshAgent = (matchingConfig?.useSshAgent && !matchingConfig?.privateKey) ||
                                 (selectedConfig.useSshAgent && !selectedConfig.privateKey);
        
        // Determine which fields should be secure based on what's actually present
        const secureFields: string[] = [];
        
        // If using SSH key authentication
        if (selectedConfig.privateKey) {
            // Only secure keyPassphrase if it exists
            if (selectedConfig.keyPassphrase) {
                secureFields.push("keyPassphrase");
            }
            // Don't include password in secure fields when using SSH keys
        } else if (selectedConfig.password) {
            // If using password authentication, secure the password
            secureFields.push("password");
        } else if (shouldUseSshAgent) {
            // For SSH agent profiles, explicitly set secure to empty array
            // This prevents inheriting password from base profile
            // SSH agent profiles don't need password or privateKey
        }
        
        // Create the base config object
        const config: IConfigProfile = {
            type: "ssh",
            properties: {
                user: selectedConfig.user,
                host: selectedConfig.hostname,
                port: selectedConfig.port || 22,
            },
            secure: secureFields,
        };
        
        // For SSH agent profiles, do NOT add password, privateKey, or keyPassphrase properties
        // Omitting these properties entirely prevents Zowe's credential manager from prompting
        // The SSH agent will be used automatically when no explicit auth is provided
        if (!shouldUseSshAgent) {
            // For non-SSH-agent profiles, add authentication properties if they exist
            if (selectedConfig.privateKey) {
                config.properties.privateKey = selectedConfig.privateKey;
            }
            if (selectedConfig.keyPassphrase) {
                config.properties.keyPassphrase = selectedConfig.keyPassphrase;
            }
            if (selectedConfig.password) {
                config.properties.password = selectedConfig.password;
            }
        }
        // Note: SSH agent profiles intentionally omit password/privateKey/keyPassphrase
        // This creates a clean config that works with SSH agent authentication

        // Check if this profile is from SSH config OR uses SSH agent (declare at function scope for later use)
        const profileKey = `${selectedConfig.hostname}:${selectedConfig.user}`;
        const isFromSshConfig = this.migratedConfigs.some(
            (cfg) => cfg.hostname === selectedConfig.hostname &&
                    cfg.user === selectedConfig.user
        );
        const usesSshAgent = selectedConfig.useSshAgent || this.sshAgentProfiles.has(profileKey);
        const shouldWriteToGlobal = isFromSshConfig || usesSshAgent;

        if (updatedProfile) {
            for (const key of Object.keys(selectedConfig)) {
                const validKey = key as keyof ISshConfigExt;

                // Get the location of the property being modified

                const propertyLocation = this.mProfilesCache
                    .mergeArgsForProfile({
                        profName: updatedProfile,
                        profType: "ssh",
                        isDefaultProfile: this.fetchDefaultProfile()?.name === updatedProfile,
                        profLoc: { locType: 1 },
                    })
                    .knownArgs.find((obj) => obj.argName === key)?.argLoc.jsonLoc;

                let allowBaseModification: string | undefined;

                if (propertyLocation) {
                    const profileName = configApi.profiles.getProfileNameFromPath(propertyLocation);

                    // Check to see if the property being modified comes from the service profile to handle possibly breaking configuration changes
                    const doesPropComeFromProfile = profileName === updatedProfile;

                    if (!doesPropComeFromProfile) {
                        const qpOpts: qpOpts = {
                            items: [
                                { label: "Yes", description: "Proceed with modification" },
                                { label: "No", description: "Modify SSH profile instead" },
                            ],
                            title: `Property: "${key}" found in a possibly shared configuration and may break others, continue?`,
                            placeholder: "Select an option",
                        };
                        allowBaseModification = await this.showMenu(qpOpts);
                    }
                }
                this.mProfilesCache.updateProperty({
                    profileName: updatedProfile,
                    profileType: "ssh",
                    property: validKey,
                    value: selectedConfig[validKey],
                    forceUpdate: allowBaseModification !== "Yes",
                    setSecure: this.mProfilesCache.isSecured(),
                });
            }
        } else {
            // Check if profile already exists
            const existingProfile = configApi.profiles.get(selectedConfig.name!);
            
            if (existingProfile) {
                // Profile exists, update it with new properties (especially privateKey from validation)
                for (const key of Object.keys(config.properties)) {
                    const value = config.properties[key];
                    if (value !== undefined) {
                        this.mProfilesCache.updateProperty({
                            profileName: selectedConfig.name!,
                            profileType: "ssh",
                            property: key,
                            value: value,
                            forceUpdate: true,
                            setSecure: this.mProfilesCache.isSecured(),
                        });
                    }
                }
            } else {
                // Profile doesn't exist, create it
                // For profiles from SSH config OR using SSH agent, write directly to global config
                // to avoid base profile creation
                if (shouldWriteToGlobal) {
                    const fs = await import("node:fs");
                    const homeDir = ConfigUtils.getZoweDir();
                    const globalConfigPath = path.join(homeDir, "zowe.config.json");
                    
                    // Read existing global config or create new one
                    let globalConfig: IConfig;
                    try {
                        const content = fs.readFileSync(globalConfigPath, "utf-8");
                        globalConfig = JSON.parse(content);
                    } catch {
                        // File doesn't exist, create new config
                        globalConfig = {
                            $schema: "./zowe.schema.json",
                            profiles: {},
                            defaults: {},
                            autoStore: true
                        };
                    }
                    
                    // Ensure profiles and defaults exist
                    if (!globalConfig.profiles) {
                        globalConfig.profiles = {};
                    }
                    if (!globalConfig.defaults) {
                        globalConfig.defaults = {};
                    }
                    
                    // Add the SSH profile
                    globalConfig.profiles[selectedConfig.name!] = config;
                    
                    // Set as default SSH profile if none exists
                    if (!globalConfig.defaults.ssh) {
                        globalConfig.defaults.ssh = selectedConfig.name!;
                    }
                    
                    // Write back to global config
                    fs.writeFileSync(globalConfigPath, JSON.stringify(globalConfig, null, 4), "utf-8");
                    
                    // Reload the config to pick up the newly written profile
                    await this.mProfilesCache.getTeamConfig().reload();
                } else {
                    // For manually created profiles, use normal Config API
                    if (!configApi.profiles.defaultGet("ssh") || !configApi.layers.get().properties.defaults.ssh)
                        configApi.profiles.defaultSet("ssh", selectedConfig.name!);
                    configApi.profiles.set(selectedConfig.name!, config);
                }
            }
        }

        // Save/write for profiles that are NOT from SSH config and NOT using SSH agent
        // (i.e., manually created profiles with password authentication)
        if (!shouldWriteToGlobal) {
            if (config.secure.length > 0) {
                await this.mProfilesCache.getTeamConfig().save();
            } else {
                this.mProfilesCache.getTeamConfig().api.layers.write();
            }
        }
    }

    private async getNewProfileName(
        selectedProfile: ISshConfigExt,
        configApi: Config,
    ): Promise<ISshConfigExt | undefined> {
        let isUniqueName = false;

        // If no name option set then use user@hostname with all "." replaced with "_"
        // This ensures unique profile names for different users on the same host
        if (!selectedProfile.name) {
            const hostPart = selectedProfile.hostname!.replace(/\./g, "_");
            const userPart = selectedProfile.user ? `${selectedProfile.user}_` : "";
            selectedProfile.name = `${userPart}${hostPart}`;
        }

        // If selectedProfile already has a name, return it unless an existing profile is found
        if (selectedProfile.name) {
            const existingProfile = configApi.layerActive().properties.profiles[selectedProfile.name];
            if (existingProfile) {
                const overwriteOpts: qpOpts = {
                    items: [{ label: "Yes" }, { label: "No" }],
                    placeholder: `A profile with the name "${selectedProfile.name}" already exists. Do you want to overwrite it?`,
                };

                const overwriteResponse = await this.showMenu(overwriteOpts);

                if (overwriteResponse === "Yes") return selectedProfile;
            } else return selectedProfile;
        }

        // If no name set or overwriting, proceed with the input loop
        while (!isUniqueName) {
            selectedProfile.name = await this.showInputBox({
                title: "Enter a name for the SSH config",
                value: selectedProfile.name!.replace(/\./g, "_"),
                validateInput: (input) => (input.includes(".") ? "Name cannot contain '.'" : null),
            });

            if (!selectedProfile.name) return;
            const existingProfile = configApi.layerActive().properties.profiles[selectedProfile.name];
            if (existingProfile) {
                const overwriteResponse = await this.showMenu({
                    items: [{ label: "Yes" }, { label: "No" }],
                    placeholder: `A profile with the name "${selectedProfile.name}" already exists. Do you want to overwrite it?`,
                });
                if (overwriteResponse === "Yes") {
                    isUniqueName = true;
                }
            } else {
                isUniqueName = true;
            }
        }
        return selectedProfile;
    }

    // Taken from ZE Api and tweaked for usage
    private getMergedAttrs(prof: string | IProfAttrs): IProfile {
        const profile: IProfile = {};
        if (prof !== null) {
            const mergedArgs = this.mProfilesCache.mergeArgsForProfile(
                typeof prof === "string"
                    ? this.mProfilesCache.getAllProfiles("ssh").find((p) => p.profName === prof)
                    : prof,
                { getSecureVals: true },
            );
            for (const arg of mergedArgs.knownArgs) {
                profile[arg.argName] = arg.argValue;
            }
        }
        return profile;
    }

    // Taken from ZE Api and tweaked for usage
    private fetchAllSshProfiles(): IProfileLoaded[] {
        const profByType: IProfileLoaded[] = [];
        const profilesForType = this.mProfilesCache.getAllProfiles("ssh");
        for (const prof of profilesForType) {
            profByType.push({
                message: "",
                name: prof.profName,
                type: "ssh",
                profile: this.getMergedAttrs(prof),
                failNotFound: false,
            });
        }
        return profByType;
    }

    // Taken from ZE Api and tweaked for usage
    private fetchDefaultProfile(): IProfileLoaded | undefined {
        const defaultProfile = this.mProfilesCache.getDefaultProfile("ssh");
        return defaultProfile
            ? {
                  message: "",
                  name: defaultProfile.profName,
                  type: "ssh",
                  profile: this.getMergedAttrs(defaultProfile),
                  failNotFound: false,
              }
            : undefined;
    }

    /**
     * Handle an invalid private key by commenting it out in the configuration file
     * and showing a warning to the user
     */
    private async handleInvalidPrivateKey(config: ISshConfigExt): Promise<boolean> {
        if (!config.privateKey || !config.name) {
            // Private key is not invalid if its missing
            return true;
        }

        try {
            // Get the team configuration object
            const teamConfig = this.mProfilesCache.getTeamConfig();

            if (teamConfig.properties.autoStore === false) {
                return true;
            }

            // Comment out the private key property using Config API and comment-json
            const commentedProperty = ConfigFileUtils.getInstance().commentOutProperty(
                teamConfig,
                config.name,
                "privateKey",
            );

            if (commentedProperty) {
                // Show warning to user with undo/delete options
                const shouldContinue = await this.showPrivateKeyWarning({
                    profileName: config.name,
                    privateKeyPath: config.privateKey,
                    onUndo: () => {
                        const success = ConfigFileUtils.getInstance().uncommentProperty(
                            teamConfig,
                            config.name,
                            commentedProperty,
                        );
                        if (success) {
                            this.showMessage(
                                `Private key has been restored for profile "${config.name}".`,
                                MESSAGE_TYPE.INFORMATION,
                            );
                        } else {
                            this.showMessage(
                                "Failed to restore private key. You may need to manually edit the configuration file.",
                                MESSAGE_TYPE.ERROR,
                            );
                        }
                    },
                    onDelete: () => {
                        const success = ConfigFileUtils.getInstance().deleteCommentedLine(
                            teamConfig,
                            config.name,
                            commentedProperty,
                        );
                        if (success) {
                            this.showMessage(
                                `Private key comment lines have been deleted from profile "${config.name}".`,
                                MESSAGE_TYPE.INFORMATION,
                            );
                        } else {
                            this.showMessage(
                                "Failed to delete private key comment lines. You may need to manually edit the configuration file.",
                                MESSAGE_TYPE.ERROR,
                            );
                        }
                    },
                });
                if (shouldContinue) {
                    const cachedProfile = this.sshProfiles.find((prof) => prof.name === config.name);
                    if (cachedProfile) {
                        cachedProfile.profile.privateKey = undefined;
                    }
                }
                return shouldContinue;
            }
        } catch (error) {
            console.error("Error handling invalid private key:", error);
            this.showMessage(
                "Failed to comment out invalid private key. You may need to manually edit the configuration file.",
                MESSAGE_TYPE.WARNING,
            );
        }

        return false;
    }
}

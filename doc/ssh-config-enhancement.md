# SSH Config Profile Enhancement

## Overview
Enhanced the Zowe-SSH extension to properly migrate and display SSH profiles from `~/.ssh/config` with their configured settings when using the "Connect to Host" command.

## Changes Made

### 1. Enhanced Profile Display (`packages/sdk/src/AbstractConfigManager.ts`)

#### Before
- SSH config profiles were shown in a "Migrate From SSH Config" section
- Only showed profiles that didn't already exist in Zowe team config (filtered list)
- Limited information displayed (just name and hostname)

#### After
- All SSH config profiles are now displayed in a dedicated "SSH Config Profiles (~/.ssh/config)" section
- Shows comprehensive profile information:
  - **User and hostname**: `user@hostname` or just `hostname`
  - **Port**: Displayed if non-standard (not 22)
  - **Private key**: Shows key filename with 🔑 icon (e.g., `🔑 id_ed25519`)
- Better organization with separate sections:
  - "Zowe SSH Profiles" - Existing profiles in team config
  - "SSH Config Profiles (~/.ssh/config)" - All profiles from SSH config

### 2. Menu Structure

The enhanced menu now displays:

```
$(plus) Add New SSH Host...
─────────────────────────────
Zowe SSH Profiles
─────────────────────────────
profile1                      hostname1.com
profile2                      hostname2.com
─────────────────────────────
SSH Config Profiles (~/.ssh/config)
─────────────────────────────
mainframe1                    user1@mainframe.example.com
mainframe2                    user2@mainframe.example.com • 🔑 id_ed25519
mainframe3                    user3@mainframe.example.com
```

### 3. Key Features

1. **Complete Visibility**: Users can now see ALL SSH config profiles, not just ones that haven't been migrated
2. **Rich Information**: Profile details include user, hostname, port, and private key information
3. **Visual Indicators**: Key icon (🔑) makes it easy to identify which profiles have SSH keys configured
4. **Better Organization**: Clear separation between Zowe profiles and SSH config profiles

### 4. Technical Details

The implementation:
- Reads all SSH config profiles using `SshConfigUtils.migrateSshConfig()`
- Displays them with formatted descriptions showing:
  - User@hostname format when user is specified
  - Port number if non-standard
  - Private key filename with icon
- Maintains backward compatibility with existing profile selection logic
- Properly handles profile matching when user selects an SSH config profile

## Benefits

1. **Improved User Experience**: Users can easily see what SSH profiles are available with their configurations
2. **Better Discoverability**: All SSH config profiles are visible, making it easier to select the right one
3. **Transparency**: Users can see which profiles have keys configured before selecting
4. **Consistency**: Follows the pattern of showing detailed information in VS Code quick pick menus

## Testing

To test the enhancement:

1. Ensure you have profiles configured in `~/.ssh/config`
2. Open VS Code with Zowe Explorer installed
3. Run the "Zowe-SSH: Connect to Host" command
4. Verify that:
   - All SSH config profiles are displayed
   - Profile details (user, hostname, port, key) are shown correctly
   - Selecting a profile works as expected
   - The 🔑 icon appears for profiles with IdentityFile configured

## Example SSH Config

```ssh
Host mainframe2
  HostName mainframe.example.com
  User user2
  IdentityFile /Users/username/.ssh/id_ed25519
  ForwardAgent yes
```

This will be displayed as:
```
mainframe2    user2@mainframe.example.com • 🔑 id_ed25519

### 2. Fixed SSH Config Parameter Preservation

**Critical Bug Fixes:**

1. **Secure Configuration Fix** (Line 627-650):
   - **Before**: Always marked `user`, `password`, and `keyPassphrase` as secure fields, even when using SSH keys
   - **After**: Only marks fields as secure based on authentication method:
     - SSH key auth: Only `keyPassphrase` is secure (if present)
     - Password auth: Only `password` is secure
   - This ensures SSH key configurations are properly stored without unnecessary secure field overhead

2. **Private Key Preservation Fix** (Line 220-227):
   - **Before**: Always cleared `privateKey` and `keyPassphrase` when validation returned any modifications
   - **After**: Only clears these fields when password authentication is actually used
   - This prevents losing SSH key configuration from `~/.ssh/config` during validation

3. **Complete Parameter Migration Fix** (Line 608-627):
   - **Before**: Only copied `privateKey` from matched SSH config profile
   - **After**: Copies ALL parameters from SSH config:
     - `user` - Username from SSH config
     - `privateKey` - SSH key path
     - `port` - Custom port (if specified)
     - `keyPassphrase` - Key passphrase (if present)
     - `handshakeTimeout` - Connection timeout
   - Ensures complete migration of SSH config settings to Zowe profile

### 3. Summary of Fixes

These fixes ensure that when migrating profiles from `~/.ssh/config`:
- ✅ All SSH config parameters are preserved (user, host, port, privateKey, etc.)
- ✅ SSH key authentication is properly configured (not replaced with password auth)
- ✅ Secure fields are correctly set based on authentication method
- ✅ Private keys from SSH config are not accidentally cleared during validation


### 4. Password Prompt Prevention Fix

**Problem**: When loading profiles from ~/.ssh/config that already have SSH keys configured, the system was still prompting for a password during validation.

**Root Cause**: The validation flow had a fallback that would ask for a password even when a private key was present from SSH config.

**Solution** (Line 214-220):
- Added logic to check if a private key is already present before asking for password
- If `selectedProfile.privateKey` exists, set `askForPassword = false`
- This prevents unnecessary password prompts when SSH key authentication is configured

**Code Change**:
```typescript
// Before:
this.validationResult = await this.validateConfig(this.selectedProfile);

// After:
const shouldAskForPassword = !this.selectedProfile.privateKey;
this.validationResult = await this.validateConfig(this.selectedProfile, shouldAskForPassword);
```

**Impact**: Users with SSH keys configured in ~/.ssh/config will no longer be prompted for passwords during profile setup.

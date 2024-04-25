# EVM HD Wallet SDK

The EVM HD Wallet SDK is a toolset that allows developers to work with hierarchical deterministic (HD) wallets on the EVMs blockchain. With this SDK, you can generate a master wallet and mnemonic using the `index.js` script, which produces an encrypted JSON file. This JSON file contains the necessary information to operate the HD wallet using the HDWalletSDK included in this SDK.

## Features

- **Generate Master Wallet and Mnemonic:** Use the `index.js` script to generate a random master wallet and mnemonic, which are then encrypted and saved as a JSON file.
  
- **HDWalletSDK Functionality:** The SDK provides functionalities to derive wallets from the master wallet using user IDs or UUIDs, send tokens (such as USDT) to specified addresses.

- **Demo Folder:** The SDK includes a demo folder with examples demonstrating the usage of each utility provided by the SDK. These demos serve as a guide for developers to understand and implement the SDK functionalities in their projects.

## Usage

1. **Generate Master Wallet:**
   - Config the `index.js` with your password and generation path and run the script to generate a random master wallet and mnemonic.
   - `index.js` script will generate a encrypted JSON file with the name and the path you chose (Default: './wallet.json') with the generated wallet information and show you its mnemonic phrase (save it carefully).

2. **Operate HD Wallet:**
   - Use the encrypted JSON file in your project to initialize the HDWalletSDK.
   - The HDWalletSDK constructor only asks the password and the JSON path , make sure to store your password in a secure .env file.
   - Utilize the SDK functionalities to derive wallets for your users and send tokens.

## Demos

Explore the demo folder to see practical examples of how to use each utility provided by the EVM HD Wallet SDK.

---

For detailed instructions and examples, refer to the demo folder and the provided documentation. Happy developing with EVM HD Wallet SDK!

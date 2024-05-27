const fs = require('fs');
const WalletGenerator = require('./WalletGenerator');

// Set your desired password and file path
const password = "p@$$word";

const customjsonFilePath = "./wallet.json";

// Generate a random wallet, mnemonic, and save as JSON
(async () => {
    const { publicKey,privateKey, mnemonic, jsonFilePath } = await WalletGenerator.generateRandomWallet(password,customjsonFilePath);

    // Remove the '0x' prefix from the public key if it exists
    const cleanedPublicKey = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;

    // Display the generated wallet mnemonic
    console.log("###############################################");
    console.log("Generated HDWallet Mnemonic (Seed Phrase):", mnemonic);
    console.log("Instructions: Save this mnemonic in a secure place. Do not share it with anyone.");
    console.log("Instructions: Your Password will be used to decrypt the json file and derive wallets, store it on a enviroment variable on your application.");
    console.log("Wallet saved as JSON:", jsonFilePath);
    console.log("###############################################");
    console.log("(optional) Hot Public Key:", cleanedPublicKey);
    console.log("(optional) Hot Private Key:", privateKey);
    console.log("Instructions: Optionally use above generated Hot Wallet for your platform, using this Public Key without 0x for encryption/decryption memo transmission, or if you already has one use its Public Key instead.");
    console.log("###############################################");
})();

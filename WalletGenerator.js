const ethers = require('ethers');
const fs = require('fs');

class WalletGenerator {
    static async generateRandomWallet(password, jsonFilePath = "./wallet.json") {
        const wallet = ethers.Wallet.createRandom();
        const mnemonic = wallet.mnemonic.phrase;

        const walletHot = ethers.Wallet.createRandom();
        
        // Get the public key and private key from walletHot
        const publicKey = walletHot.publicKey;
        const privateKey = walletHot.privateKey;

        // Save the wallet as JSON using the provided password and file path
        const json = await wallet.encrypt(password);
        fs.writeFileSync(jsonFilePath, JSON.stringify(json));

        return { publicKey,privateKey, mnemonic, jsonFilePath };
    }

    static async restoreWalletFromJson(json, password) {
        const encryptedJson = fs.readFileSync(json, 'utf8');

        // Parse the JSON content to ensure it's in the correct format
        const walletJson = await JSON.parse(encryptedJson);
        return ethers.Wallet.fromEncryptedJson(walletJson, password);
    }
}

module.exports = WalletGenerator;
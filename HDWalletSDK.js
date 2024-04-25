const ethers = require('ethers');
const fs = require('fs');
const crypto = require('crypto');

class HDWalletSDK {
    /**
     * Constructs the HDWalletSDK instance with the encrypted JSON and password.
     * @param {string} json The encrypted JSON representation of the wallet.
     * @param {string} password The password used for decrypting the JSON.
     */
    constructor(json = "./wallet.json", password) {
        this.json = json;
        this.password = password;
        this.senderSC = ""; // Your SmartContract provided by DigitalHorizon
        this.rpc = "https://polygon-rpc.com"; // Public RPC -- can use your own RPC if you like
        this.wssrpc = "wss://polygon.api.onfinality.io/public-ws"; // Public WebSocket RPC --  can use your own RPC for more performance and less rate limit
        this.derivationPath = "m/44'/60'/0'/0"; // Ethereum Addresses type HD derivation Path
    }

    /**
     * Restores the HD wallet from the encrypted JSON using the provided password.
     * @returns {Promise<ethers.Wallet>} A promise that resolves to the restored wallet.
     */
    async getHDWallet() {
        try {
            const encryptedJson = fs.readFileSync(this.json, 'utf8');
            // Parse the JSON content to ensure it's in the correct format
            const walletJson = await JSON.parse(encryptedJson);

            const wallet = ethers.Wallet.fromEncryptedJson(walletJson, this.password);

            return wallet;

        } catch (error) {
            console.error("Error decrypting JSON wallet:", error);
            throw error; // Rethrow the error to handle it in the calling code
        }
    }

    /**
     * Derives a wallet from the HD wallet using the specified ID and type.
     * @param {string} id The ID used for deriving the wallet.
     * @param {string} idType The type of ID (Sequential or UUID).
     * @returns {Promise<ethers.Wallet>} A promise that resolves to the derived wallet.
     */
    async deriveWalletFromID(id, idType = "Sequential") {
        let idWallet;
        if (idType === "Sequential") {
            idWallet = id;
        } else if (idType === "UUID") {
            idWallet = this.uuidToInteger(id);
        }

        const hdWallet = await this.getHDWallet();
        const mnemonic = hdWallet.mnemonic;
        const mnemonicWallet = ethers.utils.HDNode.fromMnemonic(mnemonic.phrase);
        const derivedWallet = mnemonicWallet.derivePath(this.derivationPath + "/" + idWallet);

        return derivedWallet;
    }

    /**
     * Converts a UUID to an integer for deriving a wallet.
     * @param {string} uuid The UUID to convert.
     * @returns {string} The converted integer.
     */
    uuidToInteger(uuid) {
        const hash = crypto.createHash('sha256').update(uuid).digest('hex');
        const bigInteger = BigInt('0x' + hash);
        const smallInteger = bigInteger % BigInt(999999999);
        return smallInteger.toString();
    }

    /**
      * Sends USDT tokens to the specified recipient using the provided wallet.
      * @param {ethers.Wallet} wallet The wallet used for sending the tokens.
      * @param {string} toAddress The recipient address.
      * @param {string} amount The amount of USDT tokens to send.
      * @returns {Promise<string>} A promise that resolves to the transaction hash.
      */
    async sendUsdt(wallet, toAddress, amount) {
        // Create a provider using the RPC URL
        const provider = new ethers.providers.JsonRpcProvider(this.rpc);

        // Create a signer from the wallet using the provider
        const signer = new ethers.Wallet(wallet.privateKey, provider);

        // Load the USDT contract ABI
        const usdtContractAbi = [
            // ABI methods for USDT contract, including the transfer function
            {
                "constant": false,
                "inputs": [
                    {
                        "name": "_to",
                        "type": "address"
                    },
                    {
                        "name": "_value",
                        "type": "uint256"
                    }
                ],
                "name": "transfer",
                "outputs": [
                    {
                        "name": "",
                        "type": "bool"
                    }
                ],
                "payable": false,
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ];

        // USDT contract address on polygon
        const contractAddress = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";

        // Create a contract instance for the USDT token
        const usdtContract = new ethers.Contract(contractAddress, usdtContractAbi, signer);

        // Send USDT tokens using the transfer function of the USDT contract
        const txResponse = await usdtContract.transfer(toAddress, ethers.utils.parseUnits(amount, 6)); // 6 decimal places for USDT
        // Check if the transaction was successful
        if (txResponse.hash) {
            // Transaction successful, wait for the receipt
            const receipt = await txResponse.wait();
            return { status: true, hash: receipt.transactionHash };
        } else {
            // Transaction failed, handle the error
            console.error("Transaction failed:", txResponse);
            return { status: false, error: txResponse };
        }
    }

}

module.exports = HDWalletSDK;

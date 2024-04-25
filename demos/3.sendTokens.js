const HDWalletSDK = require('../HDWalletSDK'); // loading SDK class

// Set the encrypted JSON representation of the wallet and the password

const jsonFilePath = "../wallet.json"; // your json file path
const password = "p@$$word"; // Usually loaded from env variable

// Create an instance of the HDWalletSDK
const hdWalletSDK = new HDWalletSDK(jsonFilePath, password);

// Example usage: Send USDT tokens using the provided wallet

const id = "33"; // your userId



const recipientAddress = "0xEceECabc68B5b8e15dAb510Cb90973a92c3e7D3F";
const amountToSend = "100"; // Amount of USDT tokens to send

(async () => {
    const userWallet = await hdWalletSDK.deriveWalletFromID(id);
    const result = await hdWalletSDK.sendUsdt(userWallet, recipientAddress, amountToSend);
    if(result.status == true){
      // Transaction was succesfull
      console.log("Transaction sent from: ", userWallet.address, " to ", recipientAddress)
      console.log("Transaction Hash:", result.hash);
    } else {
      // Transaction was failed
      console.log("Transaction Failed : ", result.error);
    }
})();
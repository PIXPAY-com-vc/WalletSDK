const HDWalletSDK = require('../HDWalletSDK'); // loading SDK class

// Set the encrypted JSON representation of the wallet and the password

const jsonFilePath = "../wallet.json"; // your json file path
const password = "p@$$word"; // Usually loaded from env variable

// Create an instance of the HDWalletSDK
const hdWalletSDK = new HDWalletSDK(jsonFilePath, password);

// Example usage: Restore the HD wallet from the encrypted JSON using the password
(async () => {
  const wallet = await hdWalletSDK.getHDWallet();
  console.log("Restored Wallet Address:", wallet.address); // first address
})();
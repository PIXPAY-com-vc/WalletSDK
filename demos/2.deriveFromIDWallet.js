const HDWalletSDK = require('../HDWalletSDK'); // loading SDK class

// Set the encrypted JSON representation of the wallet and the password

const jsonFilePath = "../wallet.json"; // your json file path
const password = "p@$$word"; // Usually loaded from env variable

// Create an instance of the HDWalletSDK
const hdWalletSDK = new HDWalletSDK(jsonFilePath, password);

// Example usage: Derive a wallet from the HD wallet using the specified ID and type
(async () => {
  const id = "33"; // your userId
  const derivedWallet = await hdWalletSDK.deriveWalletFromID(id);
  console.log("Derived ID Wallet Address:", derivedWallet.address);

  // UUID type
  const idUUID = "5c609021-ba85-4583-bc36-1ae2c2c4f3db"; // your userId in UUID db type
  const idType = "UUID";
  const derivedUUIDWallet = await hdWalletSDK.deriveWalletFromID(idUUID, idType);
  console.log("Derived UUID Wallet Address:", derivedUUIDWallet.address);
})();
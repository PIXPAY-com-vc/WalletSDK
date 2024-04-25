const ethers = require('ethers');
const fs = require('fs');
const splitter_ABIJSON = require('./splitter.json');

// Configuration

 const currentTimeFormatted = format(new Date(), 'yyyy-MM-dd HH:mm:ss');

// <><><> LOAD WALLET SDK <><><>
    const HDWalletSDK = require('../HDWalletSDK'); // loading SDK class

    // Set the encrypted JSON representation of the wallet and the password

    const jsonFilePath = "../wallet.json"; // your json file path
    const password = "p@$$word"; // Usually loaded from env variable

    // Create an instance of the HDWalletSDK
    const hdWalletSDK = new HDWalletSDK(jsonFilePath, password);
// <><><> LOAD WALLET SDK <><><>

// Public WebSocket RPC --  can use your own RPC for more performance and less rate limit
const websocketRPC = "wss://polygon.api.onfinality.io/public-ws";

const SPLITTER_CONTRACT_ADDRESS = ""; // Your SmartContract for Splitter provided by Digital Horizon

const smpWallet = "" // SmartPay verified Address
const hotWallet = "" // Platform HotWallet Address


// End Configuration

// Set the Provider
const provider = new ethers.providers.WebSocketProvider(websocketRPC);

// Set the ABI for decoding transaction data
abiDecoder.addABI(splitter_ABIJSON.abi);
// Set Contract for use
const splitterContractChecker = new ethers.Contract(SPLITTER_CONTRACT_ADDRESS, splitter_ABIJSON.abi, provider);


// Helper function to find a user whose derived wallet matches the 'to' address
const findMatchingUser = async (toAddress) => {
    const allUsers = await User.findAll(); // <-- example using typeORM , adapt the function to your database
    for (let user of allUsers) {
        const idType = "Sequential" // or "UUID"
        const derivedWallet = await hdWalletSDK.deriveWalletFromID(user.id, idType);
        if (toAddress.toLowerCase() === derivedWallet.address.toLowerCase()) {
            console.log(`Found matching user: ${user.id}`);
            return {user: user, userWallet: derivedWallet}; // Return the matching user
        }
    }
    return null; // Return null if no matching user is found
};

// Event handling logic
const handleEvent = async (event) => {
    console.log(`Handling new event: ${event.name}`);

    const { args } = event;
    const from = args[0];
    const to = args[1];
    const value = args[2];
    const memo = args[3];
    
    // Send tokens and update infos on user if 'to' address matches a user's derived wallet
    const matchingUser = await findMatchingUser(to);
    if (matchingUser) {
        const transactionHash = await hdWalletSDK.sendUsdt(matchingUser.userWallet, hotWallet, value.toString());
        console.log(`USDT transfer initiated from ${to} to ${hotWallet}: ${transactionHash}`);

        // Add logic to update user balance and perform any other actions for your database
        
        matchingUser.user.balance += parseInt(value.toString()); // Assuming 'balance' is a numeric field in your database

        await matchingUser.user.save(); // Save the updated user object to the database

    } else {
        console.log(`No matching user found for 'to' address: ${to}`);
    }

};

// Listen for events from your smart contract
const startEventListening = async () => {

    console.log(`Beggining listening to events at ${currentTimeFormatted}`);
    writeLogToFile(`Beggining listening to events at ${currentTimeFormatted}`);
  
    const currentBlock = await provider.getBlockNumber();
  
    console.log('current Block >> ', currentBlock);
  
    const filter = {
      address: splitterContractChecker.address, // Contract address
      topics: [
        ethers.utils.id('Payment(address,address,uint256,bytes)'), // Event signature
        ethers.utils.hexZeroPad(smpWallet, 32), // Indexed parameter (fromWallet)
        null, // Indexed parameter (toWallet)
        null, // Indexed parameter (Amount)
        null
      ]
    };
  
  
    // Listen for events matching the filter
    splitterContractChecker.provider.on(filter, (log) => {
      const event = splitterContractChecker.interface.parseLog(log);
      console.log('Transfer event detected on contract:', event);
      // Handle the event
      handleEvent(event);
    })
    
  };

  startEventListening();
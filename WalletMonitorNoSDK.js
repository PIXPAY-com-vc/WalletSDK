const ethers = require('ethers');
const fs = require('fs');
const splitter_ABIJSON = require('./splitter.json');

// Configuration

// Public WebSocket RPC --  can use your own RPC for more performance and less rate limit
const websocketRPC = "wss://polygon.api.onfinality.io/public-ws";

const currentTimeFormatted = format(new Date(), 'yyyy-MM-dd HH:mm:ss');

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


function sendUsdt(toAddress, amount) {
    // Create a provider using the RPC URL
    const provider = new ethers.providers.JsonRpcProvider("https://polygon-rpc.com");

    // Create a signer from the wallet using the provider
    const signer = new ethers.Wallet("your wallet privatekey", provider);

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
    const txResponse = usdtContract.transfer(toAddress, ethers.utils.parseUnits(amount, 6)); // 6 decimal places for USDT
    // Check if the transaction was successful
    if (txResponse.hash) {
        // Transaction successful, wait for the receipt
        const receipt = txResponse.wait();
        return { status: true, hash: receipt.transactionHash };
    } else {
        // Transaction failed, handle the error
        console.error("Transaction failed:", txResponse);
        return { status: false, error: txResponse };
    }
}

// Event handling logic
const handleEvent = async (event) => {
    console.log(`Handling new event: ${event.name}`);

    const { args } = event;
    const from = args[0];
    const to = args[1];
    const value = args[2];
    const memo = args[3];

    // Send tokens and update infos on user if 'to' address matches a user's  wallet

    // add logic to get your user Info based on [to] wallet for example  
    //
    //

    // Add logic to update user balance and perform any other actions for your database
    //
    //

    // send the token from user to hotwallet 
    sendUsdt(hotWallet,value);

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
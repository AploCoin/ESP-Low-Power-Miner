#include <Web3.h>
#include <WiFi.h>
#include <SHA3.h>
#include <ArduinoJson.h>

#define APLOCOIN_RPC

// WiFi credentials and contract details
const char* ssid = "drthrthd"; // Replace with your SSID
const char* password = "hrthdrth"; // Replace with your WiFi password
const char* rpcServer = "https://pub1.aplocoin.com"; // Replace with your RPC server
const char* privateKey = "hfrghdrthdrthdr"; // Replace with your private key
const char* walletAddress = "hdfhdfhdfghxfdg"; // Replace with your wallet address
const char* contractAddress = "0x0000000000000000000000000000000000001234"; // Replace with your contract address

// Conversion to std::string
const std::string walletAddressStr(walletAddress);
const std::string* walletAddressPtr = &walletAddressStr;

// Arbitrary, non-used data
long gas, gasPrice;

Web3 *web3;
SHA3_256 sha3_256;

const uint64_t DEFAULT_DIFFICULTY = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
const uint64_t BLOCK_REWARD = 10000000000;

// ABI for the smart contract
const char* abi = R"(
[
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "internalType": "address",
                "name": "owner",
                "type": "address"
            },
            {
                "indexed": true,
                "internalType": "address",
                "name": "spender",
                "type": "address"
            },
            {
                "indexed": false,
                "internalType": "uint256",
                "name": "value",
                "type": "uint256"
            }
        ],
        "name": "Approval",
        "type": "event"
    },
    {
        "anonymous": false,
        "inputs": [
            {
                "indexed": true,
                "internalType": "address",
                "name": "miner",
                "type": "address"
            },
            {
                "indexed": false,
                "internalType": "bytes32",
                "name": "nonce",
                "type": "bytes32"
            },
            {
                "indexed": false,
                "internalType": "uint256",
                "name": "prev_hash",
                "type": "uint256"
            }
        ],
        "name": "Mined",
        "type": "event"
    },
    {
        "inputs": [],
        "name": "BLOCK_REWARD",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "DEFAULT_DIFFICULTY",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "mine",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "owner",
                "type": "address"
            }
        ],
        "name": "miner_params",
        "outputs": [
            {
                "internalType": "uint256",
                "name": "last_block",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "current_difficulty",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "total_mined",
                "type": "uint256"
            },
            {
                "internalType": "uint256",
                "name": "prev_hash",
                "type": "uint256"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]
)";

struct MinerParams {
    uint64_t last_block;
    uint64_t current_difficulty;
    uint64_t total_mined;
    uint64_t prev_hash;
};

MinerParams minerParams;

void setup() {
    Serial.begin(115200);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(1000);
        Serial.println("Connecting to WiFi...");
    }
    Serial.println("Connected to WiFi");
}

void loop() {
    minerParams = getMinerParams();
    Serial.printf("Current Difficulty: %llu\n", minerParams.current_difficulty);
    Serial.printf("Total Mined: %llu\n", minerParams.total_mined);

    uint256_t balance256 = web3->EthGetBalance(walletAddressPtr);
    double balance = static_cast<double>(static_cast<uint64_t>(balance256));
    Serial.printf("Current Balance: %f\n", balance / 1e18);

    while (web3->EthBlockNumber() - minerParams.last_block < 20) {
        Serial.println("Too early for mining, waiting...");
        delay(5000);
    }

    uint64_t nonce = mineBlock();
    string txHash = sendMineTransaction(nonce);
    Serial.printf("Token mined and sent in transaction: %s\n", txHash.c_str());

    // Wait for transaction receipt
    if (waitForTransactionReceipt(txHash)) {
        Serial.println("Transaction confirmed.");
    } else {
        Serial.println("Transaction failed or reverted.");
    }

    delay(10000); // Delay before the next mining attempt
}

MinerParams getMinerParams() {
    // Call the contract function to get miner params
    std::string dataStr = "miner_params";
    std::string paramsJson = web3->EthCall(walletAddressPtr, contractAddress, gas, gasPrice, &dataStr, nullptr);
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, paramsJson.c_str());

    MinerParams params;
    params.last_block = doc["last_block"];
    params.current_difficulty = doc["current_difficulty"] ? doc["current_difficulty"] : DEFAULT_DIFFICULTY;
    params.total_mined = doc["total_mined"];
    params.prev_hash = doc["prev_hash"];
    return params;
}

uint64_t generateNonce() {
    return random(0, UINT64_MAX); // Generate a random nonce
}

uint64_t hashNonce(uint64_t nonce, const char* sender, uint64_t difficulty, uint64_t prev_hash, uint64_t total_mined) {
    // Prepare data for hashing
    uint8_t packedData[128]; // Adjust size as necessary
    // Pack data into packedData array
    memcpy(packedData, sender, 20); // Copy sender address (20 bytes)
    memcpy(packedData + 20, &nonce, sizeof(nonce)); // Copy nonce
    memcpy(packedData + 20 + sizeof(nonce), &difficulty, sizeof(difficulty)); // Copy difficulty
    memcpy(packedData + 20 + sizeof(nonce) + sizeof(difficulty), &prev_hash, sizeof(prev_hash)); // Copy prev_hash
    memcpy(packedData + 20 + sizeof(nonce) + sizeof(difficulty) + sizeof(prev_hash), &total_mined, sizeof(total_mined)); // Copy total_mined

    // Compute keccak256 hash
    uint8_t hash[32];
    sha3_256.reset();
    sha3_256.update(packedData, sizeof(packedData));
    sha3_256.finalize(hash, sizeof(hash));

    return *(uint64_t*)hash; // Convert hash to uint64_t
}

uint64_t mineBlock() {
    while (true) {
        uint64_t nonce = generateNonce();
        uint64_t hash_result = hashNonce(nonce, walletAddress, minerParams.current_difficulty, minerParams.prev_hash, minerParams.total_mined);

        if (hash_result < minerParams.current_difficulty) {
            minerParams.total_mined++;
            minerParams.last_block = web3->EthBlockNumber();
            minerParams.prev_hash = hash_result;
            return nonce;
        }
    }
}

string sendMineTransaction(uint64_t nonce) {
    // Prepare transaction data
    String nonceHex = String(nonce, HEX);
    // Manually construct the transaction data
    String transactionData = "{\"to\":\"" + String(contractAddress) + "\",\"from\":\"" + String(walletAddress) + "\",\"data\":\"0x" + nonceHex + "\"}";
    const char transactionDataCStr = transactionData.c_str();
    const std::string* transactionDataStdStr(transactionDataCStr);

    // Send the transaction
    string txHash = web3->EthSendSignedTransaction(transactionDataStdStr, transactionData.length());
    return txHash;
}

bool waitForTransactionReceipt(String txHash) {
    std::string txHashStd = txHash.c_str();
    unsigned long startTime = millis();
    while (millis() - startTime < 60000) { // Wait for up to 60 seconds
        string receiptJson = web3->EthGetTransactionReceipt(&txHashStd);
        DynamicJsonDocument doc(1024);
        deserializeJson(doc, receiptJson.c_str());
        
        if (doc["status"] == "0x1") {
            return true; // Transaction was successful
        } else if (doc["status"] == "0x0") {
            return false; // Transaction failed
        }
        delay(1000); // Check every second
    }
    return false; // Timeout
}
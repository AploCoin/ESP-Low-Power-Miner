#include <Web3.h>
#include <WiFi.h>
#include "Trezor/sha3.h"
#include "Trezor/ecdsa.h"
#include "Trezor/curves.h"
#include "Trezor/secp256k1.h"
#include <ArduinoJson.h>
#include <stdint.h>
#include <string>
#include <WiFiManager.h>
#include "esp_random.h"

// Contract details
const char* rpcServer = "https://pub1.aplocoin.com"; // Replace with your RPC server
const char* privateKey = "dfsfsdf"; // Replace with your private key
const char* walletAddress = "fsdfsdf"; // Replace with your wallet address
const char* contractAddress = "0x0000000000000000000000000000000000001234"; // Replace with your contract address

Web3 *web3;
WiFiManager wifiManager;

const uint64_t DEFAULT_DIFFICULTY = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
const uint64_t BLOCK_REWARD = 10000000000;

const ecdsa_curve *curve = &secp256k1;

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
    wifiManager.autoConnect("GAplo_Miner");
    web3 = new Web3(APLOCOIN_ID);
    Serial.println("Connected to WiFi");
}

void loop() {
    Serial.println("getMinerParams");
    minerParams = getMinerParams();
    Serial.printf("Current Difficulty: %llu\n", minerParams.current_difficulty);
    Serial.printf("Total Mined: %llu\n", minerParams.total_mined);

    Serial.println("EthGetBalance");
    // Conversion to std::string
    const std::string walletAddressStr(walletAddress);
    const std::string* walletAddressPtr = &walletAddressStr;
    uint256_t balance256 = web3->EthGetBalance(walletAddressPtr);
    double balance = static_cast<double>(static_cast<uint64_t>(balance256));
    Serial.printf("Current Balance: %f\n", balance / 1e18);

    while (web3->EthBlockNumber() - minerParams.last_block < 20) {
        Serial.println("Too early for mining, waiting...");
        delay(5000);
    }

    uint64_t nonce = mineBlock(minerParams);
    std::string txHash = sendMineTransaction(nonce);
    Serial.printf("Token mined and sent in transaction: %s\n", txHash.c_str());

    // Wait for transaction receipt
    if (waitForTransactionReceipt(String(txHash.c_str()))) {
        Serial.println("Transaction confirmed.");
    } else {
        Serial.println("Transaction failed or reverted.");
    }

    delay(20000); // Delay before the next mining attempt
}

MinerParams getMinerParams() {
    // Call the contract function to get miner params
    std::string dataStr = "miner_params";
    Serial.println("EthCall");
    // Conversion to std::string
    const std::string walletAddressStr(walletAddress);
    const std::string* walletAddressPtr = &walletAddressStr;
    std::string paramsJson = web3->EthCall(walletAddressPtr, contractAddress, &dataStr);
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, paramsJson.c_str());

    MinerParams params;
    params.last_block = doc["last_block"];
    params.current_difficulty = doc["current_difficulty"] ? doc["current_difficulty"] : DEFAULT_DIFFICULTY;
    params.total_mined = doc["total_mined"];
    params.prev_hash = doc["prev_hash"];
    return params;
}

// Generate a random nonce
uint64_t generateNonce() {
    uint64_t nonce = ((uint64_t)esp_random() << 32) | esp_random(); // Utilize the built-in ESP random number generator, esp_random() generates uint32_t so we combine two of them
    return nonce;
}

uint64_t hashNonce(uint64_t nonce, const char* sender, uint64_t difficulty, uint64_t prev_hash, uint64_t total_mined) {
    // Prepare data for hashing
    uint8_t packedData[148];

    // Pack data into packedData array
    memcpy(packedData, sender, 20); // Copy sender address (20 bytes)
    memcpy(packedData + 20, &nonce, sizeof(nonce)); // Copy nonce
    memcpy(packedData + 20 + sizeof(nonce), &difficulty, sizeof(difficulty)); // Copy difficulty
    memcpy(packedData + 20 + sizeof(nonce) + sizeof(difficulty), &prev_hash, sizeof(prev_hash)); // Copy prev_hash
    memcpy(packedData + 20 + sizeof(nonce) + sizeof(difficulty) + sizeof(prev_hash), &total_mined, sizeof(total_mined)); // Copy total_mined

    // Calculate the total size of packedData
    size_t dataSize = sizeof(packedData); // This is 148 bytes

    uint8_t hash[SHA3_256_DIGEST_LENGTH];

    SHA3_CTX ctx;
    sha3_256_Init(&ctx); // Initialize for SHA3-256
    sha3_Update(&ctx, packedData, dataSize); // Update with data
    sha3_Final(&ctx, hash); // Finalize the hash computation

    return *(uint64_t*)hash; // Convert hash to uint64_t
}

uint64_t mineBlock(MinerParams& params) {
    while (true) {
        uint64_t nonce = generateNonce();
        Serial.print("Generated nonce: ");
        Serial.println(nonce);
        uint64_t hash_result = hashNonce(nonce, walletAddress, params.current_difficulty, params.prev_hash, params.total_mined);
        Serial.print("Hash result: ");
        Serial.println(hash_result);

        if (hash_result < params.current_difficulty) {
            params.total_mined++;
            params.last_block = web3->EthBlockNumber();
            params.prev_hash = hash_result;
            return nonce;
        }
    }
}

// Function to convert hex string to byte array
void hexStringToByteArray(const char* hexString, uint8_t* byteArray, size_t byteArraySize) {
    for (size_t i = 0; i < byteArraySize; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

// Function to hash the transaction data using Keccak-256
String keccak256(const String& input) {
    uint8_t hash[SHA3_256_DIGEST_LENGTH];
    SHA3_CTX ctx;
    sha3_256_Init(&ctx); // Initialize for SHA3-256
    sha3_Update(&ctx, (const uint8_t*)input.c_str(), input.length()); // Update with data
    sha3_Final(&ctx, hash); // Finalize the hash computation

    // Convert hash to hex string
    String hashHex = "0x";
    for (int i = 0; i < SHA3_256_DIGEST_LENGTH; i++) {
        hashHex += String(hash[i], HEX);
    }
    return hashHex;
}

// Function to sign the transaction
String signTransaction(const String& transactionData, const char* privateKeyHex) {
    // Step 1: Hash the transaction data
    String hashHex = keccak256(transactionData);
    
    // Convert hash from hex string to byte array
    uint8_t hash[SHA3_256_DIGEST_LENGTH];
    hexStringToByteArray(hashHex.c_str() + 2, hash, SHA3_256_DIGEST_LENGTH); // Skip "0x"

    // Step 2: Prepare the signature buffer
    uint8_t signature[64]; // ECDSA signature (r, s)
    uint8_t recoveryId; // Recovery ID

    // Convert private key from hex string to byte array
    uint8_t privateKey[32]; // Private key should be 32 bytes
    hexStringToByteArray(privateKeyHex, privateKey, 32);

    // Step 3: Sign the hash with the private key
    if (ecdsa_sign_digest(curve, privateKey, hash, signature, &recoveryId, nullptr) != 0) {
        Serial.println("Failed to sign the transaction.");
        return "";
    }

    // Step 4: Construct the raw transaction
    String rawTransaction = transactionData + ",\"signature\":\"";
    for (int i = 0; i < 32; i++) {
        rawTransaction += String(signature[i], HEX);
    }
    for (int i = 0; i < 32; i++) {
        rawTransaction += String(signature[i + 32], HEX);
    }
    rawTransaction += String(recoveryId, HEX) + "\""; // Append recovery ID

    return rawTransaction;
}

String padLeft(const String& str, size_t length, char padChar) {
    String padded = str;
    while (padded.length() < length) {
        padded = padChar + padded; // Prepend the padding character
    }
    return padded;
}

// Function to encode ABI using the JSON ABI
String encodeABI(const char* functionName, const String& nonceHex) {
    // Parse the ABI
    DynamicJsonDocument doc(2048);
    deserializeJson(doc, abi); // Assuming 'abi' is your JSON ABI string

    // Find the function in the ABI
    String functionSelector = "";
    for (JsonObject function : doc.as<JsonArray>()) {
        if (function["name"] == functionName) {
            // Create the function signature
            String functionSignature = String(functionName) + "(uint256)";
            functionSelector = keccak256(functionSignature).substring(0, 10); // First 4 bytes
            break;
        }
    }

    // If the function is not found, return an empty string
    if (functionSelector == "") {
        Serial.println("Function not found in ABI.");
        return "";
    }

    // Encode the parameters (in this case, just the nonce)
    String encodedParams = "0x" + padLeft(nonceHex.substring(2), 64, '0'); // Pad to 32 bytes (64 hex characters)
    
    // Combine the function selector and parameters
    return functionSelector + encodedParams;
}

string sendMineTransaction(uint64_t nonce) {
    // Prepare nonce in hex format
    String nonceHex = String(nonce, HEX);
    nonceHex = "0x" + nonceHex; // Add '0x' prefix
    Serial.print("NonceHex: ");
    Serial.println(nonceHex);

    // Get current gas price
    long long int gasPrice = web3->EthGasPrice();
    Serial.print("Gas Price: ");
    Serial.println(gasPrice);

    // Get the latest nonce
    const std::string walletAddressStr(walletAddress);
    const std::string* walletAddressPtr = &walletAddressStr;
    uint64_t latestNonce = web3->EthGetTransactionCount(walletAddressPtr);
    Serial.print("Latest Nonce: ");
    Serial.println(latestNonce);

    // Set a fixed gas limit
    long long int gasEstimate = 21000; // Example for a simple transaction
    Serial.print("Gas Estimate: ");
    Serial.println(gasEstimate);

    // Construct the transaction data
    String transactionData = "{\"to\":\"" + String(contractAddress) + 
                             "\",\"from\":\"" + String(walletAddress) + 
                             "\",\"data\":\"" + encodeABI("mine", nonceHex) + 
                             "\",\"gas\":\"" + String(gasEstimate) + 
                             "\",\"gasPrice\":\"" + String(gasPrice) + 
                             "\",\"nonce\":\"" + String(latestNonce) + "\"}";

    Serial.print("Transaction data: ");
    Serial.println(transactionData);

    // Sign the transaction
    String signedTx = signTransaction(transactionData, privateKey);
    Serial.print("Signed Transaction: ");
    Serial.println(signedTx);

    // Send the signed transaction
    const char* signedTxCStr = signedTx.c_str();
    const std::string signedTxStdStr(signedTxCStr);
    Serial.print("SignedTx STD STR: ");
    Serial.println(signedTxStdStr.c_str());
    const std::string* signedTxStdStrPtr = &signedTxStdStr;
    string txHash = web3->EthSendSignedTransaction(signedTxStdStrPtr, signedTx.length());
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

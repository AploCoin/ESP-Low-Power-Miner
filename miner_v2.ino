#include <Web3.h>
#include <WiFi.h>
#include "Trezor/sha3.h"
#include "Trezor/ecdsa.h"
#include "Trezor/curves.h"
#include "Trezor/secp256k1.h"
#include <ArduinoJson.h>
#include <WiFiManager.h>
#include <stdint.h>
#include <string>
#include "esp_random.h"

// Contract details
const char* rpcServer = "https://pub1.aplocoin.com"; // Replace with your RPC server
const char* privateKey = "gdfhfhdrth"; // Replace with your private key
const char* walletAddress = "gtergesrge"; // Replace with your wallet address
const char* contractAddress = "0x0000000000000000000000000000000000001234"; // Replace with your contract address

Web3 *web3;
WiFiManager wifiManager;

const uint256_t DEFAULT_DIFFICULTY = uint256_t("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

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
    uint256_t last_block;
    uint256_t current_difficulty;
    uint256_t total_mined;
    uint256_t prev_hash;
};

MinerParams minerParams;

void setup() {
    Serial.begin(115200);
    wifiManager.autoConnect("GAplo_Miner");
    web3 = new Web3(APLOCOIN_ID);
    Contract.SetPrivateKey(privateKey);
    Serial.println("Connected to WiFi");
}

void loop() {
    minerParams = getMinerParams();
    Serial.printf("Current Difficulty: %s\n", minerParams.current_difficulty);
    Serial.printf("Total Mined: %s\n", minerParams.total_mined);

    uint256_t balance = web3->EthGetBalance(&std::string(walletAddress));
    double balanceN = static_cast<double>(static_cast<uint64_t>(balance));
    Serial.printf("Current Balance: %f\n", balanceN / 1e18);

    while (web3->EthBlockNumber() - minerParams.last_block < 20) {
        Serial.println("Too early for mining, waiting...");
        delay(5000);
    }

    uint256_t nonce = mineBlock();
    std::string txHash = sendMineTransaction(nonce);
    Serial.printf("Token mined and sent in transaction: %s\n", txHash.c_str());

    if (waitForTransactionReceipt(txHash)) {
        Serial.println("Transaction confirmed.");
    } else {
        Serial.println("Transaction failed or reverted.");
    }

    delay(20000); // Delay before the next mining attempt
}

MinerParams getMinerParams() {
    std::string paramsJson = web3->EthCall(&std::string(walletAddress), contractAddress, &std::string("miner_params"));
    DynamicJsonDocument doc(1024);
    deserializeJson(doc, paramsJson.c_str());

    MinerParams params;
    params.last_block = doc["last_block"];
    params.current_difficulty = doc["current_difficulty"] ? doc["current_difficulty"] : DEFAULT_DIFFICULTY;
    params.total_mined = doc["total_mined"];
    params.prev_hash = doc["prev_hash"];
    return params;
}

uint256_t generateNonce() {
    return uint256_t(esp_random()); // Generate a random nonce
}

uint256_t hashNonce(uint256_t nonce, const char* sender, uint256_t difficulty, uint256_t prev_hash, uint256_t total_mined) {
    uint8_t packedData[148];
    memcpy(packedData, sender, 20); // Copy sender address (20 bytes)
    memcpy(packedData + 20, &nonce, sizeof(nonce)); // Copy nonce
    memcpy(packedData + 20 + sizeof(nonce), &difficulty, sizeof(difficulty)); // Copy difficulty
    memcpy(packedData + 20 + sizeof(nonce) + sizeof(difficulty), &prev_hash, sizeof(prev_hash)); // Copy prev_hash
    memcpy(packedData + 20 + sizeof(nonce) + sizeof(difficulty) + sizeof(prev_hash), &total_mined, sizeof(total_mined)); // Copy total_mined

    uint8_t hash[ETHERS_KECCAK256_LENGTH];
    web3->Web3Sha3((const std::string*)packedData, hash); // Use the library's SHA3 function

    return *(uint256_t*)hash; // Convert hash to uint256_t
}

uint256_t mineBlock() {
    while (true ) {
        uint256_t nonce = generateNonce();
        Serial.print("Generated nonce: ");
        Serial.println(nonce);
        uint256_t hash_result = hashNonce(nonce, walletAddress, minerParams.current_difficulty, minerParams.prev_hash, minerParams.total_mined);
        Serial.print("Hash result: ");
        Serial.println(hash_result);

        if (hash_result < minerParams.current_difficulty) {
            minerParams.total_mined++;
            minerParams.last_block = web3->EthBlockNumber();
            minerParams.prev_hash = hash_result;
            return nonce;
        }
    }
}

std::string sendMineTransaction(uint256_t nonce) {
    String nonceHex = "0x" + String(nonce.toString().c_str());
    Serial.print("NonceHex: ");
    Serial.println(nonceHex);

    long long int gasPrice = web3->EthGasPrice();
    Serial.print("Gas Price: ");
    Serial.println(gasPrice);

    const std::string walletAddressStr(walletAddress);
    const std::string* walletAddressPtr = &walletAddressStr;
    uint256_t latestNonce = web3->EthGetTransactionCount(walletAddressPtr);
    Serial.print("Latest Nonce: ");
    Serial.println(latestNonce);

    long long int gasEstimate = 21000; // Example for a simple transaction
    Serial.print("Gas Estimate: ");
    Serial.println(gasEstimate);

    String data = encodeABI("mine", nonceHex);
    String signedTx = signTransaction(latestNonce, gasPrice, gasEstimate, contractAddress, walletAddress, data, privateKey);
    Serial.print("Signed Transaction: ");
    Serial.println(signedTx);

    if (signedTx.length() % 2 != 0) {
        signedTx += "0"; // Pad if necessary
    }

    const std::string signedTxStdStr(signedTx.c_str());
    std::string txHash = web3->EthSendSignedTransaction(&signedTxStdStr, signedTx.length());
    Serial.print("txHash: ");
    Serial.println(txHash.c_str());
    return txHash;
}

bool waitForTransactionReceipt(const std::string& txHash) {
    unsigned long startTime = millis();
    while (millis() - startTime < 60000) { // Wait for up to 60 seconds
        std::string receiptJson = web3->EthGetTransactionReceipt(&txHash);
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

String encodeABI(const char* functionName, const String& nonceHex) {
    DynamicJsonDocument doc(2048);
    deserializeJson(doc, abi); // Assuming 'abi' is your JSON ABI string

    String functionSelector = "";
    for (JsonObject function : doc.as<JsonArray>()) {
        if (function["name"] == functionName) {
            String functionSignature = String(functionName) + "(uint256)";
            functionSelector = web3->Web3Sha3(&functionSignature).substr(0, 10); // First 4 bytes
            break;
        }
    }

    if (functionSelector == "") {
        Serial.println("Function not found in ABI.");
        return "";
    }

    String encodedParams = "0x" + padLeft(nonceHex.substring(2), 64, '0'); // Pad to 32 bytes (64 hex characters)
    return functionSelector + encodedParams;
}

String padLeft(const String& str, size_t length, char padChar) {
    String padded = str;
    while (padded.length() < length) {
        padded = padChar + padded; // Prepend the padding character
    }
    return padded;
}

String signTransaction(uint256_t nonce, long long int gasPrice, long long int gasLimit, const char* to, const char* from, const String& data, const char* privateKeyHex) {
    String nonceHex = padLeft(String(nonce.toString().c_str(), HEX), 64, '0');
    String gasPriceHex = padLeft(String(gasPrice, HEX), 64, '0');
    String gasLimitHex = padLeft(String(gasLimit, HEX), 64, '0');
    String valueHex = "0x0"; // Value is 0 for contract calls
    String toHex = to; // To address
    String dataHex = data; // Data
    String transactionData = 
        nonceHex + 
        gasPriceHex + 
        gasLimitHex + 
        toHex + 
        valueHex + 
        dataHex;

    String hashHex = web3->Web3Sha3(&transactionData);
    
    uint8_t hash[SHA3_256_DIGEST_LENGTH];
    hexStringToByteArray(hashHex.c_str() + 2, hash, SHA3_256_DIGEST_LENGTH); // Skip "0x"

    uint8_t signature[64]; // ECDSA signature (r, s)
    uint8_t recoveryId; // Recovery ID

    uint8_t privateKey[32]; // Private key should be 32 bytes
    hexStringToByteArray(privateKeyHex, privateKey, 32);

    if (ecdsa_sign_digest(curve, privateKey, hash, signature, &recoveryId, nullptr) != 0) {
        Serial.println("Failed to sign the transaction.");
        return "";
    }

    String signedTransaction = 
        "0x" + nonceHex + 
        gasPriceHex + 
        gasLimitHex + 
        toHex + 
        valueHex + 
        dataHex + 
        String(signature[0], HEX) + 
        String(signature[1], HEX) + 
        String(recoveryId + 27, HEX); // Adjust recovery ID for Ethereum

    return signedTransaction;
}

void hexStringToByteArray(const char* hexString, uint8_t* byteArray, size_t byteArraySize) {
    for (size_t i = 0; i < byteArraySize; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

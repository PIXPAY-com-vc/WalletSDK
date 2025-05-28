<?php
// Necessary Dependencies - install via Composer:
// composer require web3p/web3.php web3p/ethereum-tx kornrunner/keccak bitwasp/bitcoin-lib simplito/elliptic-php furqansiddiqui/bip39-mnemonic-php fgrosse/phpasn1

use Web3\Web3;
use Web3\Contract;
use Web3\Providers\HttpProvider;
use Web3\RequestManagers\HttpRequestManager;
use Web3\Utils;
use kornrunner\Keccak;
use BitWasp\Bitcoin\Mnemonic\Bip39\Bip39SeedGenerator;
use BitWasp\Bitcoin\Mnemonic\MnemonicFactory;
use BitWasp\Bitcoin\Key\Factory\HierarchicalKeyFactory as HKFactory;
use BitWasp\Bitcoin\Network\NetworkFactory;
use Elliptic\EC;
use Web3p\EthereumTx\Transaction;

class HDWalletSDK {
    private $json;
    private $password;
    private $senderSC;
    private $rpc;
    private $wssrpc;
    private $derivationPath;
    private $web3;

    public function __construct($json = "./wallet.json", $password = null) {
        $this->json = $json;
        $this->password = $password;
        $this->senderSC = "";
        $this->rpc = "https://polygon-rpc.com";
        $this->wssrpc = "wss://polygon.api.onfinality.io/public-ws";
        $this->derivationPath = "m/44'/60'/0'/0";
        $this->web3 = new Web3(new HttpProvider(new HttpRequestManager($this->rpc, 30)));
        
        Bitcoin::setNetwork(\BitWasp\Bitcoin\Network\NetworkFactory::bitcoin());
    }

    public function getHDWallet() {
        $this->validatePassword();
        
        try {
            if (!file_exists($this->json)) {
                throw new Exception("Wallet file not found: " . $this->json);
            }
            
            $encryptedJson = file_get_contents($this->json);
            $walletJson = json_decode($encryptedJson, true);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("Invalid JSON format: " . json_last_error_msg());
            }

            return $this->decryptKeystore($walletJson, $this->password);
            
        } catch (Exception $e) {
            throw new Exception("Wallet decryption failed: " . $e->getMessage());
        }
    }

    private function decryptKeystore($keystore, $password) {
        $this->validateKeystoreStructure($keystore);
        
        $kdf = $keystore['crypto']['kdf'];
        $ciphertext = hex2bin($keystore['crypto']['ciphertext']);
        $iv = hex2bin($keystore['crypto']['cipherparams']['iv']);
        $mac = $keystore['crypto']['mac'];
        $params = $keystore['crypto']['kdfparams'];
        $salt = hex2bin($params['salt']);

        $derivedKey = match($kdf) {
            'pbkdf2' => $this->pbkdf2(
                $params['prf'],
                $password,
                $salt,
                $params['c'],
                $params['dklen']
            ),
            'scrypt' => $this->scrypt(
                $password,
                $salt,
                $params['n'],
                $params['r'],
                $params['p'],
                $params['dklen']
            ),
            default => throw new Exception("Unsupported KDF: $kdf")
        };

        $this->validateMac($derivedKey, $ciphertext, $mac);
        
        $privateKey = openssl_decrypt(
            $ciphertext,
            str_replace('-', '/', $keystore['crypto']['cipher']),
            substr($derivedKey, 0, 16),
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($privateKey === false) {
            throw new Exception("Decryption failed: " . openssl_error_string());
        }

        return [
            'privateKey' => bin2hex($privateKey),
            'address' => $this->privateKeyToAddress($privateKey),
            'mnemonic' => [
                'phrase' => $keystore['x-ethers']['mnemonic']['phrase'] ?? null
            ]
        ];
    }

  public function createHDWallet($password, $path = "./wallet.json") {
        try {
            $bip39 = MnemonicFactory::bip39();
            $entropy = random_bytes(16);
            $mnemonic = $bip39->entropyToMnemonic($entropy);
            
            $seedGenerator = new Bip39SeedGenerator();
            $seed = $seedGenerator->getSeed($mnemonic);
            
            Bitcoin::setNetwork(NetworkFactory::bitcoin());
            $master = HKFactory::fromEntropy($seed);
            
            $privateKey = $master->derivePath("m/44'/60'/0'/0/0")
                ->getPrivateKey()
                ->getHex();
            
            $privateKey = str_replace('0x', '', $privateKey);
            $address = $this->privateKeyToAddress(hex2bin($privateKey));
            
            $wallet = [
                'privateKey' => $privateKey,
                'address' => $address,
                'mnemonic' => ['phrase' => $mnemonic],
                'path' => "m/44'/60'/0'/0/0"
            ];
            
            $keystore = $this->encryptToKeystore($wallet, $password);
            $keystore['x-ethers'] = [
                'mnemonic' => [
                    'phrase' => $mnemonic,
                    'path' => "m/44'/60'/0'/0/0",
                    'locale' => 'en'
                ],
                'version' => '0.1'
            ];
            
            file_put_contents($path, json_encode($keystore, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            chmod($path, 0600);
            
            return $wallet;
            
        } catch (Exception $e) {
            throw new Exception("Wallet creation failed: " . $e->getMessage());
        }
    }

    private function encryptToKeystore($wallet, $password) {
        $salt = random_bytes(32);
        $iv = random_bytes(16);
        $derivedKey = $this->pbkdf2('hmac-sha256', $password, $salt, 262144, 32);
        
        $ciphertext = openssl_encrypt(
            hex2bin($wallet['privateKey']),
            'aes-128-ctr',
            substr($derivedKey, 0, 16),
            OPENSSL_RAW_DATA,
            $iv
        );
        
        return [
            'version' => 3,
            'id' => $this->generateUUID(),
            'address' => strtolower(substr($wallet['address'], 2)),
            'crypto' => [
                'ciphertext' => bin2hex($ciphertext),
                'cipherparams' => ['iv' => bin2hex($iv)],
                'cipher' => 'aes-128-ctr',
                'kdf' => 'pbkdf2',
                'kdfparams' => [
                    'dklen' => 32,
                    'salt' => bin2hex($salt),
                    'c' => 262144,
                    'prf' => 'hmac-sha256'
                ],
                'mac' => Keccak::hash(substr($derivedKey, 16, 16) . $ciphertext, 256)
            ]
        ];
    }

    public function deriveWalletFromID($id, $idType = "Sequential") {
        $hdWallet = $this->getHDWallet();
        $mnemonic = $hdWallet['mnemonic']['phrase'] ?? null;
        
        if (!$mnemonic) {
            throw new Exception("Mnemonic phrase required for derivation");
        }
        
        try {
            $seed = (new Bip39SeedGenerator())->getSeed($mnemonic);
            $master = (new HKFactory())->fromEntropy($seed);
            
            $path = match($idType) {
                'Sequential' => $this->derivationPath . "/{$id}",
                'UUID' => $this->derivationPath . "/" . $this->uuidToInteger($id),
                default => throw new Exception("Invalid ID type: {$idType}")
            };
            
            $privateKey = $master->derivePath($path)
                ->getPrivateKey()
                ->getHex();
            
            return [
                'privateKey' => str_replace('0x', '', $privateKey),
                'address' => $this->privateKeyToAddress(hex2bin($privateKey)),
                'path' => $path
            ];
            
        } catch (Exception $e) {
            throw new Exception("Derivation failed: " . $e->getMessage());
        }
    }

    public function sendUsdt($wallet, $toAddress, $amount) {
        $this->validateAddress($toAddress);
        
        try {
            $contractAddress = "0xc2132D05D31c914a87C6611C10748AEb04B58e8F";
            $usdtAbi = '[{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"type":"function"}]';
            
            $contract = new Contract($this->web3->provider, $usdtAbi);
            $amountWei = bcmul($amount, '1000000');
            
            $txData = null;
            $contract->at($contractAddress)->getData('transfer', $toAddress, $amountWei, function ($err, $data) use (&$txData) {
                if ($err) throw new Exception("Contract error: " . $err->getMessage());
                $txData = $data;
            });
            
            $txParams = [
                'from' => $wallet['address'],
                'to' => $contractAddress,
                'data' => $txData,
                'chainId' => 137
            ];
            
            $this->web3->eth->gasPrice(function ($err, $price) use (&$txParams) {
                if ($err) throw new Exception("Gas price error: " . $err->getMessage());
                $txParams['gasPrice'] = Utils::toHex($price->toString(), true);
            });
            
            $this->web3->eth->getTransactionCount($wallet['address'], function ($err, $count) use (&$txParams) {
                if ($err) throw new Exception("Nonce error: " . $err->getMessage());
                $txParams['nonce'] = Utils::toHex($count->toString(), true);
            });
            
            $contract->at($contractAddress)->estimateGas('transfer', $toAddress, $amountWei, [
                'from' => $wallet['address']
            ], function ($err, $gas) use (&$txParams) {
                if ($err) throw new Exception("Gas estimate error: " . $err->getMessage());
                $txParams['gas'] = Utils::toHex($gas->toString(), true);
            });
            
            $signedTx = $this->signTransaction($txParams, $wallet['privateKey']);
            
            $txHash = null;
            $this->web3->eth->sendRawTransaction('0x' . $signedTx, function ($err, $hash) use (&$txHash) {
                if ($err) throw new Exception("Send error: " . $err->getMessage());
                $txHash = $hash;
            });
            
            return $this->waitForTransaction($txHash);
            
        } catch (Exception $e) {
            throw new Exception("USDT transfer failed: " . $e->getMessage());
        }
    }

    private function signTransaction($txParams, $privateKey) {
        $transaction = new Transaction([
            'nonce' => $txParams['nonce'],
            'gasPrice' => $txParams['gasPrice'],
            'gasLimit' => $txParams['gas'],
            'to' => $txParams['to'],
            'value' => '0x0',
            'data' => $txParams['data'],
            'chainId' => $txParams['chainId']
        ]);
        
        return $transaction->sign($privateKey);
    }

    private function privateKeyToAddress($privateKey) {
        $ec = new EC('secp256k1');
        $key = $ec->keyFromPrivate(bin2hex($privateKey));
        $publicKey = hex2bin(substr($key->getPublic(false, 'hex'), 2));
        return '0x' . substr(Keccak::hash($publicKey, 256), -40);
    }

    private function uuidToInteger($uuid) {
        if (!preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $uuid)) {
            throw new Exception("Invalid UUID format");
        }
        
        $hash = hash('sha256', $uuid);
        return hexdec(substr($hash, 0, 15)) % 999999999;
    }

    private function generateUUID() {
        $data = random_bytes(16);
        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }

    private function pbkdf2($algo, $password, $salt, $iterations, $length) {
        $algo = str_replace('hmac-', '', $algo);
        return hash_pbkdf2($algo, $password, $salt, $iterations, $length, true);
    }

    private function scrypt($password, $salt, $n, $r, $p, $keyLength) {
        if (!function_exists('scrypt')) {
            throw new Exception("Scrypt requires PECL scrypt extension");
        }
        
        $derivedKey = scrypt($password, $salt, $n, $r, $p, $keyLength);
        if ($derivedKey === false) {
            throw new Exception("Scrypt key derivation failed");
        }
        return $derivedKey;
    }

    private function validatePassword() {
        if ($this->password === null || strlen($this->password) < 8) {
            throw new Exception("Invalid password: Minimum 8 characters required");
        }
    }

    private function validateKeystoreStructure($keystore) {
        $required = [
            'version', 'id', 'address', 'crypto',
            'crypto.ciphertext', 'crypto.cipherparams.iv',
            'crypto.mac', 'crypto.kdf', 'crypto.kdfparams'
        ];
        
        foreach ($required as $field) {
            $keys = explode('.', $field);
            $current = $keystore;
            foreach ($keys as $key) {
                if (!isset($current[$key])) {
                    throw new Exception("Invalid keystore: missing $field");
                }
                $current = $current[$key];
            }
        }
    }

    private function validateMac($derivedKey, $ciphertext, $expectedMac) {
        $macKey = substr($derivedKey, 16, 16);
        $actualMac = Keccak::hash($macKey . $ciphertext, 256);
        
        if (!hash_equals($actualMac, $expectedMac)) {
            throw new Exception("MAC validation failed - possible password mismatch");
        }
    }

    private function validatePasswordStrength($password) {
        if (strlen($password) < 12) {
            throw new Exception("Password must be at least 12 characters");
        }
        
        if (!preg_match('/[\d]/', $password)) {
            throw new Exception("Password must contain at least one number");
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            throw new Exception("Password must contain at least one uppercase letter");
        }
    }

    private function waitForTransaction($txHash, $timeout = 180) {
        $startTime = time();
        $receipt = null;
        
        while (time() - $startTime < $timeout) {
            $this->web3->eth->getTransactionReceipt($txHash, function ($err, $result) use (&$receipt) {
                if (!$err && $result !== null) {
                    $receipt = $result;
                }
            });
            
            if ($receipt !== null) {
                return $this->processReceipt($receipt, $txHash);
            }
            sleep(5);
        }
        
        throw new Exception("Transaction confirmation timeout: $txHash");
    }

    private function processReceipt($receipt, $txHash) {
        if (!isset($receipt->status)) {
            return [
                'status' => 'pending',
                'hash' => $txHash,
                'message' => 'Transaction mined but no status available'
            ];
        }
        
        $status = hexdec($receipt->status);
        return $status === 1 
            ? ['status' => true, 'hash' => $txHash]
            : ['status' => false, 'hash' => $txHash, 'error' => 'Transaction reverted'];
    }

    private function validateAddress($address) {
        if (!preg_match('/^0x[a-fA-F0-9]{40}$/', $address)) {
            throw new Exception("Invalid Ethereum address format");
        }
        
        $checksumAddress = $this->toChecksumAddress($address);
        if ($checksumAddress !== $address) {
            throw new Exception("Address checksum mismatch");
        }
    }

    private function toChecksumAddress($address) {
        $address = strtolower($address);
        $hash = Keccak::hash($address, 256);
        $checksum = '';
        
        for ($i = 0; $i < 40; $i++) {
            $char = $address[$i+2];
            $hashByte = hexdec($hash[$i]);
            $checksum .= ($hashByte >= 8) ? strtoupper($char) : $char;
        }
        
        return '0x' . $checksum;
    }
}

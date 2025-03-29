#include <Arduino.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <string.h>

// Global objects for random number generation
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_entropy_context entropy;

// Global buffer for the generated AES key (32 bytes for AES-256)
unsigned char aesKey[32];

// Example Initialization Vector (IV) for CBC mode (16 bytes)
unsigned char iv[17] = "fedcba0987654321"; // Example IV; in production, generate a fresh IV for each encryption

// Personalization string for the CTR_DRBG
char *pers = "sensor-encryption";

// Utility function to print data in hexadecimal format
void printHex(const unsigned char *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    char hexStr[3]; // two hex digits + null terminator
    sprintf(hexStr, "%02x", data[i]);
    Serial.print(hexStr);
  }
  Serial.println();
}

// Generate a 32-byte AES key using Mbed TLS's entropy and CTR_DRBG
void generateAESKey()
{
  int ret;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (unsigned char *)pers, strlen(pers));
  if (ret != 0)
  {
    Serial.print("Failed to seed CTR_DRBG, error: 0x");
    Serial.println(-ret, HEX);
    return;
  }

  ret = mbedtls_ctr_drbg_random(&ctr_drbg, aesKey, sizeof(aesKey));
  if (ret != 0)
  {
    Serial.print("Failed to generate random key, error: 0x");
    Serial.println(-ret, HEX);
    return;
  }
}

// Encrypt data using AES-CBC mode
// Note: 'length' must be a multiple of 16 bytes.
void encrypt_sensor_data(const unsigned char *input, unsigned char *output, size_t length)
{
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  // Use the generated key for AES-256 (256 bits = 32 bytes)
  mbedtls_aes_setkey_enc(&aes, aesKey, 256);

  // Encrypt using AES-CBC mode with the provided IV
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);

  mbedtls_aes_free(&aes);
}

void setup()
{
  Serial.begin(115200);
  while (!Serial)
  {
    ; // Wait for Serial port to initialize
  }

  Serial.println("Generating AES key using Mbed TLS CTR_DRBG...");
  generateAESKey();

  Serial.print("Generated AES Key (hex): ");
  printHex(aesKey, sizeof(aesKey));

  // Example sensor data: exactly 16 bytes (for simplicity)
  unsigned char sensorData[16] = "sensor_reading!"; // 16 characters
  unsigned char encryptedData[16] = {0};

  // Encrypt the sensor data using the generated AES key
  encrypt_sensor_data(sensorData, encryptedData, sizeof(sensorData));

  Serial.print("Encrypted sensor data (hex): ");
  printHex(encryptedData, sizeof(encryptedData));

  // Clean up the CTR_DRBG and entropy contexts
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

void loop()
{
  // Nothing to do in loop
}

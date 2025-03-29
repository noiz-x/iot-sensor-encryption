#include <Arduino.h>
#include "mbedtls/aes.h"
#include <string.h>

// Define a 16-byte key for AES-128 and a 16-byte IV
const unsigned char key[17] = "1234567890abcdef"; // 16 bytes key
unsigned char iv[17] = "fedcba0987654321";        // 16 bytes IV

// Function to encrypt a data block (length must be a multiple of 16 bytes)
void encrypt_sensor_data(const unsigned char *input, unsigned char *output, size_t length)
{
  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);

  // Set encryption key (128 bits)
  mbedtls_aes_setkey_enc(&aes, key, 256);

  // Encrypt using AES-CBC mode. Note: 'length' must be a multiple of 16.
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iv, input, output);

  mbedtls_aes_free(&aes);
}

// Function to print binary data as a hexadecimal string
void print_encrypted_data(const unsigned char *data, size_t len)
{
  for (size_t i = 0; i < len; i++)
  {
    char hexStr[3]; // 2 hex digits + null terminator
    sprintf(hexStr, "%02x", data[i]);
    Serial.print(hexStr);
  }
  Serial.println();
}

void setup()
{
  Serial.begin(115200);
  // Wait for Serial to initialize (necessary on some boards)
  while (!Serial)
  {
  }

  // Sensor data must be exactly 16 bytes.
  // "sensor_reading!" is 16 characters.
  unsigned char sensor_data[16] = "sensor_reading!";
  unsigned char encrypted_data[16] = {0};

  // Encrypt the sensor data
  encrypt_sensor_data(sensor_data, encrypted_data, sizeof(sensor_data));

  // Print the encrypted data as a hexadecimal string
  Serial.println("Encrypted data (hex):");
  print_encrypted_data(encrypted_data, sizeof(encrypted_data));
}

void loop()
{
  // Nothing to do here; encryption is done in setup.
}


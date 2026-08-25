/*
  SecureVault - ESP32 firmware (v2)
  ------------------------------------
  Hardware: ESP32 + SD card module (SPI)

  PROTOCOL DESIGN NOTE (read this first):
  Every line the firmware deliberately emits as a protocol message - boot
  status, and every reply to a command - is prefixed with "VLT:". Nothing
  else the ESP32 ever prints (boot-ROM diagnostic spew after reset, or the
  character-by-character echo of what you type in a terminal) ever starts
  with that prefix. A client only needs to filter for lines starting with
  "VLT:" and can safely ignore everything else, no matter how much boot
  noise or echoed input shows up in between. This replaces an earlier
  design that tried to guess which of the next N lines was the "real"
  reply, which broke whenever boot-ROM chatter got mixed in.

  Serial settings: 115200 baud, newline-terminated commands.

  Boot sequence (always exactly these 3 lines, in this order, each
  prefixed):
    VLT:BOOT
    VLT:READY            (or VLT:SDFAIL if the SD card didn't init)
    VLT:VERSION:2.0

  Commands:
    PING                              -> VLT:PONG
                                          (works even while locked - lets a
                                          client check the device is alive)
    UNLOCK:<masterPassword>           -> First ever UNLOCK sets this as the
                                          master password (VLT:OK:INITIALIZED).
                                          After that: VLT:OK if correct,
                                          VLT:FAIL:BADPASSWORD if not.
    LOCK                              -> VLT:OK
    SAVE:<domain>|<username>|<password>
                                       -> Adds a new account for that site, or
                                          updates the password if that exact
                                          domain+username already exists.
                                          Different usernames on the same
                                          domain are kept as separate accounts.
                                          VLT:OK, VLT:FAIL:BADCHARS (domain or
                                          username contains | or ;),
                                          VLT:FAIL:TOOLONG, VLT:FAIL:BADFORMAT,
                                          or VLT:FAIL:WRITE.
    GET:<domain>                      -> VLT:<user1>|<pass1>;<user2>|<pass2>...
                                          or VLT:NOTFOUND
    LIST                              -> VLT:<domain1>;<domain2>;...
                                          (one entry per site, not per account)
    DELETE:<domain>|<username>        -> VLT:OK or VLT:NOTFOUND

  Any command other than PING/UNLOCK/LOCK while locked -> VLT:FAIL:LOCKED
  Unknown command                     -> VLT:FAIL:UNKNOWNCMD

  Unsolicited (not a reply to anything the client sent):
    VLT:LOCKED:TIMEOUT                -> auto-locked after 5 min idle

  Vault file: /vault.db on SD card. One record per line:
    domain|username|iv_hex|tag_hex|ciphertext_hex

  NOTE:
  - Master key derivation uses PBKDF2-HMAC-SHA256 (10,000 iterations) with a
    random per-vault salt in /salt.bin, checked against an encrypted marker
    in /check.bin before UNLOCK succeeds - so a wrong master password is
    actually rejected, not silently accepted.
  - Confirmation (re-entering the master password before view/edit/delete)
    is expected to happen on the web interface side before it ever sends
    SAVE/DELETE over serial. This firmware trusts whatever command it
    receives once unlocked - it does not re-ask for confirmation itself.
*/

#include <SPI.h>
#include <SD.h>
#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"

// ---------- SD card pins (adjust to your wiring) ----------
#define SD_CS_PIN   5
#define SD_SCK_PIN  18
#define SD_MISO_PIN 19
#define SD_MOSI_PIN 23

const char* VAULT_PATH = "/vault.db";
const char* TEMP_PATH  = "/vault.tmp";
const char* SALT_PATH  = "/salt.bin";
const char* CHECK_PATH = "/check.bin";
const char* CHECK_PLAINTEXT = "SECUREVAULT-OK";

#define SALT_LEN 16
#define PBKDF2_ITERATIONS 10000
#define MAX_FIELD_LEN 128
#define MAX_CMD_LEN 512
const unsigned long AUTO_LOCK_MS = 5UL * 60UL * 1000UL; // 5 minutes idle -> auto lock

// ---------- session state ----------
static uint8_t sessionKey[32];
static bool unlocked = false;
static unsigned long lastActivity = 0;

// small helper so every protocol line goes out with the same prefix
void reply(const String& payload) {
  Serial.print("VLT:");
  Serial.println(payload);
}

// =========================================================
// Helpers: hex encode/decode
// =========================================================
String toHex(const uint8_t* data, size_t len) {
  String out;
  out.reserve(len * 2);
  const char* hexChars = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out += hexChars[(data[i] >> 4) & 0xF];
    out += hexChars[data[i] & 0xF];
  }
  return out;
}

bool fromHex(const String& hex, uint8_t* out, size_t outLen) {
  if (hex.length() != outLen * 2) return false;
  for (size_t i = 0; i < outLen; i++) {
    char c1 = hex[i * 2];
    char c2 = hex[i * 2 + 1];
    auto val = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
    };
    int hi = val(c1), lo = val(c2);
    if (hi < 0 || lo < 0) return false;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return true;
}

// =========================================================
// Key derivation, salt, and master-password verification
// =========================================================
bool deriveKeyPBKDF2(const String& password, const uint8_t* salt, uint8_t* keyOut32) {
  int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                           (const unsigned char*)password.c_str(), password.length(),
                                           salt, SALT_LEN,
                                           PBKDF2_ITERATIONS,
                                           32, keyOut32);
  return ret == 0;
}

bool loadOrCreateSalt(uint8_t* saltOut) {
  File f = SD.open(SALT_PATH, FILE_READ);
  if (f && f.size() == (int)SALT_LEN) {
    f.read(saltOut, SALT_LEN);
    f.close();
    return true;
  }
  if (f) f.close();

  for (int i = 0; i < SALT_LEN; i++) saltOut[i] = (uint8_t)esp_random();
  File out = SD.open(SALT_PATH, FILE_WRITE);
  if (!out) return false;
  out.write(saltOut, SALT_LEN);
  out.close();
  return true;
}

bool vaultIsInitialized() {
  File f = SD.open(CHECK_PATH, FILE_READ);
  bool exists = (bool)f;
  if (f) f.close();
  return exists;
}

// forward declares (defined below, needed here because Arduino's
// auto-prototype insertion happens before these are otherwise visible)
bool aesGcmEncrypt(const uint8_t* key, const String& plaintext, uint8_t iv[12], uint8_t tag[16], String& cipherHexOut);
bool aesGcmDecrypt(const uint8_t* key, const uint8_t iv[12], const uint8_t tag[16], const String& cipherHex, String& plaintextOut);
bool splitFields(const String& line, String parts[], int count);

bool writeCheckValue(const uint8_t* key) {
  uint8_t iv[12], tag[16];
  String cipherHex;
  if (!aesGcmEncrypt(key, String(CHECK_PLAINTEXT), iv, tag, cipherHex)) return false;
  File f = SD.open(CHECK_PATH, FILE_WRITE);
  if (!f) return false;
  f.println(toHex(iv, 12) + "|" + toHex(tag, 16) + "|" + cipherHex);
  f.close();
  return true;
}

bool verifyCheckValue(const uint8_t* key) {
  File f = SD.open(CHECK_PATH, FILE_READ);
  if (!f) return false;
  String line = f.readStringUntil('\n');
  f.close();
  line.trim();

  String parts[3];
  if (!splitFields(line, parts, 3)) return false;
  if (parts[0].length() != 24 || parts[1].length() != 32) return false;

  uint8_t iv[12], tag[16];
  fromHex(parts[0], iv, 12);
  fromHex(parts[1], tag, 16);

  String plaintext;
  if (!aesGcmDecrypt(key, iv, tag, parts[2], plaintext)) return false;
  return plaintext == CHECK_PLAINTEXT;
}

// =========================================================
// AES-256-GCM encrypt / decrypt
// =========================================================
bool aesGcmEncrypt(const uint8_t* key, const String& plaintext,
                    uint8_t iv[12], uint8_t tag[16], String& cipherHexOut) {
  for (int i = 0; i < 12; i++) iv[i] = (uint8_t)esp_random();

  size_t len = plaintext.length();
  uint8_t* cipherBuf = (uint8_t*)malloc(len > 0 ? len : 1);
  if (!cipherBuf) return false;

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) { mbedtls_gcm_free(&gcm); free(cipherBuf); return false; }

  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len,
                                   iv, 12, nullptr, 0,
                                   (const unsigned char*)plaintext.c_str(),
                                   cipherBuf, 16, tag);
  mbedtls_gcm_free(&gcm);
  if (ret != 0) { free(cipherBuf); return false; }

  cipherHexOut = toHex(cipherBuf, len);
  free(cipherBuf);
  return true;
}

bool aesGcmDecrypt(const uint8_t* key, const uint8_t iv[12], const uint8_t tag[16],
                    const String& cipherHex, String& plaintextOut) {
  size_t len = cipherHex.length() / 2;
  uint8_t* cipherBuf = (uint8_t*)malloc(len > 0 ? len : 1);
  uint8_t* plainBuf  = (uint8_t*)malloc(len > 0 ? len : 1);
  if (!cipherBuf || !plainBuf) { free(cipherBuf); free(plainBuf); return false; }
  if (!fromHex(cipherHex, cipherBuf, len)) { free(cipherBuf); free(plainBuf); return false; }

  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) { mbedtls_gcm_free(&gcm); free(cipherBuf); free(plainBuf); return false; }

  ret = mbedtls_gcm_auth_decrypt(&gcm, len, iv, 12, nullptr, 0,
                                  tag, 16, cipherBuf, plainBuf);
  mbedtls_gcm_free(&gcm);
  if (ret != 0) { free(cipherBuf); free(plainBuf); return false; }

  plaintextOut = String((char*)plainBuf, len);
  free(cipherBuf);
  free(plainBuf);
  return true;
}

// =========================================================
// Vault file operations
// =========================================================
bool splitFields(const String& line, String parts[], int count) {
  int start = 0;
  for (int i = 0; i < count; i++) {
    int sep = (i == count - 1) ? line.length() : line.indexOf('|', start);
    if (sep < 0) return false;
    parts[i] = line.substring(start, sep);
    start = sep + 1;
  }
  return true;
}

bool hasForbiddenChars(const String& s) {
  return s.indexOf('|') >= 0 || s.indexOf(';') >= 0 || s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0;
}

bool containsToken(const String& list, const String& token) {
  String withGuards = ";" + list + ";";
  String needle = ";" + token + ";";
  return withGuards.indexOf(needle) >= 0;
}

String vaultGetAccounts(const String& domain) {
  File f = SD.open(VAULT_PATH, FILE_READ);
  if (!f) return "";

  String result;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    String parts[5];
    if (!splitFields(line, parts, 5)) continue;
    if (parts[0] != domain) continue;

    uint8_t iv[12], tag[16];
    if (parts[2].length() != 24 || parts[3].length() != 32) continue;
    fromHex(parts[2], iv, 12);
    fromHex(parts[3], tag, 16);

    String plaintext;
    if (aesGcmDecrypt(sessionKey, iv, tag, parts[4], plaintext)) {
      if (result.length() > 0) result += ";";
      result += parts[1] + "|" + plaintext;
    }
  }
  f.close();
  return result;
}

typedef int (*LineFilter)(const String& line, File& outFile, void* ctx);
bool rewriteVaultFiltered(LineFilter filterFn, void* ctx);

bool rewriteVaultFiltered(LineFilter filterFn, void* ctx) {
  File in = SD.open(VAULT_PATH, FILE_READ);
  File out = SD.open(TEMP_PATH, FILE_WRITE);
  if (!out) { if (in) in.close(); return false; }

  if (in) {
    while (in.available()) {
      String line = in.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) continue;
      int action = filterFn(line, out, ctx);
      if (action == 0) {
        out.println(line);
      }
    }
    in.close();
  }
  out.close();

  SD.remove(VAULT_PATH);
  SD.rename(TEMP_PATH, VAULT_PATH);
  return true;
}

bool vaultSave(const String& domain, const String& username, const String& password) {
  uint8_t iv[12], tag[16];
  String cipherHex;
  if (!aesGcmEncrypt(sessionKey, password, iv, tag, cipherHex)) return false;

  String newLine = domain + "|" + username + "|" + toHex(iv, 12) + "|" + toHex(tag, 16) + "|" + cipherHex;

  File in = SD.open(VAULT_PATH, FILE_READ);
  File out = SD.open(TEMP_PATH, FILE_WRITE);
  if (!out) { if (in) in.close(); return false; }

  bool matched = false;
  if (in) {
    while (in.available()) {
      String line = in.readStringUntil('\n');
      line.trim();
      if (line.length() == 0) continue;
      String parts[5];
      if (splitFields(line, parts, 5) && parts[0] == domain && parts[1] == username) {
        out.println(newLine);
        matched = true;
      } else {
        out.println(line);
      }
    }
    in.close();
  }

  if (!matched) {
    out.println(newLine);
  }
  out.close();

  SD.remove(VAULT_PATH);
  SD.rename(TEMP_PATH, VAULT_PATH);
  return true;
}

struct DeleteCtx {
  String domain;
  String username;
  bool matched;
};

int deleteFilter(const String& line, File& outFile, void* ctxPtr) {
  DeleteCtx* ctx = (DeleteCtx*)ctxPtr;
  String parts[5];
  if (splitFields(line, parts, 5) && parts[0] == ctx->domain && parts[1] == ctx->username) {
    ctx->matched = true;
    return 1;
  }
  return 0;
}

bool vaultDelete(const String& domain, const String& username) {
  DeleteCtx ctx;
  ctx.domain = domain;
  ctx.username = username;
  ctx.matched = false;
  if (!rewriteVaultFiltered(deleteFilter, &ctx)) return false;
  return ctx.matched;
}

String vaultListDomains() {
  File f = SD.open(VAULT_PATH, FILE_READ);
  if (!f) return "";
  String result;
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;
    int sep = line.indexOf('|');
    if (sep < 0) continue;
    String domain = line.substring(0, sep);
    if (!containsToken(result, domain)) {
      if (result.length() > 0) result += ";";
      result += domain;
    }
  }
  f.close();
  return result;
}

// =========================================================
// Serial command handling
// =========================================================
void handleCommand(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;
  lastActivity = millis();

  int colon = cmd.indexOf(':');
  String verb = (colon < 0) ? cmd : cmd.substring(0, colon);
  String rest = (colon < 0) ? "" : cmd.substring(colon + 1);
  verb.toUpperCase();

  if (verb == "PING") {
    reply("PONG");
    return;
  }

  if (verb == "UNLOCK") {
    uint8_t salt[SALT_LEN];
    if (!loadOrCreateSalt(salt)) { reply("FAIL:SALT"); return; }

    uint8_t candidateKey[32];
    if (!deriveKeyPBKDF2(rest, salt, candidateKey)) { reply("FAIL:KDF"); return; }

    if (!vaultIsInitialized()) {
      memcpy(sessionKey, candidateKey, 32);
      if (!writeCheckValue(sessionKey)) { reply("FAIL:INIT"); return; }
      unlocked = true;
      reply("OK:INITIALIZED");
      return;
    }

    if (!verifyCheckValue(candidateKey)) {
      reply("FAIL:BADPASSWORD");
      return;
    }

    memcpy(sessionKey, candidateKey, 32);
    unlocked = true;
    reply("OK");
    return;
  }

  if (verb == "LOCK") {
    memset(sessionKey, 0, sizeof(sessionKey));
    unlocked = false;
    reply("OK");
    return;
  }

  if (!unlocked) {
    reply("FAIL:LOCKED");
    return;
  }

  if (verb == "SAVE") {
    String parts[3];
    if (!splitFields(rest, parts, 3)) { reply("FAIL:BADFORMAT"); return; }
    if (hasForbiddenChars(parts[0]) || hasForbiddenChars(parts[1])) { reply("FAIL:BADCHARS"); return; }
    if (parts[0].length() > MAX_FIELD_LEN || parts[1].length() > MAX_FIELD_LEN || parts[2].length() > MAX_FIELD_LEN) {
      reply("FAIL:TOOLONG");
      return;
    }
    bool ok = vaultSave(parts[0], parts[1], parts[2]);
    reply(ok ? "OK" : "FAIL:WRITE");
    return;
  }

  if (verb == "GET") {
    String accounts = vaultGetAccounts(rest);
    reply(accounts.length() > 0 ? accounts : "NOTFOUND");
    return;
  }

  if (verb == "LIST") {
    reply(vaultListDomains());
    return;
  }

  if (verb == "DELETE") {
    String parts[2];
    if (!splitFields(rest, parts, 2)) { reply("FAIL:BADFORMAT"); return; }
    bool ok = vaultDelete(parts[0], parts[1]);
    reply(ok ? "OK" : "NOTFOUND");
    return;
  }

  reply("FAIL:UNKNOWNCMD");
}

// =========================================================
// Arduino entry points
// =========================================================
void setup() {
  Serial.begin(115200);
  while (!Serial) { delay(10); }

  reply("BOOT");

  SPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
  if (!SD.begin(SD_CS_PIN)) {
    reply("SDFAIL");
  } else {
    reply("READY");
  }
  reply("VERSION:2.0");
}

void loop() {
  static String buffer;
  while (Serial.available()) {
    char c = Serial.read();

    if (c == '\n') {
      Serial.println(); // finishes the visible echoed line on a terminal
      handleCommand(buffer);
      buffer = "";
    } else if (c == '\r') {
      // ignore - the '\n' that follows is what actually ends the line
    } else if (c == 8 || c == 127) {
      if (buffer.length() > 0) {
        buffer.remove(buffer.length() - 1);
        Serial.print("\b \b");
      }
    } else {
      buffer += c;
      Serial.print(c); // local echo for interactive terminal use - never
                        // prefixed with "VLT:", so protocol clients ignore it
      if (buffer.length() > MAX_CMD_LEN) {
        Serial.println();
        reply("FAIL:CMDTOOLONG");
        buffer = "";
      }
    }
  }

  if (unlocked && (millis() - lastActivity > AUTO_LOCK_MS)) {
    memset(sessionKey, 0, sizeof(sessionKey));
    unlocked = false;
    reply("LOCKED:TIMEOUT");
  }
}

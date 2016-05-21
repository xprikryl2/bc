#ifndef CONFIG_H
#define CONFIG_H

// RemSig endpoints
const char* list = "https://remsig.ics.muni.cz/remsig/listCertificates";
const char* checkpassword = "https://remsig.ics.muni.cz/remsig/checkPassword";
const char* sign = "https://remsig.ics.muni.cz/remsig/sign";


// Token properties - must be set by admin
unsigned minBitlen = 512; // must be at least 512
unsigned maxBitlen = 4096;
unsigned defaultBitLen = 2048;
unsigned incrBitLen = 512;

#endif // CONFIG_H

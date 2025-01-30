/*
Spinning Cat Hashing Algorithm (SCHA) - Secure Version

The secure version of SCHA is inspired by the spinning cat 'uia' meme, but with an enhanced, more robust hash output. 
Instead of using a small character set, the algorithm generates a configurable-length hash (in bytes), which is then 
encoded as a hexadecimal string for improved readability and usability. It has a good confusion and diffusion in my opinion.

While it retains the playful origins of SCHA, this secure version produces a larger and more complex hash output, 
offering better unpredictability compared to the original version.

😺 Higher Entropy: The secure version of SCHA produces a configurable-length hash output (in bytes). The hash is then 
   encoded into a hexadecimal string, where each byte is represented by two hex characters. For example, a 384-byte hash 
   would produce a 768-character hex string. This increases entropy significantly, making the hash more resistant to 
   brute-force and collision attacks compared to the original version. However, it still doesn't provide the level of security 
   found in cryptographic hash functions like SHA-256.

😿 Might be a Potential Cryptographic Use: While this version of SCHA has improved entropy, it does not meet cryptographic standards. 
   The algorithm’s structure, based on alternating spins and pseudorandom number generation, leaves it vulnerable to attacks. 
   It might be considered for certain non-critical cryptographic-like use cases but is not suitable for applications that require 
   high levels of security.

😿 Slower Performance: Like the original version, the larger the input, the slower the hashing time due to the spin mechanism. 
   This added complexity, while improving the hash output, results in slower performance for large inputs, especially as the 
   output length increases. 


How It Works ❓❓❓

The secure version uses the Mulberry32 pseudorandom number generator (PRNG) to generate a pseudorandom stream. The rotation 
(spin) mechanism adds more complexity and sensitivity to small changes in the input, ensuring a highly unique hash output for 
even minor modifications to the plaintext.


😼 Entropy Calculation:

The concept of entropy refers to the randomness or unpredictability of the hash output. With SCHA, the output is specified 
by the user in bytes, with each byte consisting of 8 bits. After generating the hash, it is converted to a hexadecimal string, 
where each byte is represented by two hex characters, which effectively doubles the string length (since each hex character 
represents 4 bits).

For example:
- A 128-byte output generates a 256-character hexadecimal string (which corresponds to 128 bytes or 1024 bits of entropy).
- A 256-byte output generates a 512-character hexadecimal string (which corresponds to 256 bytes or 2048 bits of entropy).
- A 384-byte output generates a 768-character hexadecimal string (which corresponds to 384 bytes or 3072 bits of entropy).
- A 512-byte output generates a 1024-character hexadecimal string (which corresponds to 512 bytes or 4096 bits of entropy).

In other words, the entropy of the output is directly tied to the byte length of the hash before it is encoded in hex.

While this version of SCHA offers better entropy than the original, it might be considered for some low-security cryptographic-like use cases, 
but it should not be used for applications requiring true cryptographic strength or protection against sophisticated attacks.

This version of SCHA is more suitable for non-cryptographic scenarios where a recognizable and relatively larger hash is desired, 
but it should not be used for applications requiring true cryptographic strength or protection against sophisticated attacks.
*/

function SCHA_Hash(plaintext, hashLength) {
    // Initialize the seed by adding each character's ASCII value (plus 2) from the plaintext
    var seed = 0x01;
    for (var i = 0x0; i < plaintext.length; i++) {
        seed += (plaintext.charCodeAt(i) + 0x02);
    }

    var hashArray = [];
    var stream1 = mulberry32((seed > 0x10000) ? seed % 0x10000 : seed - 0x10000);
    var stream2 = mulberry32((seed * 0x02) % 0x10000);
    var paddedLength = (plaintext.length % hashLength == 0x0) ? plaintext.length : plaintext.length + (hashLength - plaintext.length % hashLength);
    var hashOutput = "";
    var catSpin = 0x01;

    // Initialize hash array with pseudorandom values
    for (var i = 0x0; i < hashLength; i++) {
        hashArray[i] = Math.floor((stream1() * 0x100) ^ (stream2() * 0x100));
    }

    // Modify hash array based on the input plaintext
    for (var i = 0x0; i < paddedLength + (hashLength * 0x02); i++) {
        var modifiedByte = mulberry32(((plaintext.charCodeAt(i) || 0x0) + 0x02) + (stream1() * 0x10000));
        hashArray[i % hashArray.length] = modifiedByte() ^ ((((plaintext.charCodeAt(i) || 0x0) + 0x02) ^ (stream1() * 0x100)) ^ hashArray[i % hashArray.length]);

        // Alternating spin direction
        catSpin = (i % Math.floor(hashLength * 0x04)) < (hashLength * 0x02);
        hashArray = catSpin ? spinLeft(hashArray) : spinRight(hashArray);
    }

    // Generate final result string based on the modified hash array
    for (var i = 0x0; i < hashArray.length; i++) {
        var xoredValue = ((hashArray[i] ^ (stream2() * 0x100)) % 0x100).toString(16);
        hashOutput += (xoredValue.length < 2) ? "0" + xoredValue : xoredValue;
    }

    return hashOutput;
}

// Math.imul polyfill
function imulPolyfill(a, b) {
    if (typeof (Math.imul) !== "undefined") {
        return Math.imul(a, b);
    }

    var aHigh = (a >>> 0x10) & 0xFFFF;
    var aLow = a & 0xFFFF;
    var bHigh = (b >>> 0x10) & 0xFFFF;
    var bLow = b & 0xFFFF;

    return (aLow * bLow) + (((aHigh * bLow) + (aLow * bHigh)) << 0x10) | 0x0;
}

// Mulberry32 prng to generate pseudorandom stream
function mulberry32(a) {
    return function() {
        a = (a >>> 0x0);
        a = a + 0x6D2B79F5 | 0x0;
        var t = imulPolyfill(a ^ (a >>> 0x0F), 0x01 | a);
        t = t + imulPolyfill(t ^ (t >>> 0x07), 0x3D | t) ^ t;
        return ((t ^ (t >>> 0x0E)) >>> 0x0) / 0x100000000;
    }
}

// Spin values to the right
function spinRight(arr) {
    var lastElement = arr[arr.length - 0x01];
    for (var i = arr.length - 0x01; i > 0x0; i--) {
        arr[i] = arr[i - 0x01];
    }
    arr[0x0] = lastElement;
    return arr;
}

// Spin values to the left
function spinLeft(arr) {
    var firstElement = arr[0x0];
    for (var i = 0x0; i < arr.length - 0x01; i++) {
        arr[i] = arr[i + 0x01];
    }
    arr[arr.length - 0x01] = firstElement;
    return arr;
}


// Usage

var plaintext = "Lorem Ipsum Dolor Sit Amet.";
var catlength = 256;

console.time("Hashing Speed");

// Hash plaintext
var cathash = SCHA_Hash(plaintext, catlength);

console.timeEnd("Hashing Speed");

console.log("Hash Length: " + catlength);
console.log("Plaintext: \"" + plaintext + "\"");
console.log("Hash Output: \"" + cathash + "\"");

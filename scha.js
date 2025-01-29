/*
Spinning Cat Hashing Algorithm (SCHA)

SCHA is inspired by the spinning cat 'uia' meme 
and it uses five simple characters: `o`, `i`, `a`, `u`, and space ( ).

While it may seem playful and simple, this algorithm is minimalistic.
It mimics traditional one-way hash functions but has some notable limitations that I’ll explain below.

😿 Low Entropy: Since the hash output is limited to just five possible characters, 
   the entropy (or unpredictability) is quite low. This is a big weakness compared to well-established 
   cryptographic hash functions like SHA-256 or bcrypt. With their complex transformations and larger 
   output spaces, those algorithms are much harder to reverse or predict.

😿 Not Cryptographically Secure: Due to the small character set and low entropy, 
   SCHA is NOT cryptographically secure. The limited space of possible hash outputs makes it 
   much more vulnerable to brute-force and collision attacks. For practical, secure applications, longer 
   hash outputs would be needed, though even then, this algorithm wouldn't provide the necessary level of security.

😿 Slow Performance: The larger the plaintext, the slower the hashing time 
   due to the alternating spinning mechanism. This is because the algorithm 
   performs multiple rotations for each chunk of data, which can become 
   increasingly time-consuming as the input size grows. The additional 
   complexity introduced by the spinning adds overhead, causing slower 
   execution for larger data sets compared to more optimized hashing algorithms.


How It Works ❓❓❓

The SCHA algorithm works by using the Mulberry32 pseudorandom number 
generator (PRNG) to generate pseudorandom stream.
Additionally, I’ve added a rotation (spin) mechanism to introduce more complexity.
While minimalistic, this approach makes the algorithm highly  sensitive to small changes in the input,
meaning even a tiny modification will produce completely different result.

Why It's Not Like SHA-256 ❓❓❓

SHA-256 produces a 256-bit (32-byte) hash, designed to resist 
various types of attacks. In comparison, SCHA, which may output a 128-character hash,
only offers about 297.6 bits of entropy.


😼 Entropy Calculation:

The concept of entropy refers to the unpredictability or randomness of the hash output. 
With SCHA, using 5 possible characters (`o`, `i`, `a`, `u`, and space), we can calculate the entropy as follows:

Length * log2(5) ≈ Length * 2.32 bits of entropy

To give you a sense of how entropy grows with hash length:
- Length 16: ~37.12 bits of entropy
- Length 32: ~74.24 bits of entropy
- Length 64: ~148.48 bits of entropy
- Length 128: ~297.6 bits of entropy
- Length 256: ~595.2 bits of entropy
- Length 384: ~890.88 bits of entropy
- Length 512: ~1190.4 bits of entropy
- Length 768: ~1781.76 bits of entropy

While SCHA may not meet cryptographic standards, it could still serve in low-security scenarios 
where the goal is to create a simple, recognizable hash. The small character set and low entropy make it unsuitable 
for secure applications, but it’s a fun and easy-to-implement solution where security is not the top priority.
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
        var xoredValue = ((hashArray[i] ^ stream2() * 0xFF) % 0x05) + 0x01;

        if      (xoredValue == 0x01) { xoredValue = 0x65 }
        else if (xoredValue == 0x02) { xoredValue = 0x5F }
        else if (xoredValue == 0x03) { xoredValue = 0x59 }
        else if (xoredValue == 0x04) { xoredValue = 0x51 }
        else if (xoredValue == 0x05) { xoredValue = 0x10 }

        hashOutput += String.fromCharCode(xoredValue + 0x10);
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

console.log("Hash Length: " + cathash.length);
console.log("Plaintext: \"" + plaintext + "\"");
console.log("Hash Output: \"" + cathash + "\"");

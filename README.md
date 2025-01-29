# Spinning Cat Hashing Algorithm (SCHA)

SCHA (Spinning Cat Hashing Algorithm) is a playful and minimalistic hashing algorithm inspired by the famous "spinning cat 'uia'" meme. Despite its simplicity, it mimics traditional one-way hash functions with its unique spin mechanism, designed to introduce more complexity and sensitivity to input changes. 

---

## ⚠️ Warning:

This hashing algorithm is **NOT** cryptographically secure and should **not** be used in security-critical applications. It is intended for fun, learning, and experimentation.

---

## Features
- **Minimalistic Design**: Uses only five characters: `o`, `i`, `a`, `u`, and space (` `).
- **Sensitivity to Input**: Small changes in the input produce drastically different results (Avalanche effect).
- **Rotation Mechanism**: A unique spin mechanism that alternates the direction of rotation during hashing, adding extra complexity.
- **Pseudorandom Number Generation**: Utilizes the Mulberry32 pseudorandom number generator (PRNG) for stream generation.
- **Hash Verification**: You can verify a message's integrity by comparing its hash value with the original hash to ensure it hasn't been altered.

---

## Limitations
- **Low Entropy**: Limited to five possible characters, the entropy of this hash is significantly low, making it easily vulnerable to brute-force attacks.
- **Not Secure**: This algorithm is not cryptographically secure and should not be used for real-world security purposes.
- **Slow Performance**: The larger the input, the slower the hashing process due to the additional complexity of alternating spins.

---

## How It Works
The algorithm generates pseudorandom values using **Mulberry32 PRNG** and a rotating spin mechanism to add complexity. The hash output is generated by modifying a hash array with alternating spins, making the result highly sensitive to even the smallest input change.

---

### Entropy Calculation
The entropy of the output hash grows with its length. Given that there are only five possible characters (`o`, `i`, `a`, `u`, and space), the entropy can be calculated as:

```
Entropy ≈ Length * log2(5) ≈ Length * 2.32 bits of entropy
```

---

### Example

#### Plaintext

```
"Lorem Ipsum Dolor Sit Amet."
```

#### Hash Output (Example)

```

"aio  aa i  aiuaui aooa oaa oai ou   iouuiuouoouia ooaoa ioouo ioo uiauoouuau aiuauaoiooouaaaoaaoui  uui aua uoo    oaiao  aauaiu oaa u iu oaiuua uaoo   i iai oiuuiu uuuooouiuiiouaaiaiaioo o ooaaiioiooai auooa  iuoiio  oiiu aoi  iiuouuuou uauuuuuau   o i uo"

```

---

#### Hash Lengths and Entropy:

- **Length 16**: ~37.12 bits of entropy
- **Length 32**: ~74.24 bits of entropy
- **Length 64**: ~148.48 bits of entropy
- **Length 128**: ~297.6 bits of entropy
- **Length 256**: ~595.2 bits of entropy
- **Length 384**: ~890.88 bits of entropy
- **Length 512**: ~1190.4 bits of entropy
- **Length 768**: ~1781.76 bits of entropy

---

## Code Example
```javascript
var plaintext = "Lorem Ipsum Dolor Sit Amet.";
var catlength = 256;

console.time("Hashing Speed");

// Hash plaintext
var cathash = SCHA_Hash(plaintext, catlength);

console.timeEnd("Hashing Speed");

console.log("Hash Length: " + cathash.length);
console.log("Plaintext: \"" + plaintext + "\"");
console.log("Hash Output: \"" + cathash + "\"");
```

---

# Installation

You can clone this repository to get started:

```bash
git clone https://github.com/Harbinger-3/Spinning-Cat-Hashing-Algorithm-SCHA-
cd Spinning-Cat-Hashing-Algorithm-SCHA-
```

---

## Running the Code

To use the hashing algorithm, you can either copy the JavaScript code into your project or run it directly in the browser's developer console.

---

## Secure Version is Available!

We are excited to announce the release of the **Secure Version** of the Spinning Cat Hashing Algorithm (SCHA). This version offers enhanced unpredictability and a higher entropy output compared to the original version. 

### Key Features:
- **Increased Entropy**: The hash length can now be configured by the user (in bytes), and the output is encoded in hexadecimal for better readability.
- **Improved Output**: This secure version generates significantly larger hash outputs, making it more resistant to brute-force and collision attacks.
- **Potential Cryptographic Use**: While not cryptographically secure, the enhanced entropy could serve as a potential cryptographic-like solution for certain non-critical use cases.

### Important Notes:
- **Performance Considerations**: Larger hash lengths and the rotating mechanism can result in slower performance for large datasets.
- **Not Cryptographically Secure**: While this version offers better entropy, it does not meet the security standards of established cryptographic algorithms such as SHA-256 or bcrypt. 

### Use Cases:
This version is suitable for non-security-critical applications where you need a larger, more complex hash that is still easy to generate and work with. It's perfect for low-security scenarios or fun projects where a simple but more secure hash is required.

---

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

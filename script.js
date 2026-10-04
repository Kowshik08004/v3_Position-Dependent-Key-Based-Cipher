// ==========================================
// Simple Text Encryptor - Version 3
// Position-Dependent Key-Based Cipher
// ==========================================


// ==========================================
// HTML Elements
// ==========================================

const textInput = document.getElementById("textInput");
const keyInput = document.getElementById("keyInput");
const result = document.getElementById("result");

const encryptBtn = document.getElementById("encryptBtn");
const decryptBtn = document.getElementById("decryptBtn");
const clearBtn = document.getElementById("clearBtn");
const copyBtn = document.getElementById("copyBtn");

const toggleKeyBtn =
    document.getElementById("toggleKeyBtn");

const inputCount =
    document.getElementById("inputCount");

const resultCount =
    document.getElementById("resultCount");


// ==========================================
// Fixed 62-Character Alphabet
// ==========================================

const ALPHABET =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "abcdefghijklmnopqrstuvwxyz" +
    "0123456789";

const ALPHABET_SIZE = ALPHABET.length;


// ==========================================
// Character Index Tables
// ==========================================

const CHAR_TO_INDEX = new Map();
const INDEX_TO_CHAR = new Map();

for (let i = 0; i < ALPHABET.length; i++) {

    CHAR_TO_INDEX.set(
        ALPHABET[i],
        i
    );

    INDEX_TO_CHAR.set(
        i,
        ALPHABET[i]
    );
}


// ==========================================
// Utility Functions
// ==========================================

function updateCharacterCounts() {

    const inputLength =
        textInput.value.length;

    const resultLength =
        result.value.length;

    inputCount.textContent =
        `${inputLength} character${inputLength === 1 ? "" : "s"}`;

    resultCount.textContent =
        `${resultLength} character${resultLength === 1 ? "" : "s"}`;
}


// ==========================================
// 32-Bit Utility
// ==========================================

function uint32(value) {

    return value >>> 0;
}


// ==========================================
// Deterministic Key Hash
// ==========================================

function hashKey(key) {

    if (typeof key !== "string") {

        throw new TypeError(
            "Key must be a string."
        );
    }

    if (key === "") {

        throw new Error(
            "Encryption key cannot be empty."
        );
    }


    // FNV-1a style initialization

    let state = 2166136261;


    // Process UTF-8 bytes

    const encoder =
        new TextEncoder();

    const data =
        encoder.encode(key);


    for (const byte of data) {

        state ^= byte;

        state = uint32(
            state * 16777619
        );
    }


    // Additional deterministic mixing

    state ^= state >>> 16;

    state = uint32(
        state * 2246822519
    );

    state ^= state >>> 13;

    state = uint32(
        state * 3266489917
    );

    state ^= state >>> 16;

    state = uint32(state);


    // Prevent zero state

    if (state === 0) {

        state = 0xA5A5A5A5;
    }


    return state;
}


// ==========================================
// Position-Dependent Mixing
// ==========================================

function mixPosition(state, position) {

    const positionValue =
        uint32(
            position * 0x9E3779B9
        );


    let value =
        uint32(
            state ^ positionValue
        );


    value ^=
        value >>> 16;

    value =
        uint32(
            value * 0x85EBCA6B
        );

    value ^=
        value >>> 13;

    value =
        uint32(
            value * 0xC2B2AE35
        );

    value ^=
        value >>> 16;


    return uint32(value);
}


// ==========================================
// Generate Deterministic Key Stream
// ==========================================

function generateKeyStream(
    key,
    length
) {

    if (typeof key !== "string") {

        throw new TypeError(
            "Key must be a string."
        );
    }

    if (key === "") {

        throw new Error(
            "Encryption key cannot be empty."
        );
    }

    if (length < 0) {

        throw new Error(
            "Length cannot be negative."
        );
    }


    let state =
        hashKey(key);


    const stream = [];


    for (
        let position = 0;
        position < length;
        position++
    ) {

        // Position-dependent value

        const value =
            mixPosition(
                state,
                position
            );


        // Advance deterministic state

        state ^=
            state << 13;

        state =
            uint32(state);


        state ^=
            state >>> 17;

        state =
            uint32(state);


        state ^=
            state << 5;

        state =
            uint32(state);


        // Combine state and
        // position-dependent value

        const keyValue =
            uint32(
                state ^ value
            );


        // Convert to 0–61

        stream.push(
            keyValue % ALPHABET_SIZE
        );
    }


    return stream;
}


// ==========================================
// Count Supported Characters
// ==========================================

function countSupportedCharacters(text) {

    let count = 0;

    for (const character of text) {

        if (
            CHAR_TO_INDEX.has(character)
        ) {

            count++;
        }
    }

    return count;
}


// ==========================================
// Encrypt
// ==========================================

function encrypt(text, key) {

    if (typeof key !== "string" || key === "") {

        throw new Error(
            "Encryption key cannot be empty."
        );
    }


    const supportedCount =
        countSupportedCharacters(text);


    const keyStream =
        generateKeyStream(
            key,
            supportedCount
        );


    let output = "";

    let position = 0;


    for (const character of text) {

        // Supported character

        if (
            CHAR_TO_INDEX.has(character)
        ) {

            const plainIndex =
                CHAR_TO_INDEX.get(
                    character
                );


            const keyValue =
                keyStream[position];


            const positionValue =
                position % ALPHABET_SIZE;


            const cipherIndex =
                (
                    plainIndex
                    + keyValue
                    + positionValue
                ) % ALPHABET_SIZE;


            output +=
                INDEX_TO_CHAR.get(
                    cipherIndex
                );


            position++;

        } else {

            // Spaces, punctuation,
            // symbols, Unicode and emoji
            // remain unchanged.

            output += character;
        }
    }


    return output;
}


// ==========================================
// Decrypt
// ==========================================

function decrypt(text, key) {

    if (typeof key !== "string" || key === "") {

        throw new Error(
            "Encryption key cannot be empty."
        );
    }


    const supportedCount =
        countSupportedCharacters(text);


    const keyStream =
        generateKeyStream(
            key,
            supportedCount
        );


    let output = "";

    let position = 0;


    for (const character of text) {

        // Supported character

        if (
            CHAR_TO_INDEX.has(character)
        ) {

            const cipherIndex =
                CHAR_TO_INDEX.get(
                    character
                );


            const keyValue =
                keyStream[position];


            const positionValue =
                position % ALPHABET_SIZE;


            const plainIndex =
                (
                    cipherIndex
                    - keyValue
                    - positionValue
                    + ALPHABET_SIZE
                    + ALPHABET_SIZE
                ) % ALPHABET_SIZE;


            output +=
                INDEX_TO_CHAR.get(
                    plainIndex
                );


            position++;

        } else {

            // Spaces, punctuation,
            // symbols, Unicode and emoji
            // remain unchanged.

            output += character;
        }
    }


    return output;
}


// ==========================================
// Encrypt Button
// ==========================================

encryptBtn.addEventListener(
    "click",
    function () {

        const key =
            keyInput.value;


        if (key === "") {

            result.value =
                "Please enter an encryption key.";

            updateCharacterCounts();

            return;
        }


        try {

            result.value =
                encrypt(
                    textInput.value,
                    key
                );

        } catch (error) {

            result.value =
                error.message;
        }


        updateCharacterCounts();
    }
);


// ==========================================
// Decrypt Button
// ==========================================

decryptBtn.addEventListener(
    "click",
    function () {

        const key =
            keyInput.value;


        if (key === "") {

            result.value =
                "Please enter an encryption key.";

            updateCharacterCounts();

            return;
        }


        try {

            result.value =
                decrypt(
                    textInput.value,
                    key
                );

        } catch (error) {

            result.value =
                error.message;
        }


        updateCharacterCounts();
    }
);


// ==========================================
// Clear Button
// ==========================================

clearBtn.addEventListener(
    "click",
    function () {

        textInput.value = "";

        result.value = "";

        keyInput.value = "";


        // Always return key field
        // to hidden state

        keyInput.type = "password";

        toggleKeyBtn.textContent =
            "Show";

        toggleKeyBtn.setAttribute(
            "aria-label",
            "Show encryption key"
        );


        updateCharacterCounts();

        textInput.focus();
    }
);


// ==========================================
// Copy Result
// ==========================================

copyBtn.addEventListener(
    "click",
    async function () {

        const text =
            result.value;


        if (text === "") {

            return;
        }


        try {

            await navigator.clipboard.writeText(
                text
            );

            copyBtn.textContent =
                "Copied!";

        } catch (error) {

            result.select();

            document.execCommand("copy");

            copyBtn.textContent =
                "Copied!";
        }


        setTimeout(
            function () {

                copyBtn.textContent =
                    "Copy Result";

            },
            1500
        );
    }
);


// ==========================================
// Show / Hide Encryption Key
// ==========================================

toggleKeyBtn.addEventListener(
    "click",
    function () {

        if (
            keyInput.type === "password"
        ) {

            keyInput.type = "text";

            toggleKeyBtn.textContent =
                "Hide";

            toggleKeyBtn.setAttribute(
                "aria-label",
                "Hide encryption key"
            );

        } else {

            keyInput.type = "password";

            toggleKeyBtn.textContent =
                "Show";

            toggleKeyBtn.setAttribute(
                "aria-label",
                "Show encryption key"
            );
        }
    }
);


// ==========================================
// Character Counter
// ==========================================

textInput.addEventListener(
    "input",
    updateCharacterCounts
);


// ==========================================
// Initial State
// ==========================================

updateCharacterCounts();
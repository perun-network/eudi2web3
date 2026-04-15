// Implemented in Rust
void circuit_runtime__exceptionHandler(char* circuit_name, void* arg);
void circuit_log_signal(char* circuit_name, void* instance, unsigned int len, unsigned int *data);
void circuit_log_message(char* circuit_name, void* instance, int type, char* message);

void XXXX_runtime__exceptionHandler(void* arg, unsigned int signal) {
    circuit_runtime__exceptionHandler("YYYY", arg);
}
void XXXX_runtime__printErrorMessage(void* instance) {
    // Get the message (for simplicity truncate long messages)
    char message[1024];
    int i = 0;
    char c;
    do {
        c = XXXX_getMessageChar(instance);
        message[i] = c;
        i++;
    } while (c != 0 && i < 1024);
    
    // Make truncate if necessary.
    message[1023] = 0;

    // Call the Rust handler
    circuit_log_message("YYYY", instance, 1, message);
}
// See https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/test/circuit2/circuit_js/witness_calculator.cjs#L91
void XXXX_runtime__showSharedRWMemory(void *instance) {
    unsigned int len = XXXX_getFieldNumLen32(instance);

    // Get the data (for simplicity I'm assuming its just one signal, snarkjs also
    // only outputs a single number). Allow up to u256
    unsigned int data[8];
    if (len > 8) {
        len = 8;
    }

    // Read the data
    for (unsigned int i = 0; i < len; i++) {
        data[i] = XXXX_readSharedRWMemory(instance, i);
    }

    // Give the array to Rust, probably easier than building the number here.
    circuit_log_signal("YYYY", instance, len, data);
}
// See https://github.com/iden3/snarkjs/blob/9a8f1c0083d18b9b5e18f526cfd729e7259423be/test/circuit2/circuit_js/witness_calculator.cjs#L81
void XXXX_runtime__writeBufferMessage(void *instance) {
    // Get the message (for simplicity truncate long messages)
    char message[1024];
    int i = 0;
    char c;
    do {
        c = XXXX_getMessageChar(instance);
        message[i] = c;
        i++;
    } while (c != 0 && i < 1024);
    
    // Make truncate if necessary.
    message[1023] = 0;

    // Call the Rust handler
    circuit_log_message("YYYY", instance, 0, message);
}


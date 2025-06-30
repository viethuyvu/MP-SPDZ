/*
 * PPMLAC_prep.h
 *
 */
#pragma once
#include "Protocols/ReplicatedPrep.h"
#include "Tools/Exceptions.h"
#include "Tools/random.h"
#include "Tools/Commit.h"         // For cryptographic operations
#include "Networking/Player.h"    // For communication
#include "PPMLAC_protocol.h"

std::string to_hex(const std::string& data) {
    std::stringstream ss;
    for (char c : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(static_cast<unsigned char>(c));
    }
    return ss.str();
}

template<class T> class SubProcessor;
class DataPositions;

// preprocessing facility
template<class T>
class PPMLACPrep : public BufferPrep<T>
{
    Player& player;
public:
    // global setup for encryption keys if needed
    static void basic_setup(Player& player)
    {
        /**
         * octetStream is a core utility class used for serializing 
         * and transmitting data between parties over the network.
         * acts like a binary buffer
         * Stores raw bytes
         * Can serialize/deserialize arbitrary data (e.g. integers, field elements, strings)
         * Supports sending/receiving over Player objects (i.e., communication channels between parties)
         */
        // octetStream os;

        // // Alice:
        // if(player.my_num() == 0)
        // {
        //     // Step 1: Alice receives Bob's public key
        //     octetStream bob_public_key;
        //     player.receive_player(1, bob_public_key);

        //     // Step 2: Alice does remote attestation to verify the received key is a trusted public key, and fails the whole protocol if it is not. (omitted)

        //     // Step 3: Alice calls trueRnd ⟨𝑚⟩ ;𝑚 is set to a random number.
        //     PRNG temp_rng;
        //     temp_rng.ReSeed();
        //     string m(16,' ');
        //     temp_rng.get_octets((octet*)m.data(), 16);

        //     // Step 4: Alice packs 𝑚, 𝑃𝐾0 (her public key) into a message x′ = {𝑚,𝑃𝐾0} and encrypts 𝑥′ with 𝑃𝐾1 (Bob’s public key) toget ciphertext 𝑥 = 𝐸𝑛𝑐𝑟𝑦𝑝𝑡(𝑃𝐾1, {𝑚,𝑃𝐾0})
        //     // This step is simulated only, not actual real world encryption
        //     string payload = m + "PK0";

        //     // Step 5: Alice sends 𝑥 to Bob.
        //     os.store_bytes(reinterpret_cast<octet*>(payload.data()), payload.size());
        //     player.send_to(1, os);

        //     //Step 7: Alice receives 𝑦 from Bob
        //     octetStream y_stream;
        //     player.receive_player(1, y_stream);
        //     string TR = y_stream.str();

        //     // Step 8: Initialize shared PRNG with seed = m + TR
        //     std::cerr << "Alice m: " << to_hex(m) << ", TR: " << to_hex(TR) << std::endl;
        //     string seed = m + TR;
        //     octet seed_octet[SEED_SIZE];
        //     if (seed.size() < SEED_SIZE)
        //         throw runtime_error("Seed too short");
        //     memcpy(seed_octet, seed.data(), SEED_SIZE);
        //     std::stringstream ss;
        //     ss << "Alice Seed: ";
        //     for (size_t i = 0; i < SEED_SIZE; i++) {
        //         ss << std::hex << std::setw(2) << std::setfill('0') 
        //         << static_cast<int>(seed_octet[i]);
        //     }
        //     std::cerr << ss.str() << std::endl;
        //     PPMLACProtocol<T>::synchronized_prng.SetSeed(seed_octet);
        // }
        // else if (player.my_num() == 1)
        // {
        //     // Step 1: Send public key to Alice
        //     string bob_public_key = "PK1"; // Simulated public key
        //     os.store_bytes(reinterpret_cast<octet*>(bob_public_key.data()), bob_public_key.size());
        //     player.send_to(0, os);

        //     // Step 5: Receive x from Alice
        //     octetStream x_stream;
        //     player.receive_player(0, x_stream);
        //     string payload = x_stream.str();
        //     string m = payload.substr(0, 16); // 16 bytes of random
        //     // PK0 is not used because no actual key exchange is performed in this simulation

        //     // Step 6: generate TR and init CSPRNG
        //     PRNG temp_rng;
        //     temp_rng.ReSeed();
        //     string TR(16, ' ');
        //     temp_rng.get_octets((octet*)TR.data(), TR.size());

        //     std::cerr << "Bob m: " << to_hex(m) << ", TR: " << to_hex(TR) << std::endl;
        //     string seed = m + TR;
        //     octet seed_octet[SEED_SIZE]; // SEED_SIZE is 16 bytes
        //     if (seed.size() < SEED_SIZE)
        //         throw runtime_error("Seed too short");
        //     memcpy(seed_octet, seed.data(), SEED_SIZE);
        //     // Format seed for debug output
        //     std::stringstream ss;
        //     ss << "Bob Seed: ";
        //     for (size_t i = 0; i < SEED_SIZE; i++) {
        //         ss << std::hex << std::setw(2) << std::setfill('0') 
        //         << static_cast<int>(seed_octet[i]);
        //     }
        //     std::cerr << ss.str() << std::endl;
            
        //     PPMLACProtocol<T>::synchronized_prng.SetSeed(seed_octet);

        //     // Step 7: Pack TR and send to Alice (simulating encryption)

        //     octetStream y_stream;
        //     y_stream.store_bytes(reinterpret_cast<octet*>(TR.data()), TR.size());
        //     player.send_to(0, y_stream);
        // }
        // else{
        //     throw runtime_error("PPMLACPrep: Invalid player number, only 2 allowed");
        // }
        // Fixed 16-byte seed (must be 16 bytes if SEED_SIZE is 16)
        const std::string fixed_seed = "test_seed_123456"; // 16 bytes

        if (fixed_seed.size() != SEED_SIZE)
            throw std::runtime_error("Fixed seed size mismatch");

        // Convert to octet array
        octet seed_octet[SEED_SIZE];
        memcpy(seed_octet, fixed_seed.data(), SEED_SIZE);

        std::stringstream ss;
        ss << "Fixed Seed for P" << player.my_num() << ": ";
        for (size_t i = 0; i < SEED_SIZE; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
            << static_cast<int>(seed_octet[i]);
        }
        std::cerr << ss.str() << std::endl;

        // Set the fixed seed for both players
        PPMLACProtocol<T>::synchronized_prng.SetSeed(seed_octet);
    }

    // destruct global setup
    static void teardown()
    {
    }

    PPMLACPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), player(proc->P){}

    PPMLACPrep(DataPositions& usage, Player& player) :
            BufferPrep<T>(usage), player(player){}

    // access to protocol instance if needed
    void set_protocol(typename T::Protocol&)
    {
    }

    // buffer batch of multiplication triples in this->triples
    void buffer_triples()
    {
        throw runtime_error("no triples");
    }

    // buffer batch of random bit shares in this->bits
    void buffer_bits()
    {
        // Temporary implementation to avoid errors
        int n = 1000;  // number of bits to buffer
        for (int i = 0; i < n; i++) {
            // Get random bit from synchronized PRNG
            bool bit = PPMLACProtocol<T>::synchronized_prng.get_bit();
            // Convert to the clear type (0 or 1)
            typename T::clear value = bit ? 1 : 0;
            this->bits.push_back(value);
        }
        std::cerr << "Buffered " << n << " dummy bits" << std::endl;
    }
};


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
#include <iomanip> 

// Improved hex conversion for debugging
std::string to_hex(const octet* data, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(data[i]);
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
        const int seed_size = SEED_SIZE;
        int other_party = 1 - player.my_num();

        if (player.my_num() == 0) {
            // Alice (P0)
            std::cerr << "Alice starting Protocol 2 setup..." << std::endl;
            
            // Step 3: Generate random m
            PRNG temp_rng;
            temp_rng.ReSeed();
            octet m_oct[seed_size];
            temp_rng.get_octets(m_oct, seed_size);
            std::cerr << "Alice generated m: " << to_hex(m_oct, seed_size) << std::endl;

            // Step 5: Send m to Bob
            octetStream os_send;
            os_send.append(m_oct, seed_size);
            player.send_to(other_party, os_send);
            std::cerr << "Alice sent m to Bob" << std::endl;

            // Step 7: Receive TR from Bob
            octetStream os_recv;
            player.receive_player(other_party, os_recv);
            std::cerr << "Alice received TR: " << os_recv.get_length() << " bytes" << std::endl;
            
            if (os_recv.get_length() < seed_size) {
                std::cerr << "Error: Received TR of insufficient length" << std::endl;
                throw runtime_error("Received TR of insufficient length");
            }
            
            octet TR_oct[seed_size];
            os_recv.consume(TR_oct, seed_size);
            std::cerr << "Alice received TR: " << to_hex(TR_oct, seed_size) << std::endl;

            // Derive seed = m XOR TR
            octet derived_seed[seed_size];
            for (int i = 0; i < seed_size; i++) {
                derived_seed[i] = m_oct[i] ^ TR_oct[i];
            }
            std::cerr << "Alice derived seed: " << to_hex(derived_seed, seed_size) << std::endl;

            // Initialize synchronized PRNG
            PPMLACProtocol<T>::synchronized_prng.SetSeed(derived_seed);
            std::cerr << "Alice initialized synchronized PRNG" << std::endl;
        }
        else if (player.my_num() == 1) {
            // Bob (P1)
            std::cerr << "Bob starting Protocol 2 setup..." << std::endl;
            
            // Step 5: Receive m from Alice
            octetStream os_recv;
            player.receive_player(other_party, os_recv);
            std::cerr << "Bob received m: " << os_recv.get_length() << " bytes" << std::endl;
            
            if (os_recv.get_length() < seed_size) {
                std::cerr << "Error: Received m of insufficient length" << std::endl;
                throw runtime_error("Received m of insufficient length");
            }
            
            octet m_oct[seed_size];
            os_recv.consume(m_oct, seed_size);
            std::cerr << "Bob received m: " << to_hex(m_oct, seed_size) << std::endl;

            // Generate random TR
            PRNG temp_rng;
            temp_rng.ReSeed();
            octet TR_oct[seed_size];
            temp_rng.get_octets(TR_oct, seed_size);
            std::cerr << "Bob generated TR: " << to_hex(TR_oct, seed_size) << std::endl;

            // Step 7: Send TR to Alice
            octetStream os_send;
            os_send.append(TR_oct, seed_size);
            player.send_to(other_party, os_send);
            std::cerr << "Bob sent TR to Alice" << std::endl;

            // Derive seed = m XOR TR
            octet derived_seed[seed_size];
            for (int i = 0; i < seed_size; i++) {
                derived_seed[i] = m_oct[i] ^ TR_oct[i];
            }
            std::cerr << "Bob derived seed: " << to_hex(derived_seed, seed_size) << std::endl;

            // Initialize synchronized PRNG
            PPMLACProtocol<T>::synchronized_prng.SetSeed(derived_seed);
            std::cerr << "Bob initialized synchronized PRNG" << std::endl;
        }
        else {
            throw runtime_error("PPMLACPrep: Invalid player number, only 0 and 1 allowed");
        }
    }

    // destruct global setup
    static void teardown()
    {
        std::cerr << "Tearing down PPMLAC setup" << std::endl;
    }

    PPMLACPrep(SubProcessor<T>* proc, DataPositions& usage) :
            BufferPrep<T>(usage), player(proc->P)
    {
        std::cerr << "PPMLACPrep constructor with SubProcessor" << std::endl;
    }

    PPMLACPrep(DataPositions& usage, Player& player) :
            BufferPrep<T>(usage), player(player)
    {
        std::cerr << "PPMLACPrep constructor with Player" << std::endl;
    }

    // access to protocol instance if needed
    void set_protocol(typename T::Protocol&)
    {
        std::cerr << "PPMLACPrep set_protocol called" << std::endl;
    }

    // buffer batch of multiplication triples in this->triples
    void buffer_triples()
    {
        std::cerr << "PPMLACPrep buffer_triples called - not supported" << std::endl;
        throw runtime_error("no triples");
    }

    // buffer batch of random bit shares in this->bits
    void buffer_bits()
    {
        int n = 1000;
        std::cerr << "Buffering " << n << " secure bits" << std::endl;
        
        for (int i = 0; i < n; i++) {
            bool bit = PPMLACProtocol<T>::synchronized_prng.get_bit();
            typename T::clear value = bit ? 1 : 0;
            this->bits.push_back(value);
        }
        
        std::cerr << "Buffered " << n << " secure bits using synchronized PRNG" << std::endl;
    }
};


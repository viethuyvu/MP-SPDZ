/*
 * PPMLAC_Protocol.h
 *
 */
#pragma once
#include <vector>
#include "Protocols/Replicated.h"
#include "Protocols/MAC_Check_Base.h"
#include "Processor/Input.h"
#include "Tools/random.h"
#include <map>

// opening facility
template<class T>
class PPMLACOutput : public MAC_Check_Base<T>
{
    // MAC_Check_Base: MP-SPDZ uses this base class to store collected shares, opened values, and define a common interface for "open" protocols.
public:

    using MAC_Check_Base<T>::secrets;  // Declare access to protected member
    using MAC_Check_Base<T>::values;   // Declare access to protected member
    // Constructor
    // Accepts a Mac key type but does not use it in this case.
    PPMLACOutput(const typename T::mac_key_type& mac_key, int = 0, int = 0) :
            MAC_Check_Base<T>(mac_key){}

    // open shares in this->shares and put clear values in this->values
    // Perform the actual opening of shares between parties.
    // reconstructing the underlying value from secret shares
    void exchange(const Player& P)
    {
        int other_party = 1 - P.my_num(); // Assuming two-party protocol

        std::cerr << "OUTPUT EXCHANGE: P" << P.my_num() << " opening " << this->secrets.size() << " values with P" << other_party << std::endl;
        octetStream os_send, os_receive;

        // Shares stored in this->secrets (inherited from MAC_Check_Base) are serialized 
        // and packed into os_send to be sent.
        for(auto& secret: this->secrets)
        {
            secret.pack(os_send); // Pack the share into the octetStream
        }

        // Sends your packed shares and receives the other party's shares.
        P.send_to(other_party, os_send); // Send shares to the other party
        P.receive_player(other_party, os_receive); // Receive shares from the other party

        // Reconstruct the values from the received shares
        for (size_t i = 0; i < this->secrets.size(); i++) {
            T other_share;
            other_share.unpack(os_receive);
            auto reconstructed = this->secrets[i].value + other_share.value;
            this->values.push_back(reconstructed);
            std::cerr << "Reconstructed value: " << reconstructed<< " = " << this->secrets[i].value<< " (local) + " << other_share.value<< " (remote)" << std::endl;
        }

        // Clear the shares after opening
        this->secrets.clear();
    }
};

// multiplication protocol
template<class T>
class PPMLACProtocol : public ProtocolBase<T>
{
    // ProtocolBase: MP-SPDZ uses this base class to define a common interface for protocols that handle multiplications.
    // It provides methods for initializing, preparing, exchanging, and finalizing multiplications.
    vector<T> x_vec, y_vec; // Buffers for input shares of multiplications
    vector<T> results; // Buffer for output shares
    octetStream os_send, os_receive; // Streams for sending and receiving data/ communication buffers
public:
    static PRNG synchronized_prng;  // Static synchronized PRNG
    static PRNG local_prng;
    Player& P;
    static int get_n_relevant_players() 
    {
        // This function returns the number of relevant players for the protocol.
        // In this case, it is hardcoded to 2, intending for a two-party protocol.
        return 2;
    }

    PPMLACProtocol(Player& P) :P(P){
        octet seed[SEED_SIZE];
        synchronized_prng.get_octets(seed, SEED_SIZE);
        local_prng.SetSeed(seed);
    }

    // prepare next round of multiplications
    void init_mul()
    {
        // Initialize the multiplication protocol by clearing buffers
        // Called once per round of multiplications
        x_vec.clear();
        y_vec.clear();
        results.clear();
        os_send.clear();
        os_receive.clear();
    }

    // schedule multiplication
    void prepare_mul(const T&x, const T&y, int = -1)
    {
        x_vec.push_back(x); // Store the first operand
        y_vec.push_back(y); // Store the second operand
    }

    // execute protocol
    // Core function that handles the multiplication protocol.
    void exchange()
    {
        int other_party = 1 - P.my_num(); // Assuming two-party protocol
        if(P.my_num() == 0) // Alice
        {
            // Alice's side: send her inputs to Bob
            for(size_t i = 0; i < x_vec.size(); i++)
            {
                // Generate random mask
                auto r1 = synchronized_prng.get<typename T::clear>();
                auto r2 = synchronized_prng.get<typename T::clear>();
                auto q1 = synchronized_prng.get<typename T::clear>(); // samples a fresh q1


                std::cerr << "ALICE: x_share=" << x_vec[i]<< " y_share=" << y_vec[i]<< " r1=" << r1 << " r2=" << r2 << " q1=" << q1 << std::endl;

                // Compute masked values d,e
                auto d = x_vec[i] - r1;
                auto e = y_vec[i] - r2;

                // Pack for sending
                d.pack(os_send); // Pack the first operand
                e.pack(os_send); // Pack the second operand

                results.push_back(T(q1)); // sets her output share [z]_0 = q1.
            }
            P.send_to(other_party, os_send); // Send packed data to Bob
        }
        else if(P.my_num() == 1) // Bob
        {
            // Bob's side: receive Alice's inputs and perform multiplications
            P.receive_player(other_party, os_receive); // Receive masked value d,e from Alice

            for(size_t i = 0; i < x_vec.size(); i++)
            {
                // r1,r2 is the same as Alice's r1,r2 due to synchronized PRNG
                auto r1 = synchronized_prng.get<typename T::clear>();
                auto r2 = synchronized_prng.get<typename T::clear>();
                auto q1 = synchronized_prng.get<typename T::clear>(); // Same q1 as Alice's

                T d,e;
                d.unpack(os_receive); // Unpack the first operand
                e.unpack(os_receive); // Unpack the second operand

                auto u = x_vec[i] +d;
                auto v = y_vec[i] + e;
                auto product = (u.value + r1)*(v.value + r2);
                auto result_share = product - q1;

                std::cerr << "BOB: x_share=" << x_vec[i]<< " y_share=" << y_vec[i]<< " r1=" << r1 << " r2=" << r2 << " q1=" << q1 << std::endl;
                std::cerr << "  d=" << d << " e=" << e<< " u=" << u << " v=" << v << std::endl;
                std::cerr << "  product=" << product<< " result_share=" << result_share << std::endl;
                
                // Compute [z]_1 = (u + r1) * (v + r2) - q1 = x * y - q1
                // z[0] + z[1] = x*y
                results.push_back(T(result_share));
            }
        }
        else{
            throw runtime_error("PPMLACPrep: Invalid player number, only 2 allowed");
        }
    }

    // return next product
    T finalize_mul(int = -1)
    {
        T res = results.front();
        results.erase(results.begin()); // Remove the first result from the buffer
        return res; // Return the first result
    }
};

// Definition provides actual storage
template<class T> PRNG PPMLACProtocol<T>::synchronized_prng;
template<class T> PRNG PPMLACProtocol<T>::local_prng;  // Add this line

template<class T>
class PPMLACInput : public InputBase<T>
{
private:
    Player& P;
    int my_num;
    int other_player;

    // Store local input shares and masked values, per player
    std::map<int, std::vector<T>> my_shares;
    std::map<int, std::vector<typename T::open_type>> masked_values;
    std::map<int, octetStream> buffered_input_streams;

public:
    PPMLACInput(SubProcessor<T>& proc, typename T::MAC_Check&) :
        P(proc.P), my_num(P.my_num()), other_player(1 - my_num)
    {
        if (P.num_players() != 2){
            throw std::runtime_error("PPMLACInput supports only 2 players");
        }
        std::cerr << "INPUT_INIT: Player " << my_num << std::endl;
    }

    void reset(int player)
    {
        my_shares[player].clear();
        masked_values[player].clear();
        //std::cerr << "Reset input buffer for player " << player << std::endl;
    }

    void add_mine(const typename T::open_type& input, int = -1)
    {
        typename T::clear r;
        r.randomize(PPMLACProtocol<T>::local_prng);

        T share(r);
        my_shares[my_num].push_back(share);
        masked_values[my_num].push_back(input - r);

        std::cerr << "Added private input (player " << my_num << ")" << std::endl;
    }

    void add_other(int player, int = -1)
    {
        if (player == my_num)
            throw std::runtime_error("Should not add_other for self");
        std::cerr << "Expecting input from player " << player << std::endl;
    }

    void send_mine()
    {
        if (masked_values[my_num].empty()){
            std::cerr << "WARNING: send_mine called with empty buffer" << std::endl;
            return;
        }
            
        octetStream os;
        for (const auto& val : masked_values[my_num]){
            val.pack(os);
        }
        std::cerr << "Sending " << masked_values[my_num].size() << " values to P" << other_player << std::endl;
        P.send_to(other_player, os);

    }

    void exchange() override
    {
        //std::cerr << "Input exchange (P" << my_num << "): ";
        
        if (my_num == 0) {  // Party 0: send then receive
            //std::cerr << "Send->Receive" << std::endl;
            if (!masked_values[my_num].empty()) {
                send_mine();
            }
            octetStream os;
            P.receive_player(other_player, os);
            buffered_input_streams[other_player] = std::move(os);
        }
        else {  // Party 1: receive then send
            //std::cerr << "Receive->Send" << std::endl;
            octetStream os;
            P.receive_player(other_player, os);
            buffered_input_streams[other_player] = std::move(os);
            
            if (!masked_values[my_num].empty()) {
                send_mine();
            }
        }
    }

    T finalize_mine()
    {
        if (my_shares[my_num].empty()){
            throw std::runtime_error("No shares to finalize for mine");
        } 
        T result = my_shares[my_num].front();
        my_shares[my_num].erase(my_shares[my_num].begin());

        return result;
    }

    void finalize_other(int player, T& target, octetStream&, int = -1)
    {
        if (buffered_input_streams[player].get_length() == 0 || buffered_input_streams.find(player) == buffered_input_streams.end())
        {
            std::cerr << "Error: No data in buffered_input_streams for player " << player << std::endl;
            throw std::runtime_error("INPUTMIXED: insufficient data");
        }

        typename T::open_type masked_value;
        masked_value.unpack(buffered_input_streams[player]);
        target = T(masked_value);

        std::cerr << "Received input from P" << player << std::endl;
    }

};


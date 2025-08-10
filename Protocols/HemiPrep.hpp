/*
 * HemiPrep.hpp
 *
 */

#ifndef PROTOCOLS_HEMIPREP_HPP_
#define PROTOCOLS_HEMIPREP_HPP_

#include "HemiPrep.h"
#include "FHEOffline/PairwiseMachine.h"
#include "Tools/Bundle.h"

#include "FHEOffline/DataSetup.hpp"

template<class T>
PairwiseMachine* HemiPrep<T>::pairwise_machine = 0;

template<class T>
Lock HemiPrep<T>::lock;

template<class T>
void HemiPrep<T>::teardown()
{
    if (pairwise_machine)
        delete pairwise_machine;
}

template<class T>
void HemiPrep<T>::basic_setup(Player& P)
{
    // cout << "===== FHE BASIC SETUP START =====" << endl;
    // cout << "Player " << P.my_num() << ": Initializing pairwise machine" << endl;
    assert(pairwise_machine == 0);
    pairwise_machine = new PairwiseMachine(P);
    auto& machine = *pairwise_machine;
    auto& setup = machine.setup<FD>();

    // Print FHE parameters
    // cout << "Player " << P.my_num() << ": FHE Parameters:" << endl;
    // cout << " - Security parameter: " << OnlineOptions::singleton.security_parameter << endl;
    // cout << " - Matrix dimension: " << setup.params.m << endl;
    // cout << " - Plaintext modulus: " << setup.params.get_plaintext_modulus() << endl;
    // cout << " - Ciphertext levels: " << setup.params.levels() << endl;
    setup.params.set_matrix_dim_from_options();
    setup.params.set_sec(OnlineOptions::singleton.security_parameter);

    secure_init(setup, P, machine, typename T::clear(), 0);
    T::clear::template init<typename FD::T>();
    // cout << "Player " << P.my_num() << ": FHE setup completed" << endl;
    // cout << "===== FHE BASIC SETUP COMPLETE =====" << endl;
}

template<class T>
const FHE_PK& HemiPrep<T>::get_pk()
{
    assert(pairwise_machine);
    return pairwise_machine->pk;
}

template<class T>
const typename T::clear::FD& HemiPrep<T>::get_FTD()
{
    assert(pairwise_machine);
    return pairwise_machine->setup<FD>().FieldD;
}


template<class T>
HemiPrep<T>::~HemiPrep()
{
    for (auto& x : multipliers)
        delete x;

    if (two_party_prep)
    {
        auto& usage = two_party_prep->usage;
        delete two_party_prep;
        delete &usage;
    }
}

template<class T>
vector<Multiplier<typename T::clear::FD>*>& HemiPrep<T>::get_multipliers()
{
    assert(this->proc != 0);
    auto& P = this->proc->P;

    lock.lock();
    if (pairwise_machine == 0 or pairwise_machine->enc_alphas.empty())
    {
        PlainPlayer P(this->proc->P.N, "Hemi" + T::type_string());
        if (pairwise_machine == 0)
            basic_setup(P);

        // cout << "Player " << P.my_num() << ": Starting covert key generation" << endl;
        pairwise_machine->setup<FD>().covert_key_generation(P,*pairwise_machine, 1);
        // cout << "Player " << P.my_num() << ": Covert key generation completed" << endl;
        pairwise_machine->enc_alphas.resize(1, pairwise_machine->pk);
        // cout << "Player " << P.my_num() << ": enc_alphas initialized with public key" << endl;
    }
    lock.unlock();

    if (multipliers.empty()){
        // cout << "Player " << P.my_num() << ": Creating " << (P.num_players() - 1) << " multipliers" << endl;
        for (int i = 1; i < P.num_players(); i++){
            // cout << "  - Creating multiplier for player offset " << i << endl;
            multipliers.push_back(new Multiplier<FD>(i, *pairwise_machine, P, timers));
        }
    }
    return multipliers;
}

template<class T>
void HemiPrep<T>::buffer_triples()
{
    CODE_LOCATION
    assert(this->proc != 0);
    auto& P = this->proc->P;
    auto& multipliers = get_multipliers();
    auto& FieldD = pairwise_machine->setup<FD>().FieldD;
    Plaintext_<FD> a(FieldD), b(FieldD), c(FieldD);

    // cout << "Player " << P.my_num() << ": Generating random a and b" << endl;
    a.randomize(G);
    b.randomize(G);
    // cout << "Player " << P.my_num() << ": a[0] = " << a.element(0) << ", b[0] = " << b.element(0) << endl;
    c.mul(a, b);
    // cout << "Player " << P.my_num() << ": Computed c[0] = " << c.element(0) << endl;
    Bundle<octetStream> bundle(P);
    // cout << "Player " << P.my_num() << ": Encrypting and packing a" << endl;
    pairwise_machine->pk.encrypt(a).pack(bundle.mine);

    // cout << "Player " << P.my_num() << ": Broadcasting encrypted a" << endl;
    P.unchecked_broadcast(bundle);

    Ciphertext C(pairwise_machine->pk);
    for (auto m : multipliers)
    {
        // cout << "Player " << P.my_num() << ": Unpacking ciphertext from player " << P.get_player(-m->get_offset()) << endl;
        C.unpack(bundle[P.get_player(-m->get_offset())]);

        // cout << "Player " << P.my_num() << ": Multiplying ciphertext with b" << endl;
        m->multiply_and_add(c, C, b);
    }
    assert(b.num_slots() == a.num_slots());
    assert(c.num_slots() == a.num_slots());

    // cout << "Player " << P.my_num() << ": Storing " << a.num_slots() << " triples in buffer" << endl;
    for (unsigned i = 0; i < a.num_slots(); i++)
        this->triples.push_back({{ a.element(i), b.element(i), c.element(i) }});
}

template<class T>
SemiPrep<T>& HemiPrep<T>::get_two_party_prep()
{
    assert(this->proc);
    assert(this->proc->P.num_players() == 2);

    if (not two_party_prep)
    {
        two_party_prep = new SemiPrep<T>(this->proc,
                *new DataPositions(this->proc->P.num_players()));
        two_party_prep->set_protocol(this->proc->protocol);
    }

    return *two_party_prep;
}

template<class T>
void HemiPrep<T>::buffer_bits()
{
    CODE_LOCATION
    assert(this->proc);
    if (this->proc->P.num_players() == 2)
    {
        auto& prep = get_two_party_prep();
        prep.buffer_size = BaseMachine::batch_size<T>(DATA_BIT,
                this->buffer_size);
        prep.buffer_dabits(0);
        for (auto& x : prep.dabits)
            this->bits.push_back(x.first);
        prep.dabits.clear();
    }
    else
        SemiHonestRingPrep<T>::buffer_bits();
}

template<class T>
void HemiPrep<T>::buffer_dabits(ThreadQueues* queues)
{
    CODE_LOCATION
    assert(this->proc);
    if (this->proc->P.num_players() == 2)
    {
        auto& prep = get_two_party_prep();
        prep.buffer_size = BaseMachine::batch_size<T>(DATA_DABIT,
                this->buffer_size);
        prep.buffer_dabits(queues);
        this->dabits = prep.dabits;
        prep.dabits.clear();
    }
    else
        SemiHonestRingPrep<T>::buffer_dabits(queues);
}

#endif

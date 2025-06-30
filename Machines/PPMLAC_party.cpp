/*
 * PPMLAC-party.cpp
 *
 */

#include "Protocols/PPMLAC_share.h"

#include "Processor/OnlineMachine.hpp"
#include "Processor/Machine.hpp"
#include "Processor/OnlineOptions.hpp"
#include "Protocols/Replicated.hpp"
#include "Protocols/MalRepRingPrep.hpp"
#include "Protocols/ReplicatedPrep.hpp"
#include "Protocols/MAC_Check_Base.hpp"
#include "Math/gfp.hpp"
#include "Math/Z2k.hpp"

int main(int argc, const char** argv)
{
    ez::ezOptionParser opt;
    // Use PPMLACShare<gf2n> for OnlineOptions to set binary domain
    OnlineOptions::singleton = {opt, argc, argv, PPMLACShare<gf2n>()};
    OnlineMachine machine(argc, argv, opt, OnlineOptions::singleton);
    OnlineOptions::singleton.finalize(opt, argc, argv);
    machine.start_networking();
    // Use PPMLACShare for both domains
    // Initialize PRNGs for both domains
    machine.run<PPMLACShare<gfp_<0, 2>>, PPMLACShare<gf2n>>();
}

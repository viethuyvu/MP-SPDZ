/*
 * PPMLAC_Share.h
 *
 */
#pragma once
#include <vector>
#include "ShareInterface.h"
#include "Math/bigint.h"
#include "Math/gfp.h"
#include "GC/NoShare.h"
#include "BMR/Register.h"

#include "PPMLAC_prep.h"
#include "PPMLAC_protocol.h"

template<class T>
class PPMLACShare : public ShareInterface
{
    typedef PPMLACShare This;

public:
    T value; // value of the share
    typedef This share_type;

    // type for clear values in relevant domain
    typedef T clear;
    typedef clear open_type;

    // disable binary computation
    typedef GC::NoShare bit_type;

    // opening facility
    typedef PPMLACOutput<PPMLACShare> MAC_Check;
    typedef MAC_Check Direct_MC;

    // multiplication protocol
    typedef PPMLACProtocol<PPMLACShare> Protocol;

    // preprocessing facility
    typedef PPMLACPrep<PPMLACShare> LivePrep;

    // private input facility
    typedef PPMLACInput<PPMLACShare> Input;

    // default private output facility (using input tuples)
    typedef ::PrivateOutput<PPMLACShare> PrivateOutput;

    // indicate whether protocol allows dishonest majority and variable players
    static const bool dishonest_majority = true;
    static const bool variable_players = true;

    // Default constructor
    PPMLACShare() = default;

    // Constructor from clear value
    PPMLACShare(const clear& value) : value(value) {}

    // description used for debugging output
    static string type_string()
    {
        return "ppmlac share";
    }

    // used for preprocessing storage location
    static string type_short()
    {
        return "P";
    }

    // size in bytes
    // must match assign/pack/unpack and machine-readable input/output
    static int size()
    {
        return clear::size();  // Size of underlying type
    }

    // maximum number of corrupted parties
    // only used in virtual machine instruction
    static int threshold(int n_parties)
    {
        return n_parties - 1;
    }

    // serialize computation domain for client communication
    static void specification(octetStream& os)
    {
        T::specification(os);
    }

    // constant secret sharing
    static This constant(const clear& constant, int my_num, const mac_key_type&)
    {
        // Only party 0 holds the constant value, others hold 0
        if (my_num == 0)
            return This(constant);
        else
            return This(clear(0));  // Other parties get 0
    }

    // share addition
    This operator+(const This& other) const
    {
        return This(value + other.value);
    }

    This operator-() const {
        return This(-value);
    }

    // share subtraction
    This operator-(const This& other) const
    {
        return This(value - other.value);
    }

    This& operator+=(const This& other) {
        value += other.value;
        return *this;
    }

    This& operator-=(const This& other) {
        value -= other.value;
        return *this;
    }

    // private-public multiplication
    This operator*(const clear& other) const {
        return This(value * other);
    }

    // private-public division
    This operator/(const clear& other) const
    {
        return This(value / other);
    }

    // multiplication by power of two
    This operator<<(int n) const
    {
        return This(value << n);  // assumes value supports bit shift
    }

    // assignment from byte string
    // must match unpack
    void assign(const char* buffer) {
        value.assign(buffer);
    }

    // serialization
    // must use the number of bytes given by size()
    void pack(octetStream& os, bool = false) const {
        value.pack(os);
    }

    // serialization
    // must use the number of bytes given by size()
    void unpack(octetStream& os, bool = false) {
        value.unpack(os);
    }

    // serialization
    // must use the number of bytes given by size() for human=false
    void input(istream& is, bool human) {
        value.input(is, human);
    }

    // serialization
    // must use the number of bytes given by size() for human=false
    void output(ostream& os, bool human) const {
        value.output(os, human);
    }
};

template<class T>
inline ostream& operator<<(ostream& o, const PPMLACShare<T>& share)
{
    share.output(o, false);
    return o;
}


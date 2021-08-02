#include <boost/asio.hpp>

#include <algorithm>
#include <iostream>

using boost::asio::io_context;
using boost::asio::ip::tcp;



struct ipv4_header final // for now the full implementation is 
                         // unnecessary. the only purpose this
                         // class serves is better verbosity
                         // on replies
{
    using header_t = char;

    friend std::istream&
    operator>> (std::istream& is, ipv4_header& header)
    {
        is.read(header.header_, 60); 
        return is;
    }
private:
    header_t header_[60];
};


struct icmp_header final
{
    using header_t = char;
    static constexpr int request_code = 8;
    static constexpr int reply_code = 0;

    icmp_header()
    { 
        std::fill(header_, header_ + 8, 0);
    }

    void type (header_t c) {header_[0] = c;}
    header_t type () { return header_[0];}

    void code (header_t c) {header_[1] = c;}
    header_t code () { return header_[1];}

    unsigned short checksum() {return from_seq(2, 3);}
    void checksum(unsigned short value) {to_seq(2, 3, value);}

    unsigned short id() {return from_seq(4, 5);}
    void id(unsigned short value) {to_seq(4, 5, value);}

    unsigned short sequence_number() {return from_seq(6, 7);}
    void sequence_number(unsigned short value) {to_seq(6, 7, value);}

private:
    void to_seq(int i1, int i2, unsigned short value)
    {
        header_[i1] = static_cast<header_t>(value >> 8);
        header_[i2] = static_cast<header_t>(value & 0xFF);
    }
    unsigned short from_seq(int i1, int i2)
    {
        return (header_[i1] << 8) + header_[i2];
    }
    header_t header_[8];
};

int
main()
{
    return 1;
}

#include <boost/asio.hpp>

#include <algorithm>

using boost::asio::io_context;
using boost::asio::ip::tcp;

#include <iostream>

struct ipv4_header final
{
    using header_t = unsigned char;

    ipv4_header()
    {
        std::fill(header_, header_ + 60, 1);
    }

    header_t header_[60];
};

int
main()
{
    ipv4_header header;
    for(int i = 0; i < 60; ++i)
        std::cout << (int)header.header_[i] << '\n';
    return 1;
}

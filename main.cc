#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <string_view>
#include <sstream>

#include "flags.h"

using boost::asio::io_context;
using boost::asio::ip::icmp;
using boost::asio::steady_timer;
namespace chrono = boost::asio::chrono;
using namespace boost::placeholders;


struct ipv4_header final 
{
    using header_t = unsigned char;

    ipv4_header()
    { 
        std::fill(header_, header_ + 60, 0);
    }

    unsigned char
    version() const noexcept
    {
        return (header_[0] >> 4) & 0xF;
    }

    unsigned short
    header_length() const noexcept
    {
        return (header_[0] & 0xF) * 4;
    }

    unsigned char
    type_of_service() const noexcept 
    {
        return header_[1];
    }

    unsigned short
    total_length() const noexcept
    {
        return from_seq(2, 3);
    }
    
    unsigned short
    identification() const noexcept
    {
        return from_seq(4, 5);
    }

    bool
    dont_fragment() const noexcept
    {
        return (header_[6] & 0x40) != 0;
    }
    
    bool
    more_fragments() const noexcept
    {
        return (header_[6] & 0x20) != 0;
    }
    
    unsigned short
    fragment_offset() const noexcept
    {
        return from_seq(6, 7) & 0x1FFF;
    }

    unsigned int
    time_to_live() const noexcept
    {
        return header_[8];
    }

    unsigned char
    protocol() const noexcept
    {
        return header_[9];
    }

    unsigned short
    header_checksum() const noexcept
    {
        return from_seq(10, 11);
    }

    boost::asio::ip::address_v4
    source_address() const
    {
        boost::asio::ip::address_v4::bytes_type bytes
            = { { header_[12], header_[13], header_[14], header_[15] } };
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v4
    destination_address() const
    {
        boost::asio::ip::address_v4::bytes_type bytes
            = { { header_[16], header_[17], header_[18], header_[19] } };
        return boost::asio::ip::address_v4(bytes);
  }

    friend std::istream&
    operator>>(std::istream& is, ipv4_header& header)
    {
        is.read(reinterpret_cast<char*>(header.header_), 20);
        if (header.version() != 4)
        is.setstate(std::ios::failbit);
        std::streamsize options_length = header.header_length() - 20;
        if (options_length < 0 || options_length > 40)
            is.setstate(std::ios::failbit);
        else
            is.read(reinterpret_cast<char*>(header.header_) + 20, options_length);
        return is;
  }
private:
    unsigned short
    from_seq(int a, int b) const noexcept
    {
        return (header_[a] << 8) + header_[b];
    }

    header_t header_[60];
};


struct icmp_header final
{
    using header_t = unsigned char;
    static constexpr int echo_request = 8;
    static constexpr int echo_reply = 0;

    icmp_header()
    { 
        std::fill(header_, header_ + 8, 0);
    }

    void
    type (header_t c) noexcept
    {
        header_[0] = c;
    }
    header_t
    type () const noexcept
    {
        return header_[0];
    }

    void
    code (header_t c) noexcept
    {
        header_[1] = c;
    }
    header_t
    code () const noexcept
    {
        return header_[1];
    }

    void
    checksum (unsigned short value) noexcept
    {
        to_seq(2, 3, value);
    }
    unsigned short
    checksum () const noexcept
    {
        return from_seq(2, 3);
    }

    void
    id (unsigned short value) noexcept
    {
        to_seq(4, 5, value);
    }
    unsigned short
    id () const noexcept
    {
        return from_seq(4, 5);
    }

    void
    sequence_number (unsigned short value) noexcept
    {
        to_seq(6, 7, value);
    }
    unsigned short
    sequence_number () const noexcept
    {
        return from_seq(6, 7);
    }

    friend std::istream&
    operator>> (std::istream& is, icmp_header& header)
    {
        return is.read(reinterpret_cast<char*>(header.header_), 8);
    }
    
    friend std::ostream&
    operator<< (std::ostream& os, icmp_header& header)
    {
        return os.write(reinterpret_cast<char*>(header.header_), 8);
    }
private:
    void
    to_seq (int i1, int i2, unsigned short value) noexcept
    {
        header_[i1] = static_cast<header_t>(value >> 8);
        header_[i2] = static_cast<header_t>(value & 0xFF);
    }

    unsigned short
    from_seq (int i1, int i2) const noexcept
    {
        return (header_[i1] << 8) + header_[i2];
    }

    header_t header_[8];
};


template<typename It>
void
calculate_checksum(icmp_header& header, It beg, It end) noexcept
{
    unsigned int sum = (header.type() << 8) + header.code()
        + header.id() + header.sequence_number();

    auto start = beg;
    for(;start != end;)
    {
        sum += (static_cast<icmp_header::header_t>
            (*start++) << 8);
        if(start != end)
        {
           sum += static_cast<icmp_header::header_t>(*start++);
        }
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    header.checksum(static_cast<unsigned short>(~sum));
}

struct pdping final
{
    pdping(io_context& ioc, std::string_view dest, int nbytes,
           int m_sended)
        : resolver_(ioc), socket_(ioc, icmp::v4()),
          timer_(ioc), n_sended_(0), n_replies_(0),
          nbytes_(nbytes), m_sended_(m_sended)
    {
        endpoint_ = *resolver_.resolve(icmp::v4(), dest, "").begin();
        std::cout << "PING " << nbytes_
                  << " bytes of data to " 
                  << endpoint_.address().to_string() << '\n';
        start_send();
        start_receive();
    }

    void
    start_send ()
    {
        if(n_sended_ == m_sended_)
        {
            return;
        }

        std::string message(nbytes_, 'q');

        icmp_header icmph;
        icmph.type(icmp_header::echo_request);
        icmph.code(0);
        icmph.id(getid());
        icmph.sequence_number(++n_sended_);
        calculate_checksum(icmph, message.cbegin(), message.cend());

        boost::asio::streambuf request_buf;
        std::ostream os(&request_buf);
        os << icmph << message;

        time_sent_ = steady_timer::clock_type::now();
        socket_.send_to(request_buf.data(), endpoint_);

        n_replies_ = 0;
        timer_.expires_at(time_sent_ + chrono::seconds(2));
        timer_.async_wait(boost::bind(&pdping::handle_timeout, this));
    }

    void
    handle_timeout ()
    {
        if(n_replies_ == 0)
            std::cout << "Request timed out!\n";

        timer_.expires_at(time_sent_ + chrono::seconds(1));
        timer_.async_wait(boost::bind(&pdping::start_send, this));
    }

    void
    start_receive ()
    {
        reply_buf_.consume(reply_buf_.size());
        socket_.async_receive(reply_buf_.prepare(65536), 
                boost::bind(&pdping::handle_receive, this, _2));
    }

    void
    handle_receive (std::size_t len)
    {
        reply_buf_.commit(len);
        std::istream is(&reply_buf_);
        ipv4_header ipv4h;
        icmp_header icmph;
        is >> ipv4h >> icmph;

        if (is && icmph.type() == icmp_header::echo_reply
               && icmph.id() == getid()
               && icmph.sequence_number() == n_sended_)
        {
            if (n_replies_++ == 0)
                timer_.cancel();

            chrono::steady_clock::time_point now
                = chrono::steady_clock::now();
            chrono::steady_clock::duration elapsed
                = now - time_sent_;

            std::cout << len - ipv4h.header_length()
            << " bytes from " << ipv4h.source_address()
            << ": icmp_seq=" << icmph.sequence_number()
            << ", ttl=" << ipv4h.time_to_live()
            << ", time="
            << static_cast<double>(chrono::duration_cast<chrono::nanoseconds>(elapsed).count()) / 1e6 << "ms\n";

            if (n_sended_ == m_sended_)
                return;
        }
        start_receive();
    }

    static unsigned short getid() noexcept
    {
        return static_cast<unsigned short>(::getpid());
    }

    icmp::resolver resolver_;
    icmp::endpoint endpoint_;
    icmp::socket socket_;
    boost::asio::streambuf reply_buf_;
    boost::asio::steady_timer timer_;
    chrono::steady_clock::time_point time_sent_;
    unsigned short n_sended_;
    unsigned short n_replies_;
    unsigned short nbytes_;
    unsigned short m_sended_;
};


void print_help(const char * executable) {
    auto print_entry = [](std::string_view spec,
                          std::string_view desc)
        {
            std::cout << std::left << "  "
            << std::setw(20) << spec
            << desc << '\n';
        };
    std::cout << "Usage: " << executable
        << " [options] " << "--host <hostname>\n"
        << "Options:\n";
    print_entry("-host <hostname>", "hostname to ping");
    print_entry("-n <count>", "send <count> bytes");
    print_entry("-c <count>", "stop after <count> replies");
}
int
main(int argc, const char* argv[])
{
    const flags::args args(argc, argv);

    if (args.get<bool>("help").has_value())
    {
        print_help(*argv);
        return 0;

    }
    if (geteuid() != 0)
    {
        std::cerr << "You should run this program as root.\n";
        return 1;
    }
    const auto host = args.get<std::string_view>("host");
    if (!host) {
        std::cerr << "You must provide hostname to ping.\n";
        return 1;
    }

    const auto nbytes = args.get<unsigned short>("n", 32);
    const auto max_replies = args.get<unsigned short>("c", 256);

    io_context ioc;
    pdping pp(ioc, host.value(), nbytes, max_replies);
    ioc.run();
    return 0;
}

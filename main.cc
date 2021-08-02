#include <boost/asio.hpp>
#include <boost/bind/bind.hpp>

#include <algorithm>
#include <iostream>

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
    version() const
    {
        return (header_[0] >> 4) & 0xF;
    }

    unsigned short
    header_length() const
    {
        return (header_[0] & 0xF) * 4;
    }

    unsigned char
    type_of_service() const 
    {
        return header_[1];
    }

    unsigned short
    total_length() const
    {
        return from_seq(2, 3);
    }
    
    unsigned short
    identification() const
    {
        return from_seq(4, 5);
    }

    bool
    dont_fragment() const
    {
        return (header_[6] & 0x40) != 0;
    }
    
    bool
    more_fragments() const
    {
        return (header_[6] & 0x20) != 0;
    }
    
    unsigned short
    fragment_offset() const
    {
        return from_seq(6, 7) & 0x1FFF;
    }

    unsigned int
    time_to_live() const
    {
        return header_[8];
    }

    unsigned char
    protocol() const
    {
        return header_[9];
    }

    unsigned short
    header_checksum() const
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
    from_seq(int a, int b) const
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
    type (header_t c)
    {
        header_[0] = c;
    }
    header_t
    type ()
    {
        return header_[0];
    }

    void
    code (header_t c)
    {
        header_[1] = c;
    }
    header_t
    code ()
    {
        return header_[1];
    }

    unsigned short
    checksum ()
    {
        return from_seq(2, 3);
    }
    void
    checksum (unsigned short value)
    {
        to_seq(2, 3, value);
    }

    unsigned short
    id ()
    {
        return from_seq(4, 5);
    }
    void
    id (unsigned short value)
    {
        to_seq(4, 5, value);
    }

    unsigned short
    sequence_number ()
    {
        return from_seq(6, 7);
    }
    void
    sequence_number (unsigned short value)
    {
        to_seq(6, 7, value);
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
    to_seq (int i1, int i2, unsigned short value)
    {
        header_[i1] = static_cast<header_t>(value >> 8);
        header_[i2] = static_cast<header_t>(value & 0xFF);
    }

    unsigned short
    from_seq (int i1, int i2)
    {
        return (header_[i1] << 8) + header_[i2];
    }

    header_t header_[8];
};


template<typename It>
void
calculate_checksum(icmp_header& header, It beg, It end)
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
    pdping(io_context& ioc, const char* dest)
        : resolver_(ioc), socket_(ioc, icmp::v4()),
          timer_(ioc), n_sended_(0), num_replies_(0)
    {
        endpoint_ = *resolver_.resolve(icmp::v4(), dest, "").begin();
        start_send();
        start_receive();
    }

    void
    start_send ()
    {
        std::string message("");

        icmp_header icmph;
        icmph.type(icmp_header::echo_request);
        icmph.code(0);
        icmph.id(getid());
        icmph.sequence_number(++n_sended_);
        calculate_checksum(icmph, message.begin(), message.end());

        boost::asio::streambuf request_buf;
        std::ostream os(&request_buf);
        os << icmph << message;

        time_sent_ = steady_timer::clock_type::now();
        socket_.send_to(request_buf.data(), endpoint_);

        num_replies_ = 0;
        timer_.expires_at(time_sent_ + chrono::seconds(5));
        timer_.async_wait(boost::bind(&pdping::handle_timeout, this));
    }

    void
    handle_timeout ()
    {
        if(num_replies_ == 0)
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
            if (num_replies_++ == 0)
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
            << chrono::duration_cast<chrono::milliseconds>(elapsed).count()
            << std::endl;
        }
        start_receive();
    }

    static unsigned short getid()
    {
        return static_cast<unsigned short>(::getpid());
    }

    icmp::resolver resolver_;
    icmp::endpoint endpoint_;
    icmp::socket socket_;
    boost::asio::streambuf reply_buf_;
    boost::asio::steady_timer timer_;
    chrono::steady_clock::time_point time_sent_;
    int n_sended_;
    unsigned short num_replies_;
};

int
main()
{
    io_context ioc;
    pdping pp(ioc, "127.0.0.1");
    ioc.run();
    return 0;
}

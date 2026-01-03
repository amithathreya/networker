import dns.resolver
import dns.reversename


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python reverse_DNS.py <IP_ADDRESS>")
        sys.exit(1)
    ip = sys.argv[1]
    rev_name = dns.reversename.from_address(ip)

    try:
        answer = dns.resolver.resolve(rev_name, "PTR")
        for rdata in answer:
            print(rdata.to_text())
    except Exception as e:
        print("No PTR record")

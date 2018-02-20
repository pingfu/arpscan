using System;
using System.Net;

namespace arpscan
{
    public static class IPAddressExtensions
    {
        public static uint ToInt(this IPAddress ip)
        {
            var octets = ip.ToString().Split('.');

            return uint.Parse(octets[3]) + 
                   uint.Parse(octets[2]) * 256 + 
                   uint.Parse(octets[1]) * 65536 + 
                   uint.Parse(octets[0]) * 16777216;
        }

        public static IPAddress ToIpAddress(this uint value)
        {
            return ToIpAddress((double)value);
        }

        public static IPAddress ToIpAddress(this double value)
        {
            var ip = string.Empty;

            for (var n = 1; n < 5; n++)
            {
                var octet = Math.Truncate(value / Math.Pow(256, 4 - n));

                value = value - octet * Math.Pow(256, 4 - n);

                if (octet > 255) return IPAddress.Parse("0.0.0.0");
                if (n == 1)
                {
                    ip = octet.ToString();
                }
                else
                {
                    ip += "." + octet;
                }
            }

            return IPAddress.Parse(ip);
        }
    }
}
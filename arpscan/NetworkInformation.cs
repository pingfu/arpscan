using System.Net;
using System.Net.NetworkInformation;

namespace arpscan
{
    public struct NetworkInformation
    {
        public IPAddress BroadcastAddress { get; }
        public IPAddress FirstAddress { get; }
        public IPAddress IpAddress { get; }
        public IPAddress LastAddress { get; }
        public IPAddress NetworkAddress { get; }
        public int NetworkSize { get; }
        public IPAddress SubnetMask { get; }

        public NetworkInformation(UnicastIPAddressInformation unicastAddress) : this(unicastAddress.Address, unicastAddress.IPv4Mask)
        {
        }

        public NetworkInformation(IPAddress ipAddress, IPAddress subnetMask)
        {
            IpAddress = ipAddress;
            SubnetMask = subnetMask;

            var ip = ipAddress.ToInt();
            var mask = subnetMask.ToInt();

            // logical AND the ipAddress and subnetMask
            var network = ip & mask;

            // logical OR the ipAddress and inverted subnetMask
            var broadcast = ip | ~mask;

            var first = network + 1;
            var last = broadcast - 1;

            // convert to IPAddress
            NetworkAddress = network.ToIpAddress();
            BroadcastAddress = broadcast.ToIpAddress();
            FirstAddress = first.ToIpAddress();
            LastAddress = last.ToIpAddress();
            NetworkSize = (int)(broadcast - network);
        }
    }
}
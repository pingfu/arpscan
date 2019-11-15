using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace arpscan
{
    public class Program
    {
        public static void Main()
        {
            foreach (var unicastAddress in GetInterfaceList())
            {
                var info = new NetworkInformation(unicastAddress.Address, unicastAddress.IPv4Mask);
                var addressList = Enumerable.Range(0, info.NetworkSize).Select(i => ((uint)i + info.FirstAddress.ToInt()).ToIpAddress()).ToList();

                Console.WriteLine();
                Console.WriteLine($"Interface  . . . . . . : {info.IpAddress}/{info.SubnetMask}");
                Console.WriteLine($"Network Address  . . . : {info.NetworkAddress}");
                Console.WriteLine($"Broadcast Address  . . : {info.BroadcastAddress}");
                Console.WriteLine($"Usable address range . : {info.FirstAddress} - {info.LastAddress}");
                Console.WriteLine($"Size . . . . . . . . . : {addressList.Count} addresses");
                Console.WriteLine($"Scanning:\n");

                Parallel.ForEach(addressList, target =>
                {
                    var mac = GetPhysicalAddress(info.IpAddress, target);

                    Interlocked.Increment(ref _scanCount);

                    // prevent WriteLine() calls from overlapping
                    lock (ConsoleLock)
                    {
                        if (mac != null)
                        {
                            Console.WriteLine($"  {target,-15} [{BitConverter.ToString(mac.GetAddressBytes())}]");
                        }
                        else
                        {
                            Console.WriteLine($"  {_scanCount}/{addressList.Count} ...");
                            Console.SetCursorPosition(Console.CursorLeft, Console.CursorTop - 1);
                        }
                    }
                });
            }
        }

        public static List<UnicastIPAddressInformation> GetInterfaceList()
        {
            var originalColor = Console.ForegroundColor;
            var unicastAddressList = new List<UnicastIPAddressInformation>();

            Console.WriteLine($"{"Interface List",-64}{"Address",-32}{"Status",-12}{"Scan Action",-11}");
            Console.WriteLine($"{new string('=', 119)}");

            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (var unicastAddress in ni.GetIPProperties().UnicastAddresses)
                {
                    var include = true;
                    if (ni.OperationalStatus != OperationalStatus.Up) include = false;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) include = false;
                    if (unicastAddress.SuffixOrigin == SuffixOrigin.LinkLayerAddress) include = false;
                    if (unicastAddress.Address.AddressFamily != AddressFamily.InterNetwork) include = false;

                    // restrict scanning to /19 networks and smaller
                    if (unicastAddress.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        var info = new NetworkInformation(unicastAddress.Address, unicastAddress.IPv4Mask);
                        if (info.NetworkSize > 8192) include = false;
                    }

                    var includeAction = include ? "Scan" : "Skip";
                    if (include) Console.ForegroundColor = ConsoleColor.Green;

                    Console.WriteLine($"{ni.Name,-64}{unicastAddress.Address,-32}{ni.OperationalStatus,-12}{includeAction,-11}");
                    Console.ForegroundColor = originalColor;

                    if (include) unicastAddressList.Add(unicastAddress);
                }
            }

            Console.WriteLine($"{new string('=', 119)}\n");

            return unicastAddressList;
        }

        public static PhysicalAddress GetPhysicalAddress(IPAddress senderAddress, IPAddress targetAddress)
        {
            var mac = new byte[6];
            var length = mac.Length;

            var sender = BitConverter.ToUInt32(senderAddress.GetAddressBytes(), 0);
            var target = BitConverter.ToUInt32(targetAddress.GetAddressBytes(), 0);

            var result = SendArp(target, sender, mac, ref length);
            if (result != 0)
            {
                return null;
            }

            return new PhysicalAddress(mac);
        }

        [DllImport("Iphlpapi.dll", EntryPoint = "SendARP")]
        private static extern int SendArp(uint destIpAddress, uint srcIpAddress, byte[] macAddress, ref int macAddressLength);

        private static int _scanCount;

        private static readonly object ConsoleLock = new object();
    }
}
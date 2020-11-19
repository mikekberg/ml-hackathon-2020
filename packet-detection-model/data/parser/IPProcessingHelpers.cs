using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Kaitai
{
    internal static class IPProcessingHelpers
    {
        public static string ParseIPAddress(this byte[] ip)
        {
            return ip.Select(x => Convert.ToInt32(x).ToString()).Aggregate((x, y) => $"{x}.{y}");
        }
    }
}

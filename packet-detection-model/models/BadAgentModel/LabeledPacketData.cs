using Kaitai;
using Microsoft.ML.Data;
using System;
using System.Collections.Generic;
using System.Reflection.Metadata.Ecma335;
using System.Text;

namespace packet_detection_model.models.BadAgentModel
{
    public class LabeledPacketData
    {
        public int PacketLength { get; set; }
        public byte[] PacketBody { get; set; }
        public string SrcIp { get; set; }

        [ColumnName("IsMalicious")]
        public bool IsMalicious { get; set; } = false;
    }
}

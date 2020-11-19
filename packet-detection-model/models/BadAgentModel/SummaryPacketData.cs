using Kaitai;
using Microsoft.ML.Data;
using System;
using System.Collections.Generic;
using System.Reflection.Metadata.Ecma335;
using System.Text;

namespace packet_detection_model.models.BadAgentModel
{
    public class SummaryPacketData
    {
        public int WindowSize { get; set; }
        public float[] PortData { get; set; }
        public string Ip { get; set; }

        [ColumnName("IsMalicious")]
        public bool IsMalicious { get; set; } = false;
    }
}

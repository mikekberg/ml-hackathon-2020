namespace packet_detection_model.models.BadAgentModel
{
    public class PortSummaryInfoData
    {
        public int PortNumber { get; set; }
        public int AveragePacketSize { get; set; }
        public int SentPackets { get; set; }
        public int ReceivedPackets { get; set; }
    }
}
